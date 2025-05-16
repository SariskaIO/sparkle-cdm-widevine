// SPDX-License-Identifier: MIT

#include <gst/gst.h>
#include <gst/gstclock.h>
#include <gst/base/gstbytereader.h>

#include <glib.h>
#include <gmodule.h>

#include <atomic>
#include <future>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>
#include <variant>

#include "open_cdm.h"
#include "content_decryption_module.h"

#include "system.h"
#include "search.h"
#include "session.h"

using std::atomic_uint32_t;
using std::future;
using std::monostate;
using std::optional;
using std::nullopt;
using std::promise;
using std::shared_future;
using std::shared_ptr;
using std::span;
using std::string;
using std::unique_ptr;
using std::unordered_map;
using std::variant;
using std::vector;

using cdm::Buffer;
using cdm::CdmProxyClient;
using cdm::ContentDecryptionModule_10;
using cdm::DecryptedBlock;
using cdm::Exception;
using cdm::FileIO;
using cdm::FileIOClient;
using cdm::Host_10;
using cdm::InitDataType;
using cdm::KeyInformation;
using cdm::MessageType;
using cdm::SessionType;
using cdm::Status;
using cdm::StreamType;
using cdm::Time;

#define UNUSED(v) (void)v
#ifndef LOG
#define LOG(fmt, ...) GST_DEBUG(fmt, __VA_ARGS__)
#endif

GST_DEBUG_CATEGORY(sparkle_widevine_debug_cat);
#define GST_CAT_DEFAULT sparkle_widevine_debug_cat

static const string widevineId("com.widevine.alpha");
static const string widevineUUID("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed");

static GModule *mod;

using InitializeCdmModuleFunc = void (*)();
using CreateCdmInstanceFunc = void* (*)(
    int cdm_interface_version,
    const char* key_system,
    uint32_t key_system_size,
    GetCdmHostFunc get_cdm_host_func,
    void* user_data
);

static bool initialize_cdm(GModule* mod) {
  void* sym;
  if(!g_module_symbol(mod, G_STRINGIFY(INITIALIZE_CDM_MODULE), &sym)) {
    return false;
  }
  auto func = reinterpret_cast<InitializeCdmModuleFunc>(sym);
  func();
  return true;
}

static bool create_cdm_instance(
    GModule* mod,
    cdm::ContentDecryptionModule_10*& instance,
    const string& keySystem,
    GetCdmHostFunc get_cdm_host,
    void* user_data
) {
  void* sym;
  if (!g_module_symbol(mod, G_STRINGIFY(CreateCdmInstance), &sym)) {
    return false;
  }
  auto func = reinterpret_cast<CreateCdmInstanceFunc>(sym);
  auto ptr = func(10, keySystem.data(), keySystem.size(), get_cdm_host, user_data);
  if (ptr == nullptr) {
    return false;
  }
  instance = reinterpret_cast<cdm::ContentDecryptionModule_10*>(ptr);
  return true;
}

static const gchar *widevine_cdm_blob_env() {
  return g_getenv ("WIDEVINE_CDM_BLOB");
}

static gchar *firefox_dir() {
#ifdef __APPLE__
  return g_build_filename(g_get_home_dir(), "Library", "Application Support", "Firefox", NULL);
#else
  return g_build_filename(g_get_home_dir(), ".mozilla", "firefox", NULL);
#endif
}

static gchar *chromium_dir() {
#ifdef __APPLE__
  // Try both Chrome and Chromium paths on macOS
  gchar *chrome_path = g_build_filename(g_get_home_dir(), "Library", "Application Support", "Google", "Chrome", NULL);
  if (g_file_test(chrome_path, G_FILE_TEST_IS_DIR)) {
    return chrome_path;
  }
  g_free(chrome_path);
  return g_build_filename(g_get_home_dir(), "Library", "Application Support", "Chromium", NULL);
#else
  return g_build_filename(g_get_user_config_dir(), "chromium", NULL);
#endif
}

#ifdef __APPLE__
static gchar* find_chrome_widevine_cdm() {
  const gchar* arch;
#ifdef __aarch64__
  arch = "mac_arm64";
#else
  arch = "mac_x64";
#endif
  
  // Look for Chrome's Widevine CDM
  gchar *chrome_base = g_strdup("/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework");
  gchar *versions_dir = g_build_filename(chrome_base, "Versions", NULL);
  
  GDir *dir = g_dir_open(versions_dir, 0, NULL);
  if (dir) {
    const gchar *version;
    const gchar *latest_version = NULL;
    
    // Find the latest version
    while ((version = g_dir_read_name(dir))) {
      if (g_regex_match_simple("^\\d+\\.\\d+\\.\\d+\\.\\d+$", version, (GRegexCompileFlags)0, (GRegexMatchFlags)0)) {
        if (!latest_version || g_strcmp0(version, latest_version) > 0) {
          latest_version = version;
        }
      }
    }
    
    if (latest_version) {
      gchar *widevine_path = g_build_filename(chrome_base, "Versions", latest_version, 
                                             "Libraries", "WidevineCdm", "_platform_specific", 
                                             arch, "libwidevinecdm.dylib", NULL);
      
      if (g_file_test(widevine_path, G_FILE_TEST_EXISTS)) {
        GST_LOG("Found Chrome CDM at: %s", widevine_path);
        g_dir_close(dir);
        g_free(versions_dir);
        g_free(chrome_base);
        return widevine_path;
      }
      
      g_free(widevine_path);
    }
    
    g_dir_close(dir);
  }
  
  g_free(versions_dir);
  g_free(chrome_base);
  return NULL;
}
#else
static gchar* find_chrome_widevine_cdm() {
  // Look for Chrome's Widevine CDM on Linux
  if (g_file_test("/opt/google/chrome/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so", G_FILE_TEST_EXISTS)) {
    return g_strdup("/opt/google/chrome/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so");
  }
  
  // Also check common alternative locations
  if (g_file_test("/usr/lib/chromium/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so", G_FILE_TEST_EXISTS)) {
    return g_strdup("/usr/lib/chromium/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so");
  }
  
  return NULL;
}
#endif

static void do_init(bool& success) {
  GST_DEBUG_CATEGORY_INIT(sparkle_widevine_debug_cat, "sprklcdm-widevine", 0,
      "Sparkle CDM Widevine");

  g_autofree gchar *cdm_path = nullptr;
  const gchar *widevine_cdm_blob = widevine_cdm_blob_env();
  
  if (widevine_cdm_blob && g_file_test(widevine_cdm_blob, G_FILE_TEST_EXISTS)) {
    GST_LOG("using env@%s", widevine_cdm_blob);
    mod = g_module_open(widevine_cdm_blob, GModuleFlags::G_MODULE_BIND_LAZY);
  } 
#ifdef __APPLE__
  else {
    // On macOS, try to find Widevine in Chrome
    cdm_path = find_chrome_widevine_cdm();
    if (cdm_path) {
      GST_LOG("found Chrome CDM@%s", cdm_path);
      mod = g_module_open(cdm_path, GModuleFlags::G_MODULE_BIND_LAZY);
    }
  }
#else
  else {
    // Linux paths
    g_autofree gchar *ff_home = firefox_dir();
    g_autofree gchar *chr_home = chromium_dir();
    
    // Try to find CDM in Chrome first (most reliable)
    cdm_path = find_chrome_widevine_cdm();
    if (cdm_path) {
      GST_LOG("found chrome cdm@%s", cdm_path);
      mod = g_module_open(cdm_path, GModuleFlags::G_MODULE_BIND_LAZY);
    }
    // Then try Firefox
    else if (find_firefox_cdm(ff_home, &cdm_path, nullptr, nullptr)) {
      GST_LOG("found firefox cdm@%s", cdm_path);
      mod = g_module_open(cdm_path, GModuleFlags::G_MODULE_BIND_LAZY);
    } 
    // Then Chromium
    else if (find_chromium_cdm(chr_home, &cdm_path, nullptr, nullptr)) {
      GST_LOG("found chromium cdm@%s", cdm_path);
      mod = g_module_open(cdm_path, GModuleFlags::G_MODULE_BIND_LAZY);
    }
  }
#endif
  
  if (!mod) {
    GST_ERROR("no cdm found, trying fallback");
#ifdef __APPLE__
    mod = g_module_open("libwidevinecdm.dylib", GModuleFlags::G_MODULE_BIND_LAZY);
#else
    mod = g_module_open("libwidevinecdm.so", GModuleFlags::G_MODULE_BIND_LAZY);
#endif
  }

  success = mod && initialize_cdm(mod);
  
  if (!success) {
    if (mod) {
      const gchar *error = g_module_error();
      GST_ERROR("Failed to initialize CDM: %s", error ? error : "unknown error");
    } else {
      GST_ERROR("Failed to open CDM module");
    }
  }
}

static bool do_init_once() {
  static bool success = false;
  static std::once_flag init_flag;
  std::call_once(init_flag, []() { do_init(success); });
  return success;
}

static atomic_uint32_t nextPromiseId_ = 0;
uint32_t nextPromiseId() {
  return nextPromiseId_.fetch_add(1);
}

struct VecBuffer final : Buffer {
  vector<uint8_t> data;

  VecBuffer(uint32_t capacity) { data.resize(capacity); }
  void Destroy() final { data.resize(0); }

  [[nodiscard]] uint32_t Capacity() const final { return data.capacity(); }
  uint8_t* Data() final { return data.data(); }
  void SetSize(uint32_t size) final { data.resize(size); }
  [[nodiscard]] uint32_t Size() const final { return data.capacity(); }
};

struct BasicDecryptedBlock final : DecryptedBlock {
  Buffer* buffer;
  int64_t timestamp;

  ~BasicDecryptedBlock() final {
    if (buffer) {
      buffer->Destroy();
    }
  }

  void SetDecryptedBuffer(Buffer* buffer) final { this->buffer = buffer; }
  Buffer* DecryptedBuffer() final { return buffer; }

  void SetTimestamp(int64_t timestamp) final { this->timestamp = timestamp; }
  [[nodiscard]] int64_t Timestamp() const final { return timestamp; }

  [[nodiscard]] uint32_t size() const { return buffer ? buffer->Size() : 0; }
  [[nodiscard]] const uint8_t* data() const {
    return buffer ? buffer->Data() : nullptr;
  }
};

struct Host;

struct SetTimerContext {
  Host* host;
  void* call_context;
};

struct RejectedPromise {
  uint32_t id;
  Exception exception;
  uint32_t system_code;
  string message;

  OpenCDMError openCdmError() {
    switch (exception) {
      case Exception::kExceptionInvalidStateError:
      case Exception::kExceptionNotSupportedError:
      case Exception::kExceptionQuotaExceededError:
      case Exception::kExceptionTypeError:
        return ERROR_FAIL;
      default:
        return ERROR_UNKNOWN;
    }
  }
};

struct UpdateSessionResponse : variant<monostate, RejectedPromise> {
  bool isOk() {
    return std::get_if<monostate>(this);
  }
  optional<RejectedPromise> error() {
    if (std::holds_alternative<RejectedPromise>(*this)) {
      return std::get<RejectedPromise>(*this);
    } else {
      return nullopt;
    }
  }
};

struct LoadSessionResponse : variant<monostate, RejectedPromise> {
  bool isOk() {
    return std::get_if<monostate>(this);
  }
  optional<RejectedPromise> error() {
    if (std::holds_alternative<RejectedPromise>(*this)) {
      return std::get<RejectedPromise>(*this);
    } else {
      return nullopt;
    }
  }
};

struct RemoveSessionResponse : variant<monostate, RejectedPromise> {
  bool isOk() {
    return std::get_if<monostate>(this);
  }
  optional<RejectedPromise> error() {
    if (std::holds_alternative<RejectedPromise>(*this)) {
      return std::get<RejectedPromise>(*this);
    } else {
      return nullopt;
    }
  }
};

struct CloseSessionResponse : variant<monostate, RejectedPromise> {
  bool isOk() {
    return std::get_if<monostate>(this);
  }
  optional<RejectedPromise> error() {
    if (std::holds_alternative<RejectedPromise>(*this)) {
      return std::get<RejectedPromise>(*this);
    } else {
      return nullopt;
    }
  }
};

struct CreateSessionRequest {
  cdm::SessionType sessionType;
  OpenCDMSessionCallbacks* callbacks;
  void* userData;
};

struct CreateSessionResponse : variant<shared_ptr<OpenCDMSession>, RejectedPromise> {
  optional<shared_ptr<OpenCDMSession>> session() {
    if (std::holds_alternative<shared_ptr<OpenCDMSession>>(*this)) {
      return std::get<shared_ptr<OpenCDMSession>>(*this);
    } else {
      return nullopt;
    }
  }
  optional<RejectedPromise> error() {
    if (std::holds_alternative<RejectedPromise>(*this)) {
      return std::get<RejectedPromise>(*this);
    } else {
      return nullopt;
    }
  }
};

struct SetServerCertificateRequest {
  span<const uint8_t> certificate;
};

struct SetServerCertificateResponse : variant<monostate, RejectedPromise> {
  optional<RejectedPromise> error() {
    if (std::holds_alternative<RejectedPromise>(*this)) {
      return std::get<RejectedPromise>(*this);
    } else {
      return nullopt;
    }
  }
};

struct Host final : Host_10 {
  GstClock *clock;
  OpenCDMSystem *system;
  promise<bool> cdmInitialized;
  shared_future<bool> cdmInitializedFuture;
  unordered_map<uint32_t, CreateSessionRequest> create_session_requests;

  unordered_map<uint32_t, unique_ptr<promise<SetServerCertificateResponse>>> set_server_certificate_promises;
  unordered_map<uint32_t, unique_ptr<promise<CreateSessionResponse>>> create_session_promises;
  unordered_map<uint32_t, unique_ptr<promise<LoadSessionResponse>>> load_session_promises;
  unordered_map<uint32_t, unique_ptr<promise<UpdateSessionResponse>>> update_session_promises;
  unordered_map<uint32_t, unique_ptr<promise<RemoveSessionResponse>>> remove_session_promises;
  unordered_map<uint32_t, unique_ptr<promise<CloseSessionResponse>>> close_session_promises;

  unordered_map<string, shared_ptr<OpenCDMSession>> sessions;

  Host(OpenCDMSystem* system) : clock(gst_system_clock_obtain())
                              , system(system)
                              , cdmInitializedFuture(shared_future(cdmInitialized.get_future()))
  { }

  Buffer* Allocate(uint32_t capacity) final {
    return new VecBuffer(capacity);
  }

  void SetTimer(int64_t delay_ms, void* context) final {
    auto delay_ns = delay_ms * 1000 * 1000;
    auto deadline = gst_clock_get_time(clock) + delay_ns;
    auto id = gst_clock_new_single_shot_id(clock, deadline);
    auto set_timer_context = new SetTimerContext { this, context };
    auto cb = [] (GstClock* clock, GstClockTime time, GstClockID id, void* user_data) -> gboolean {
      UNUSED(clock);
      UNUSED(time);
      auto ctx = (SetTimerContext *) user_data;
      gst_clock_id_unref(id);
      ctx->host->system->cdm->TimerExpired(ctx->call_context);
      delete ctx;
      return false;
    };
    gst_clock_id_wait_async(id, cb, set_timer_context, nullptr);
  }

  Time GetCurrentWallTime() final {
    return ((double) g_get_real_time()) / G_USEC_PER_SEC;
  }

  future<CreateSessionResponse> registerPromiseCreateSession(
      uint32_t id,
      CreateSessionRequest request
  ) {
    create_session_requests[id] = std::move(request);
    auto promise = std::make_unique<std::promise<CreateSessionResponse>>();
    auto future = promise->get_future();
    create_session_promises[id] = std::move(promise);
    return future;
  }

  future<UpdateSessionResponse> registerPromiseUpdateSession(uint32_t id) {
    auto promise = std::make_unique<std::promise<UpdateSessionResponse>>();
    auto future = promise->get_future();
    update_session_promises[id] = std::move(promise);
    return future;
  }

  future<RemoveSessionResponse> registerPromiseRemoveSession(uint32_t id) {
    auto promise = std::make_unique<std::promise<RemoveSessionResponse>>();
    auto future = promise->get_future();
    remove_session_promises[id] = std::move(promise);
    return future;
  }

  future<CloseSessionResponse> registerPromiseCloseSession(uint32_t id) {
    auto promise = std::make_unique<std::promise<CloseSessionResponse>>();
    auto future = promise->get_future();
    close_session_promises[id] = std::move(promise);
    return future;
  }

  future<SetServerCertificateResponse> registerPromiseSetServerCertificate(
      uint32_t id
  ) {
    auto promise = std::make_unique<std::promise<SetServerCertificateResponse>>();
    auto future = promise->get_future();
    set_server_certificate_promises[id] = std::move(promise);
    return future;
  }

  void OnInitialized(bool success) final {
    cdmInitialized.set_value(success);
  }

  void OnResolveKeyStatusPromise(
      uint32_t promise_id,
      cdm::KeyStatus key_status
  ) final {
    if (key_status != cdm::KeyStatus::kUsable) {
      LOG("%u: %d", promise_id, key_status);
    }
  }

  void OnResolveNewSessionPromise(
      uint32_t promise_id,
      const char* session_id,
      uint32_t session_id_size
  ) final {
    string sessionId(session_id, session_id_size);
    auto request = std::move(create_session_requests[promise_id]);
    auto promise = std::move(create_session_promises[promise_id]);
    auto newSession = std::make_shared<OpenCDMSession>(
        sessionId,
        request.sessionType,
        system,
        request.callbacks,
        request.userData
    );
    sessions[sessionId] = newSession;
    if (promise) {
      CreateSessionResponse response = { newSession };
      promise->set_value(response);
      LOG("%u: resolved", promise_id);
    } else {
      LOG("%u: id=%s no promise was registered", promise_id, sessionId.c_str());
    }
  }

  void OnResolvePromise(uint32_t promise_id) final {
    LOG("%u", promise_id);
    if (create_session_promises.contains(promise_id)) {
      auto promise = std::move(create_session_promises[promise_id]);
      promise->set_value({});
    } else if (set_server_certificate_promises.contains(promise_id)) {
      auto promise = std::move(set_server_certificate_promises[promise_id]);
      promise->set_value({});
    } else if (load_session_promises.contains(promise_id)) {
      auto promise = std::move(load_session_promises[promise_id]);
      promise->set_value({});
    } else if (update_session_promises.contains(promise_id)) {
      auto promise = std::move(update_session_promises[promise_id]);
      promise->set_value({});
    } else if (remove_session_promises.contains(promise_id)) {
      auto promise = std::move(remove_session_promises[promise_id]);
      promise->set_value({});
    } else if (close_session_promises.contains(promise_id)) {
      auto promise = std::move(close_session_promises[promise_id]);
      promise->set_value({});
    } else {
      LOG("%u: no matching promise found", promise_id);
    }
  }

  void OnRejectPromise(
      uint32_t promise_id,
      Exception exception,
      uint32_t system_code,
      const char* error_message, uint32_t error_message_size
  ) final {
    string message(error_message, error_message_size);
    #ifdef __GLIBC__
      auto errname = strerrorname_np(system_code);
    #else
      auto errname = strerror(system_code);
    #endif
    LOG(
        "%u: exception=%d, code=%u, errname=`%s' message=`%s'",
        promise_id,
        exception,
        system_code,
        errname,
        message.c_str()
    );

    switch (exception) {
      case Exception::kExceptionTypeError:
        LOG("%u: type error", promise_id);
        break;
      case Exception::kExceptionNotSupportedError:
        LOG("%u: not supported error", promise_id);
        break;
      case Exception::kExceptionInvalidStateError:
        LOG("%u: invalid state error", promise_id);
        break;
      case Exception::kExceptionQuotaExceededError:
        LOG("%u: quota exceeded error", promise_id);
        break;
      default:
        LOG("%u: unknown error %d", promise_id, exception);
    }

    RejectedPromise rejection = {
      promise_id,
      exception,
      system_code,
      message,
    };
    if (create_session_promises.contains(promise_id)) {
      auto promise = std::move(create_session_promises[promise_id]);
      promise->set_value({rejection});
    } else if (set_server_certificate_promises.contains(promise_id)) {
      auto promise = std::move(set_server_certificate_promises[promise_id]);
      promise->set_value({rejection});
    } else if (load_session_promises.contains(promise_id)) {
      auto promise = std::move(load_session_promises[promise_id]);
      promise->set_value({rejection});
    } else if (update_session_promises.contains(promise_id)) {
      auto promise = std::move(update_session_promises[promise_id]);
      promise->set_value({rejection});
    } else if (remove_session_promises.contains(promise_id)) {
      auto promise = std::move(remove_session_promises[promise_id]);
      promise->set_value({rejection});
    } else if (close_session_promises.contains(promise_id)) {
      auto promise = std::move(close_session_promises[promise_id]);
      promise->set_value({rejection});
    } else {
      LOG("%u: no matching promise found", promise_id);
    }
  }

  void OnSessionMessage(
      const char* session_id, uint32_t session_id_size,
      MessageType message_type,
      const char* message, uint32_t message_size
  ) final {
    string sessionId(session_id, session_id_size);
    span<const uint8_t> messageData(
        (const uint8_t *) message,
        (const uint8_t *) message + message_size
    );
    bool haveSession = sessions.contains(sessionId);
    if (!haveSession) {
      LOG("%s: no session in internal map", sessionId.c_str());
    }
    switch (message_type) {
      case MessageType::kIndividualizationRequest:
        LOG("%s: kIndividualizationRequest", sessionId.c_str());
        if (haveSession) {
          auto session = sessions[sessionId];
          session->individualizationRequestCallback(messageData);
        }
        break;
      case MessageType::kLicenseRequest:
        LOG("%s: kLicenseRequest", sessionId.c_str());
        if (haveSession) {
          auto session = sessions[sessionId];
          session->licenseRequestCallback(messageData);
        }
        break;
      case MessageType::kLicenseRenewal:
        LOG("%s: kLicenseRenewal", sessionId.c_str());
        if (haveSession) {
          auto session = sessions[sessionId];
          session->licenseRenewalCallback(messageData);
        }
        break;
      case MessageType::kLicenseRelease:
        LOG("%s: kLicenseRelease", sessionId.c_str());
        if (haveSession) {
          auto session = sessions[sessionId];
          session->licenseReleaseCallback(messageData);
        }
        break;
    }
  }

  void OnSessionKeysChange(
      const char* session_id,
      uint32_t session_id_size,
      bool has_additional_usable_key,
      const KeyInformation* keys_info,
      uint32_t keys_info_count
  ) final {
    string sessionId(session_id, session_id_size);
    UNUSED(has_additional_usable_key);
    if (sessions.contains(sessionId)) {
      auto session = sessions[sessionId];
      auto keys = span(keys_info, keys_info + keys_info_count);
      session->onKeyUpdate(keys);
    } else {
      LOG("%s: session not found", sessionId.c_str());
    }
  }

  void OnExpirationChange(
      const char* session_id,
      uint32_t session_id_size,
      Time new_expiry_time
  ) final {
    string sessionId(session_id, session_id_size);
    if (sessions.contains(sessionId))  {
      auto session = sessions[sessionId];
      session->expiration = new_expiry_time;
    } else {
      LOG("%s: session not found", sessionId.c_str());
    }
  }

  void OnSessionClosed(const char* session_id, uint32_t session_id_size) final {
    string sessionId(session_id, session_id_size);
    LOG("%s", sessionId.c_str());
    sessions.erase(sessionId);
  }

  void SendPlatformChallenge(
      const char* service_id,
      uint32_t service_id_size,
      const char* challenge,
      uint32_t challenge_size
  ) final {
    string serviceId(service_id, service_id_size);
    string challengeData(challenge, challenge_size);
    LOG("%s", serviceId.c_str());
  }

  void EnableOutputProtection(uint32_t desired_protection_mask) final {
    LOG("%u", desired_protection_mask);
  }

  void QueryOutputProtectionStatus() final {
    system->cdm->OnQueryOutputProtectionStatus(cdm::QueryResult::kQuerySucceeded, 0, 0);
  }

  void OnDeferredInitializationDone(StreamType stream_type, Status decoder_status) final {
    LOG("%u, %u", stream_type, decoder_status);
  }

  FileIO* CreateFileIO(FileIOClient* client) final {
    LOG("%p", client);
    return nullptr;
  }

  void RequestStorageId(uint32_t version) final {
    LOG("%u", version);
    string id("test");
    system->cdm->OnStorageId(version, (uint8_t *) id.c_str(), id.length());
  }
};

static void* get_host_func(int cdm_interface_version, void* user_data) {
  auto self = (OpenCDMSystem *) user_data;
  auto host = self->host;
  if (host->kVersion == cdm_interface_version) {
    host->system = self;
    return host.get();
  } else {
    return nullptr;
  }
}

OpenCDMSystem::OpenCDMSystem(string keySystem) {
  host = std::make_shared<Host>(this);
  create_cdm_instance(
      mod,
      cdm,
      keySystem,
      get_host_func,
      this
  );
}

OpenCDMSystem::~OpenCDMSystem() {
  cdm->Destroy();
  cdm = nullptr;
}

static SessionType sessionTypeFromLicenseType(LicenseType licenseType) {
  switch (licenseType) {
    case LicenseType::PersistentLicense:
      return SessionType::kPersistentLicense;
    case LicenseType::PersistentUsageRecord:
      return SessionType::kPersistentUsageRecord;
    case LicenseType::Temporary:
    default:
      return SessionType::kTemporary;
  }
}

bool initDataTypeFromString(const string& value, InitDataType& type) {
  if (value == "cenc") {
    type = InitDataType::kCenc;
    return true;
  }
  if (value == "keyids") {
    type = InitDataType::kKeyIds;
    return true;
  }
  if (value == "webm") {
    type = InitDataType::kWebM;
    return true;
  }
  return false;
}

OpenCDMError OpenCDMSystem::constructSession(
    LicenseType licenseType,
    const string& initDataTypeName,
    span<const uint8_t> initData,
    OpenCDMSessionCallbacks* callbacks,
    void* userData,
    OpenCDMSession*& session
) {
  InitDataType initDataType;
  if (!initDataTypeFromString(initDataTypeName, initDataType)) {
    return ERROR_INVALID_ARG;
  }

  auto initialized = host->cdmInitializedFuture;
  if (initialized.wait_for(std::chrono::seconds(0)) != std::future_status::ready) {
    LOG("%p: initializing cdm", cdm);
    cdm->Initialize(false, false, false);
  }
  if (!initialized.get()) {
    LOG("%p: CDM failed to initialize", cdm);
    return ERROR_FAIL;
  }

  auto promiseId = nextPromiseId();
  auto sessionType = sessionTypeFromLicenseType(licenseType);
  auto request = CreateSessionRequest {
    sessionType,
    callbacks,
    userData,
  };
  auto future = host->registerPromiseCreateSession(promiseId, request);
  cdm->CreateSessionAndGenerateRequest(
      promiseId,
      sessionType,
      initDataType,
      initData.data(),
      initData.size()
  );
  auto response = future.get();
  auto error = response.error();
  if (error) {
    return error->openCdmError();
  }
  auto newSession = response.session().value();
  sessions[newSession->id] = newSession;
  session = newSession.get();
  return ERROR_NONE;
}

OpenCDMError OpenCDMSystem::loadSession(const OpenCDMSession& session) {
  auto promiseId = nextPromiseId();
  auto future = host->registerPromiseUpdateSession(promiseId);
  cdm->LoadSession(
      promiseId,
      session.sessionType,
      session.id.data(),
      session.id.length()
  );
  auto response = future.get();
  auto error = response.error();
  if (error) {
    return error->openCdmError();
  }
  return ERROR_NONE;
}

OpenCDMError OpenCDMSystem::updateSession(
    OpenCDMSession& session,
    span<const uint8_t> message
) {
  auto promiseId = nextPromiseId();
  auto future = host->registerPromiseUpdateSession(promiseId);
  cdm->UpdateSession(
      promiseId,
      session.id.data(),
      session.id.length(),
      message.data(),
      message.size()
  );
  auto response = future.get();
  auto error = response.error();
  if (error) {
    session.errorCallback(error->message);
    return error->openCdmError();
  }
  return ERROR_NONE;
}

OpenCDMError OpenCDMSystem::removeSession(OpenCDMSession& session) {
  auto promiseId = nextPromiseId();
  auto future = host->registerPromiseRemoveSession(promiseId);
  cdm->RemoveSession(promiseId, session.id.data(), session.id.length());
  auto response = future.get();
  auto error = response.error();
  if (error) {
    session.errorCallback(error->message);
    return error->openCdmError();
  }
  sessions.erase(session.id);
  return ERROR_NONE;
}

OpenCDMError OpenCDMSystem::closeSession(OpenCDMSession& session) {
  auto promiseId = nextPromiseId();
  auto future = host->registerPromiseCloseSession(promiseId);
  cdm->CloseSession(promiseId, session.id.data(), session.id.length());
  auto response = future.get();
  auto error = response.error();
  if (error) {
    session.errorCallback(error->message);
    return error->openCdmError();
  }
  sessions.erase(session.id);
  return ERROR_NONE;
}

OpenCDMError OpenCDMSystem::setServerCertificate(
    span<const uint8_t> certificate
) {
  auto promiseId = nextPromiseId();
  auto future = host->registerPromiseSetServerCertificate(promiseId);
  cdm->SetServerCertificate(promiseId, certificate.data(), certificate.size());
  auto response = future.get();
  auto error = response.error();
  if (error) {
    return error->openCdmError();
  }
  return ERROR_NONE;
}

static OpenCDMError processDecryptionResult(
    ContentDecryptionModule_10& cdm,
    span<uint8_t> buffer,
    cdm::InputBuffer_2 input
) {
  BasicDecryptedBlock decrypted;
  auto result = cdm.Decrypt(input, &decrypted);
  switch (result) {
    case cdm::kSuccess:
      memcpy(buffer.data(), decrypted.data(), decrypted.size());
      return ERROR_NONE;
    case cdm::kNeedMoreData:
      return ERROR_MORE_DATA_AVAILBALE;
    case cdm::kNoKey:
      return ERROR_INVALID_SESSION;
    default:
      return ERROR_FAIL;
  }
}

static OpenCDMError decryptWithoutSubsamples(
    ContentDecryptionModule_10& cdm,
    span<uint8_t> buffer,
    span<uint8_t> iv,
    span<uint8_t> keyId
) {
  cdm::InputBuffer_2 input = {
    .data = buffer.data(),
    .data_size = static_cast<uint32_t>(buffer.size()),
    .encryption_scheme = cdm::EncryptionScheme::kCenc,
    .key_id = keyId.data(),
    .key_id_size = static_cast<uint32_t>(keyId.size()),
    .iv = iv.data(),
    .iv_size = static_cast<uint32_t>(iv.size()),
    .subsamples = nullptr,
    .num_subsamples = 0,
    .pattern = { 0, 0 },
    .timestamp = 0,
  };

  return processDecryptionResult(cdm, buffer, input);
}

static optional<cdm::SubsampleEntry> parseSubsample(GstByteReader& reader) {
  guint16 clear;
  guint32 cipher;
  if (!gst_byte_reader_get_uint16_be(&reader, &clear)) {
    return nullopt;
  }
  if (!gst_byte_reader_get_uint32_be(&reader, &cipher)) {
    return nullopt;
  }
  return cdm::SubsampleEntry {
    .clear_bytes = clear,
    .cipher_bytes = cipher,
  };
}

static optional<vector<cdm::SubsampleEntry>> parseSubsamples(
    span<const uint8_t> data,
    size_t subsampleCount
) {
  std::vector<cdm::SubsampleEntry> entries;
  if (subsampleCount < 1) {
    return nullopt;
  }

  GstByteReader reader;
  gst_byte_reader_init(&reader, data.data(), data.size());

  for (auto i = 0U; i < subsampleCount; i++) {
    auto entry = parseSubsample(reader);
    if (entry) {
      entries.push_back(std::move(entry.value()));
    } else {
      return nullopt;
    }
  }

  return entries;
}

static OpenCDMError decryptSubsample(
    ContentDecryptionModule_10& cdm,
    span<uint8_t> buffer,
    const cdm::SubsampleEntry& subsample,
    span<uint8_t> iv,
    span<uint8_t> keyId
) {

  if (subsample.cipher_bytes < 1) {
    return ERROR_NONE;
  }

  auto encryptedBuffer = buffer.subspan(
      subsample.clear_bytes,
      subsample.cipher_bytes
  );
  cdm::InputBuffer_2 input = {
    .data = encryptedBuffer.data(),
    .data_size = static_cast<uint32_t>(encryptedBuffer.size()),
    .encryption_scheme = cdm::EncryptionScheme::kCenc,
    .key_id = keyId.data(),
    .key_id_size = static_cast<uint32_t>(keyId.size()),
    .iv = iv.data(),
    .iv_size = static_cast<uint32_t>(iv.size()),
    .subsamples = nullptr,
    .num_subsamples = 0,
    .pattern = { 0, 0 },
    .timestamp = 0,
  };

  return processDecryptionResult(cdm, encryptedBuffer, input);
}

static OpenCDMError decryptSubsamples(
    ContentDecryptionModule_10& cdm,
    span<uint8_t> buffer,
    span<uint8_t> subsamples,
    const uint32_t subsampleCount,
    span<uint8_t> iv,
    span<uint8_t> keyId
) {
  auto subsampleEntriesResult = parseSubsamples(subsamples, subsampleCount);
  if (!subsampleEntriesResult) {
    return ERROR_FAIL;
  }

  auto subsampleEntries = subsampleEntriesResult.value();

  size_t position = 0;
  for (auto subsample : subsampleEntries) {
    auto subsampleSize = subsample.clear_bytes + subsample.cipher_bytes;
    auto result = decryptSubsample(
        cdm,
        buffer.subspan(position, subsampleSize),
        subsample,
        iv,
        keyId
    );
    switch (result) {
      case ERROR_NONE:
        position += subsampleSize;
        continue;
      default:
        return result;
    }
  }
  return ERROR_NONE;
}

OpenCDMError OpenCDMSystem::decrypt(
    const OpenCDMSession& session,
    span<uint8_t> buffer,
    span<uint8_t> subsamples,
    const uint32_t subsampleCount,
    span<uint8_t> iv,
    span<uint8_t> keyId
) {
  UNUSED(session);

  if (subsampleCount < 1) {
    return decryptWithoutSubsamples(*cdm, buffer, iv, keyId);
  } else {
    return decryptSubsamples(
        *cdm,
        buffer,
        subsamples,
        subsampleCount,
        iv,
        keyId
    );
  }
}

OpenCDMError opencdm_is_type_supported(
    const char keySystem[],
    const char mimeType[]
) {
  UNUSED(mimeType);
  string systemId(keySystem);
  if (systemId == widevineId || systemId == widevineUUID) {
    return ERROR_NONE;
  } else {
    return ERROR_KEYSYSTEM_NOT_SUPPORTED;
  }
}

OpenCDMError opencdm_init() {
  if (do_init_once()) {
    return ERROR_NONE;
  } else {
    return ERROR_FAIL;
  }
}

OpenCDMSystem* opencdm_create_system(const char keySystem[]) {
  if (do_init_once()) {
    return new OpenCDMSystem(keySystem);
  } else {
    return nullptr;
  }
}

OpenCDMError opencdm_destruct_system(OpenCDMSystem* system) {
  delete system;
  return ERROR_NONE;
}

OpenCDMBool opencdm_system_supports_server_certificate(OpenCDMSystem* system) {
  LOG("%p", system);
  return OPENCDM_BOOL_TRUE;
}

OpenCDMSession* opencdm_get_system_session(
    OpenCDMSystem* system,
    const uint8_t keyId[],
    const uint8_t length,
    const uint32_t waitTime
) {
  UNUSED(keyId);
  UNUSED(length);
  UNUSED(waitTime);
  const string key((const char *) keyId, length);
  for (auto pair : system->sessions) {
    auto session = pair.second;
    if (session->hasKey(key)) {
      return session.get();
    }
  }
  return nullptr;
}

OpenCDMError opencdm_system_set_server_certificate(
    OpenCDMSystem* system,
    const uint8_t serverCertificate[],
    const uint16_t serverCertificateLength
) {
  LOG("%p", system);
  auto certificate = span(
      serverCertificate,
      serverCertificate + serverCertificateLength
  );
  return system->setServerCertificate(certificate);
}

OpenCDMError opencdm_construct_session(
    OpenCDMSystem* system,
    const LicenseType licenseType,
    const char initDataType[],
    const uint8_t initData[],
    const uint16_t initDataLength,
    const uint8_t CDMData[],
    const uint16_t CDMDataLength,
    OpenCDMSessionCallbacks* callbacks,
    void* userData,
    OpenCDMSession** session
) {
  UNUSED(CDMData);
  UNUSED(CDMDataLength);
  string initDataTypeName(initDataType);
  auto initDataBytes = span(initData, initData + initDataLength);
  return system->constructSession(
      licenseType,
      initDataTypeName,
      initDataBytes,
      callbacks,
      userData,
      *session
  );
}
