#include <gst/gst.h>

#include "open_cdm.h"
#include "open_cdm_adapter.h"
#include "content_decryption_module.h"
#include <string>

#include "session.h"
#include "system.h"

#define UNUSED(v) (void)v
#ifndef LOG
#define LOG(fmt, ...) GST_DEBUG(fmt, __VA_ARGS__)
#endif

GST_DEBUG_CATEGORY_EXTERN(sparkle_widevine_debug_cat);
#define GST_CAT_DEFAULT sparkle_widevine_debug_cat

OpenCDMSession::OpenCDMSession(
    string id,
    cdm::SessionType sessionType,
    OpenCDMSystem* system,
    OpenCDMSessionCallbacks* callbacks,
    void* userData
) : id(std::move(id))
  , sessionType(sessionType)
  , system(system)
  , callbacks(callbacks)
  , userData(userData) {
}

void OpenCDMSession::errorCallback(const string& message) {
  if (callbacks->error_message_callback) {
    callbacks->error_message_callback(this, userData, message.data());
  }
}

void OpenCDMSession::licenseRequestCallback(span<const uint8_t> message) {
  if (callbacks->process_challenge_callback) {
    callbacks->process_challenge_callback(
        this,
        userData,
        nullptr,
        message.data(),
        message.size()
    );
  }
}

void OpenCDMSession::licenseRenewalCallback(span<const uint8_t> message) {
}

void OpenCDMSession::licenseReleaseCallback(span<const uint8_t> message) {
}

void OpenCDMSession::individualizationRequestCallback(
    span<const uint8_t> message
) {
}

void OpenCDMSession::onKeyUpdate(span<const cdm::KeyInformation> keys) {
  for (auto &key : keys) {
    string keyId((char *) key.key_id, key.key_id_size);
    keyInfo[keyId] = key;
  }
  if (callbacks->key_update_callback) {
    for (auto &key : keys) {
      span keyId(key.key_id, key.key_id + key.key_id_size);
      callbacks->key_update_callback(
          this,
          userData,
          keyId.data(),
          keyId.size()
      );
    }
  }
  if (callbacks->keys_updated_callback) {
    callbacks->keys_updated_callback(this, userData);
  }
}

optional<cdm::KeyInformation> OpenCDMSession::getKeyInfo(
    const string& keyId
) const {
  if (keyInfo.contains(keyId)) {
    return keyInfo.at(keyId);
  } else {
    return std::nullopt;
  }
}

bool OpenCDMSession::hasKey(const string& keyId) const {
  return keyInfo.contains(keyId);
}

OpenCDMError opencdm_destruct_session(OpenCDMSession* session) {
  LOG("%p", session);
  delete session;
  return ERROR_NONE;
}

const char* opencdm_session_id(const OpenCDMSession* session) {
  return session->id.c_str();
}

static KeyStatus openCdmKeyStatusFromCdmKeyStatus(cdm::KeyStatus status) {
  switch (status) {
    case cdm::KeyStatus::kUsable:
      return Usable;
    case cdm::KeyStatus::kInternalError:
      return InternalError;
    case cdm::KeyStatus::kExpired:
      return Expired;
    case cdm::KeyStatus::kOutputRestricted:
      return OutputRestricted;
    case cdm::KeyStatus::kOutputDownscaled:
      return OutputDownscaled;
    case cdm::KeyStatus::kStatusPending:
      return StatusPending;
    case cdm::KeyStatus::kReleased:
      return Released;
    default:
      return InternalError;
  }
}

KeyStatus opencdm_session_status(
    const OpenCDMSession* session,
    const uint8_t keyId[],
    const uint8_t length
) {
  LOG("%p", session);
  string id(keyId, keyId + length);
  auto key = session->getKeyInfo(id);
  cdm::KeyStatus status;
  if (key) {
    status = key.value().status;
  } else {
    status = cdm::KeyStatus::kStatusPending;
  }
  return openCdmKeyStatusFromCdmKeyStatus(status);
}

uint32_t opencdm_session_has_key_id(
    OpenCDMSession* session,
    const uint8_t length,
    const uint8_t keyId[]
) {
  LOG("%p", session);
  string id(keyId, keyId + length);
  auto key = session->getKeyInfo(id);
  return key.has_value();
}

OpenCDMError opencdm_session_load(OpenCDMSession* session) {
  LOG("%p", session);
  return session->system->loadSession(*session);
}

OpenCDMError opencdm_session_update(
    OpenCDMSession* session,
    const uint8_t keyMessage[],
    const uint16_t keyLength
) {
  LOG("%p", session);
  auto message = span<const uint8_t>(keyMessage, keyMessage + keyLength);
  return session->system->updateSession(*session, message);
}

OpenCDMError opencdm_session_remove(OpenCDMSession* session) {
  LOG("%p", session);
  return session->system->removeSession(*session);
}

OpenCDMError opencdm_session_close(OpenCDMSession* session) {
  LOG("%p", session);
  return session->system->closeSession(*session);
}

OpenCDMError opencdm_gstreamer_session_decrypt(
    OpenCDMSession* session,
    GstBuffer* buffer,
    GstBuffer* subsamples,
    const uint32_t subsampleCount,
    GstBuffer* iv,
    GstBuffer* keyID,
    uint32_t initWithLast15
) {
  UNUSED(initWithLast15);
  GstMapInfo bufferInfo, subsampleInfo, ivInfo, keyIdInfo;

  gst_buffer_map(buffer, &bufferInfo, GST_MAP_READ);
  if (GST_IS_BUFFER(subsamples)) {
    gst_buffer_map(subsamples, &subsampleInfo, GST_MAP_READ);
  }
  gst_buffer_map(iv, &ivInfo, GST_MAP_READ);
  gst_buffer_map(keyID, &keyIdInfo, GST_MAP_READ);

  span<uint8_t> bufferData(bufferInfo.data, bufferInfo.size);
  span<uint8_t> subsampleData(subsampleInfo.data, subsampleInfo.size);
  span<uint8_t> ivData(ivInfo.data, ivInfo.size);
  span<uint8_t> keyIdData(keyIdInfo.data, keyIdInfo.size);

  auto result = session->system->decrypt(
      *session,
      bufferData,
      subsampleData,
      subsampleCount,
      ivData,
      keyIdData
  );

  gst_buffer_unmap(buffer, &bufferInfo);
  if (GST_IS_BUFFER(subsamples)) {
    gst_buffer_unmap(subsamples, &subsampleInfo);
  }
  gst_buffer_unmap(iv, &ivInfo);
  gst_buffer_unmap(keyID, &keyIdInfo);

  return result;
}
