#pragma once

#include <atomic>
#include <memory>
#include <span>
#include <string>
#include <unordered_map>

#include <glib.h>
#include "open_cdm.h"
#include "content_decryption_module.h"

#include "session.h"

using std::shared_ptr;
using std::string;
using std::span;
using std::unordered_map;

using cdm::ContentDecryptionModule_10;

struct Host;

struct OpenCDMSystem {
  G_GNUC_INTERNAL
  OpenCDMSystem(string keySystem);
  G_GNUC_INTERNAL
  ~OpenCDMSystem();

  G_GNUC_INTERNAL
  OpenCDMError constructSession(
      LicenseType licenseType,
      const string& initDataType,
      span<const uint8_t> initData,
      OpenCDMSessionCallbacks* callbacks,
      void* userData,
      OpenCDMSession*& session
  );
  G_GNUC_INTERNAL
  OpenCDMError loadSession(const OpenCDMSession& session);
  G_GNUC_INTERNAL
  OpenCDMError updateSession(
      OpenCDMSession& session,
      span<const uint8_t> message
  );
  G_GNUC_INTERNAL
  OpenCDMError removeSession(OpenCDMSession& session);
  G_GNUC_INTERNAL
  OpenCDMError closeSession(OpenCDMSession& session);
  G_GNUC_INTERNAL
  OpenCDMError decrypt(
          const OpenCDMSession& session,
          span<uint8_t> buffer,
          span<uint8_t> subsamples,
          const uint32_t subsampleCount,
          span<uint8_t> iv,
          span<uint8_t> keyId
  );

  G_GNUC_INTERNAL
  cdm::KeyStatus getSessionKeyStatus(
      const OpenCDMSession& session,
      span<const uint8_t> keyId
  );

  G_GNUC_INTERNAL
  OpenCDMError setServerCertificate(span<const uint8_t> certificate);

  shared_ptr<Host> host;
  ContentDecryptionModule_10* cdm;
  unordered_map<string, shared_ptr<OpenCDMSession>> sessions;
};
