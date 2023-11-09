#pragma once

#include <string>
#include <optional>
#include <span>
#include <unordered_map>

#include "open_cdm.h"
#include "content_decryption_module.h"

using std::optional;
using std::string;
using std::span;
using std::unordered_map;

#include <glib.h>

struct OpenCDMSession {
  G_GNUC_INTERNAL
  OpenCDMSession(
      string id,
      cdm::SessionType sessionType,
      OpenCDMSystem* system,
      OpenCDMSessionCallbacks* callbacks,
      void* userData
  );
  G_GNUC_INTERNAL
  ~OpenCDMSession() = default;

  G_GNUC_INTERNAL
  void errorCallback(const string& message);
  G_GNUC_INTERNAL
  void licenseRequestCallback(span<const uint8_t> message);
  G_GNUC_INTERNAL
  void licenseRenewalCallback(span<const uint8_t> message);
  G_GNUC_INTERNAL
  void licenseReleaseCallback(span<const uint8_t> message);
  G_GNUC_INTERNAL
  void individualizationRequestCallback(span<const uint8_t> message);

  G_GNUC_INTERNAL
  void onKeyUpdate(span<const cdm::KeyInformation> keys);
  G_GNUC_INTERNAL
  optional<cdm::KeyInformation> getKeyInfo(const string& keyId) const;
  G_GNUC_INTERNAL
  bool hasKey(const string& keyId) const;

  string id;
  cdm::SessionType sessionType;
  cdm::Time expiration;
  OpenCDMSystem* system;
  OpenCDMSessionCallbacks* callbacks;
  void* userData;
  unordered_map<string, cdm::KeyInformation> keyInfo;
};
