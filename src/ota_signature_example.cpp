// OTA signature verification helper (example for ESP8266/Arduino)
// This example is for documentation and is not compiled into the default build.
#if 0
// Uses mbed TLS to verify ECDSA-P256 signatures (DER) for OTA binary.

#include <LittleFS.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <ESP8266httpUpdate.h>
#include <ESP8266WiFi.h>
#include <Update.h>

// If mbedtls headers exist in your environment, include them
#ifdef MBEDTLS
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#endif

#include <Arduino.h>
#include <base64.h> // optional base64 lib for decoding

// Include the public key for verification (PEM format)
// Generate or use the public.pem from the signing process and embed here.

const char OTA_PUBKEY_PEM[] = R"KEY(-----BEGIN PUBLIC KEY-----
REPLACE_WITH_YOUR_PUBLIC_KEY
-----END PUBLIC KEY-----)KEY";

static bool saveUrlToFS(const String &url, const String &path) {
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  if (!http.begin(client, url)) return false;
  int code = http.GET();
  if (code != HTTP_CODE_OK) { http.end(); return false; }
  File f = LittleFS.open(path, "w");
  if (!f) { http.end(); return false; }
  WiFiClient *stream = http.getStreamPtr();
  const size_t bufSz = 1024;
  uint8_t buffer[bufSz];
  while (http.getStream().connected() && http.getSize() > 0) {
    size_t available = (size_t)http.getStream().available();
    if (available) {
      int read = http.getStream().readBytes((char*)buffer, min(available, bufSz));
      f.write(buffer, read);
    } else {
      delay(10);
    }
  }
  f.close();
  http.end();
  return true;
}

#ifdef MBEDTLS
static bool verify_ecdsa_signature_file_mbedtls(const char *path, const char *sigBase64) {
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  const unsigned char *pem = (const unsigned char*)OTA_PUBKEY_PEM;
  int ret = mbedtls_pk_parse_public_key(&pk, pem, strlen((const char*)pem)+1);
  if (ret != 0) {
    Serial.printf("mbedtls_pk_parse_public_key failed: -0x%04x\n", -ret);
    mbedtls_pk_free(&pk);
    return false;
  }

  // Decode base64 signature
  size_t sigDerLen = 0;
  unsigned char *sigDer = nullptr;
  {
    size_t outLen = (strlen(sigBase64) * 3) / 4 + 4;
    sigDer = (unsigned char*)malloc(outLen);
    if (!sigDer) { mbedtls_pk_free(&pk); return false; }
    if ((ret = mbedtls_base64_decode(sigDer, outLen, &sigDerLen, (const unsigned char*)sigBase64, strlen(sigBase64))) != 0) {
      Serial.printf("mbedtls_base64_decode failed: -0x%04x\n", -ret);
      free(sigDer);
      mbedtls_pk_free(&pk);
      return false;
    }
  }

  // Compute SHA256 of file
  mbedtls_sha256_context shaCtx;
  mbedtls_sha256_init(&shaCtx);
  mbedtls_sha256_starts_ret(&shaCtx, 0);

  File f = LittleFS.open(path, "r");
  if (!f) { free(sigDer); mbedtls_pk_free(&pk); return false; }
  const size_t bufSz = 1024;
  unsigned char buf[bufSz];
  while (f.available()) {
    size_t r = f.readBytes((char*)buf, bufSz);
    mbedtls_sha256_update_ret(&shaCtx, buf, r);
  }
  f.close();
  unsigned char digest[32];
  mbedtls_sha256_finish_ret(&shaCtx, digest);
  mbedtls_sha256_free(&shaCtx);

  // Verify
  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, sizeof(digest), sigDer, sigDerLen);
  if (ret != 0) {
    Serial.printf("mbedtls_pk_verify failed: -0x%04x\n", -ret);
    free(sigDer);
    mbedtls_pk_free(&pk);
    return false;
  }
  free(sigDer);
  mbedtls_pk_free(&pk);
  return true;
}
#endif

// Example using LittleFS update from file
static bool applyUpdateFromFS(const char *path) {
  if (!LittleFS.begin()) return false;
  File f = LittleFS.open(path, "r");
  if (!f) return false;
  size_t len = f.size();
  if (!Update.begin(len)) { f.close(); return false; }
  size_t written = Update.writeStream(f);
  f.close();
  if (written != len) return false;
  if (!Update.end()) return false;
  return true;
}

// Sample usage inside checkGitHubUpdate, simplified and robust checks omitted
// 1) Save to FS
// 2) Verify SHA and signature
// 3) applyUpdateFromFS

// Example: function to perform the whole flow given a version JSON payload (passed as a string)
bool checkUpdateWithSignature(const String &payload) {
  DynamicJsonDocument doc(1024);
  DeserializationError err = deserializeJson(doc, payload);
  if (err) return false;
  String newVer = doc["version"]; // unused here, but can compare
  String binUrl = doc["bin"];
  String expectedSha = doc["sha256"];
  String sigB64 = doc["sig"];

  const char *tmpPath = "/newfw.bin";
  if (!saveUrlToFS(binUrl, tmpPath)) return false;

  // Verify SHA
  // compute SHA and compare
  {
    File f = LittleFS.open(tmpPath, "r");
    if (!f) return false;
    // compute sha256
    Sha256Class sha; // placeholder for actual SHA-256 class; in real code use mbedtls_sha256 or Hash
    uint8_t buffer[1024];
    while (f.available()) {
      size_t r = f.readBytes((char*)buffer, sizeof(buffer));
      sha.update(buffer, r);
    }
    f.close();
    uint8_t digest[32];
    sha.final(digest);
    String s = ""; // format to hex
    char tmp[3];
    for (int i=0;i<32;i++) { sprintf(tmp, "%02x", digest[i]); s += tmp; }
    if (s != expectedSha) {
      Serial.println("SHA mismatch, aborting OTA");
      return false;
    }
  }

  // Verify signature
#ifdef MBEDTLS
  if (!verify_ecdsa_signature_file_mbedtls(tmpPath, sigB64.c_str())) {
    Serial.println("Signature verification failed, aborting OTA");
    return false;
  }
#else
  Serial.println("Signature verification not supported on this build (missing mbedtls). Skipping verification!");
#endif

  // Apply update
  if (!applyUpdateFromFS(tmpPath)) {
    Serial.println("Update failed");
    return false;
  }
  Serial.println("Update applied successfully (device should restart)");
  return true;
}
#endif

