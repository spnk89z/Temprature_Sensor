/*
============================================================
 ESP8266 DHT SENSOR - ULTIMUM EDITION v3.6 (OTA ENABLED)
 - Async Web Server + WebSocket Live Charts
 - Role-based Users (admin / viewer)
 - REST API
 - Home Assistant Industrial Sensor Pack
 - Encrypted Config Storage
 - AUTO GITHUB OTA UPDATES
============================================================
*/

#include <FS.h>
#include <LittleFS.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266httpUpdate.h>
#include <Update.h>
#include <DNSServer.h>
#include <ESPAsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <ESPAsyncWiFiManager.h>
#include <ESP8266mDNS.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>
#include <time.h>
// Optional includes for signature verification
#ifdef MBEDTLS
#include "mbedtls/sha256.h"
#include "mbedtls/pk.h"
#include "mbedtls/base64.h"
#endif

// Optional cloud
#include <SinricPro.h>
#include <SinricProTemperaturesensor.h>

// -------------------- FIRMWARE --------------------
#ifndef FW_VERSION
#define FW_VERSION        "3.5.1-ULTIMUM"
#endif
#define DHTPIN            14     // D5
#define DHTTYPE           DHT11
#define WIFI_AP_SSID      "ULTIMUM_SETUP"
#define WIFI_AP_PASS      "12345678"

// ✅ GITHUB OTA SETTINGS
// NOTE: Must use 'raw.githubusercontent.com' links!
const char* URL_VERSION_JSON = "https://raw.githubusercontent.com/spnk89z/Temprature_Sensor/main/version.json";

// Public key for OTA verification - replace with your actual public key PEM
const char OTA_PUBKEY_PEM[] = R"KEY(-----BEGIN PUBLIC KEY-----
REPLACE_WITH_YOUR_PUBLIC_KEY
-----END PUBLIC KEY-----)KEY";

// Encrypted config file
#define CONFIG_FILE       "/config.enc"
#define ENC_KEY           "ChangeThisKey123!"   // CHANGE THIS IN PRODUCTION

// MQTT defaults (can be changed in UI)
#define MQTT_PORT_DEFAULT "1883"

// -------------------- OBJECTS --------------------
DHT dht(DHTPIN, DHTTYPE);
WiFiClient espClient;
PubSubClient mqttClient(espClient);
AsyncWebServer server(80);
AsyncWebSocket ws("/ws");

// -------------------- CONFIG STATE --------------------
char device_name[40]   = "UltimumSensor";
char device_room[40]   = "Living Room";

char mqtt_server[40]   = "";
char mqtt_port[6]      = MQTT_PORT_DEFAULT;
char mqtt_user[20]     = "";
char mqtt_pass[20]     = "";

// Role-based auth
char admin_user[20]    = "admin";
char admin_pass[20]    = "admin";
char viewer_user[20]   = "viewer";
char viewer_pass[20]   = "viewer";

// Sensor calibration & alerts
float temp_offset      = 0.0;
float hum_offset       = 0.0;
bool  use_fahrenheit   = false;
float alert_temp_high  = 50.0;
float alert_temp_warn  = 40.0;

// Webhook
bool  enable_webhook   = false;
char  webhook_url[150] = "";

// Sinric Pro (optional)
bool  enable_sinric    = false;
char  sinric_app_key[80]    = "";
char  sinric_app_secret[80] = "";
char  sinric_dev_id[40]     = "";

// -------------------- RUNTIME STATE --------------------
float lastTemp = NAN;
float lastHum  = NAN;
bool  alertHigh = false;
bool  alertWarn = false;

unsigned long lastSensorRead  = 0;
unsigned long lastMqttPush    = 0;
unsigned long sensorInterval  = 10 * 1000;   // 10s
unsigned long pushInterval    = 60 * 1000;   // 60s

// OTA Timer
unsigned long lastOtaCheck    = 0;
const unsigned long OTA_CHECK_INTERVAL = 6UL * 60UL * 60UL * 1000UL; // Check every 6 hours

// Login security
uint8_t        loginFailures  = 0;
const uint8_t  MAX_LOGIN_FAIL = 5;
unsigned long  lockoutUntil   = 0;
const unsigned long LOCKOUT_MS = 5UL * 60UL * 1000UL;  // 5 minutes

// HA / MQTT
bool mqttConfigured = false;

// ---------- HA robustness helpers ----------
unsigned long lastHADiscovery   = 0;
unsigned long lastHAStatePush   = 0;
const unsigned long haRediscoveryInterval = 3UL * 60UL * 1000UL; // 3 minutes
const unsigned long haStateInterval       = 60UL * 1000UL;       // 1 minute

// -------------------- HELPERS --------------------

String sanitize(String s) {
  s.replace(" ", "_");
  s.replace(":", "");
  s.replace("/", "");
  s.replace(".", "");
  return s;
}

String getUptime() {
  unsigned long ms = millis();
  unsigned long s  = ms / 1000;
  unsigned long m  = s / 60;
  unsigned long h  = m / 60;
  unsigned long d  = h / 24;
  s %= 60;
  m %= 60;
  h %= 24;
  char buf[32];
  snprintf(buf, sizeof(buf), "%lud %luh %lum", d, h, m);
  return String(buf);
}

bool usingDefaultAdmin() {
  return (String(admin_user) == "admin" && String(admin_pass) == "admin");
}

bool usingDefaultViewer() {
  return (String(viewer_user) == "viewer" && String(viewer_pass) == "viewer");
}

// -------------------- ENCRYPTION --------------------
String encryptConfig(const String &plain) {
  String out;
  out.reserve(plain.length() * 2);
  size_t keyLen = strlen(ENC_KEY);
  for (size_t i = 0; i < plain.length(); i++) {
    uint8_t b = (uint8_t)plain[i];
    uint8_t k = (uint8_t)ENC_KEY[i % keyLen];
    uint8_t e = b ^ k;
    char buf[3];
    snprintf(buf, sizeof(buf), "%02X", e);
    out += buf;
  }
  return out;
}

uint8_t hexNibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return 0;
}

String decryptConfig(const String &hex) {
  String out;
  size_t keyLen = strlen(ENC_KEY);
  size_t j = 0;
  for (size_t i = 0; i + 1 < hex.length(); i += 2) {
    uint8_t e = (hexNibble(hex[i]) << 4) | hexNibble(hex[i + 1]);
    uint8_t k = (uint8_t)ENC_KEY[j % keyLen];
    char c = (char)(e ^ k);
    out += c;
    j++;
  }
  return out;
}

// -------------------- CONFIG I/O --------------------

void loadConfig() {
  if (!LittleFS.begin()) {
    LittleFS.format();
    LittleFS.begin();
  }
  if (!LittleFS.exists(CONFIG_FILE)) return;

  File f = LittleFS.open(CONFIG_FILE, "r");
  if (!f) return;
  String enc = f.readString();
  f.close();

  String json = decryptConfig(enc);
  DynamicJsonDocument doc(2048);
  DeserializationError err = deserializeJson(doc, json);
  if (err) return;

  if (doc.containsKey("device_name")) strcpy(device_name, doc["device_name"]);
  if (doc.containsKey("device_room")) strcpy(device_room, doc["device_room"]);
  if (doc.containsKey("mqtt_server")) strcpy(mqtt_server, doc["mqtt_server"]);
  if (doc.containsKey("mqtt_port"))   strcpy(mqtt_port,   doc["mqtt_port"]);
  if (doc.containsKey("mqtt_user"))   strcpy(mqtt_user,   doc["mqtt_user"]);
  if (doc.containsKey("mqtt_pass"))   strcpy(mqtt_pass,   doc["mqtt_pass"]);
  if (doc.containsKey("admin_user"))  strcpy(admin_user, doc["admin_user"]);
  if (doc.containsKey("admin_pass"))  strcpy(admin_pass, doc["admin_pass"]);
  if (doc.containsKey("viewer_user")) strcpy(viewer_user, doc["viewer_user"]);
  if (doc.containsKey("viewer_pass")) strcpy(viewer_pass, doc["viewer_pass"]);
  if (doc.containsKey("temp_offset")) temp_offset = doc["temp_offset"];
  if (doc.containsKey("hum_offset"))  hum_offset  = doc["hum_offset"];
  if (doc.containsKey("use_fahrenheit")) use_fahrenheit = doc["use_fahrenheit"];
  if (doc.containsKey("alert_high"))  alert_temp_high = doc["alert_high"];
  if (doc.containsKey("alert_warn"))  alert_temp_warn = doc["alert_warn"];
  if (doc.containsKey("enable_webhook")) enable_webhook = doc["enable_webhook"];
  if (doc.containsKey("webhook_url"))    strcpy(webhook_url, doc["webhook_url"]);
  if (doc.containsKey("enable_sinric")) enable_sinric = doc["enable_sinric"];
  if (doc.containsKey("sinric_key"))    strcpy(sinric_app_key, doc["sinric_key"]);
  if (doc.containsKey("sinric_secret")) strcpy(sinric_app_secret, doc["sinric_secret"]);
  if (doc.containsKey("sinric_id"))     strcpy(sinric_dev_id, doc["sinric_id"]);

  mqttConfigured = strlen(mqtt_server) > 0;
}

void saveConfig() {
  DynamicJsonDocument doc(2048);
  doc["device_name"] = device_name;
  doc["device_room"] = device_room;
  doc["mqtt_server"] = mqtt_server;
  doc["mqtt_port"]   = mqtt_port;
  doc["mqtt_user"]   = mqtt_user;
  doc["mqtt_pass"]   = mqtt_pass;
  doc["admin_user"]  = admin_user;
  doc["admin_pass"]  = admin_pass;
  doc["viewer_user"] = viewer_user;
  doc["viewer_pass"] = viewer_pass;
  doc["temp_offset"] = temp_offset;
  doc["hum_offset"]  = hum_offset;
  doc["use_fahrenheit"] = use_fahrenheit;
  doc["alert_high"]  = alert_temp_high;
  doc["alert_warn"]  = alert_temp_warn;
  doc["enable_webhook"] = enable_webhook;
  doc["webhook_url"]    = webhook_url;
  doc["enable_sinric"]  = enable_sinric;
  doc["sinric_key"]     = sinric_app_key;
  doc["sinric_secret"]  = sinric_app_secret;
  doc["sinric_id"]      = sinric_dev_id;

  String json;
  serializeJson(doc, json);
  String enc = encryptConfig(json);

  File f = LittleFS.open(CONFIG_FILE, "w");
  if (!f) return;
  f.print(enc);
  f.close();
}

// -------------------- SECURITY HELPERS --------------------

bool isAdmin(AsyncWebServerRequest *request) {
  return request->authenticate(admin_user, admin_pass);
}

bool isViewer(AsyncWebServerRequest *request) {
  return request->authenticate(viewer_user, viewer_pass);
}

bool ensureAdmin(AsyncWebServerRequest *request) {
  unsigned long now = millis();
  if (now < lockoutUntil) {
    request->send(429, "text/plain", "Too many failed logins. Try later.");
    return false;
  }
  if (!isAdmin(request)) {
    loginFailures++;
    if (loginFailures >= MAX_LOGIN_FAIL) {
      lockoutUntil = now + LOCKOUT_MS;
      loginFailures = 0;
    }
    request->requestAuthentication("Ultimum Admin");
    return false;
  }
  loginFailures = 0;
  return true;
}

bool ensureViewerOrAdmin(AsyncWebServerRequest *request) {
  unsigned long now = millis();
  if (now < lockoutUntil) {
    request->send(429, "text/plain", "Too many failed logins. Try later.");
    return false;
  }
  if (isAdmin(request) || isViewer(request)) {
    loginFailures = 0;
    return true;
  }
  loginFailures++;
  if (loginFailures >= MAX_LOGIN_FAIL) {
    lockoutUntil = now + LOCKOUT_MS;
    loginFailures = 0;
  }
  request->requestAuthentication("Ultimum Viewer");
  return false;
}

// -------------------- SENSOR & DATA --------------------

void readSensor() {
  float t = dht.readTemperature();
  float h = dht.readHumidity();

  if (!isnan(t)) {
    t += temp_offset;
    if (use_fahrenheit) t = t * 1.8 + 32;
    lastTemp = t;
  }
  if (!isnan(h)) {
    h += hum_offset;
    lastHum = h;
  }

  if (!isnan(lastTemp)) {
    alertHigh = lastTemp > alert_temp_high;
    alertWarn = (!alertHigh && lastTemp > alert_temp_warn);
  }
}

// -------------------- WEBSOCKET --------------------

void broadcastStateWS() {
  DynamicJsonDocument doc(512);
  doc["type"] = "state";
  doc["temp"] = isnan(lastTemp) ? 0 : lastTemp;
  doc["hum"]  = isnan(lastHum) ? 0 : lastHum;
  doc["rssi"] = WiFi.RSSI();
  doc["uptime"] = getUptime();
  doc["unit"] = use_fahrenheit ? "F" : "C";
  doc["alertHigh"] = alertHigh;
  doc["alertWarn"] = alertWarn;
  String out;
  serializeJson(doc, out);
  ws.textAll(out);
}

void onWsEvent(AsyncWebSocket * serverPtr,
               AsyncWebSocketClient * client,
               AwsEventType type,
               void * arg, uint8_t * data, size_t len) {

  if (type == WS_EVT_CONNECT) {
    broadcastStateWS();
  } else if (type == WS_EVT_DATA) {
    AwsFrameInfo * info = (AwsFrameInfo*)arg;
    if (info->final && info->index == 0 && info->len == len && info->opcode == WS_TEXT) {
      String msg;
      for (size_t i = 0; i < len; i++) msg += (char)data[i];
      if (msg == "ping") {
        client->text("{\"type\":\"pong\"}");
      }
    }
  }
}

// -------------------- MQTT + HA --------------------

String haAvailTopic() { return "home/" + sanitize(device_name) + "/status"; }
String haStateTopic() { return "home/" + sanitize(device_name) + "/state"; }

void sendHaDiscovery() {
  if (!mqttClient.connected()) return;

  String base = sanitize(device_name);
  String uid = base + "_" + WiFi.macAddress();
  uid.replace(":", "");
  uid.toLowerCase();
  String avail = haAvailTopic();

  DynamicJsonDocument dev(256);
  JsonObject d = dev.createNestedObject("dev");
  d["ids"]  = uid;
  d["name"] = device_name;
  d["mf"]   = "Ultimum";
  d["mdl"]  = "ESP8266-DHT";
  d["sw"]   = FW_VERSION;
  d["cu"]   = "http://" + WiFi.localIP().toString(); 

  auto publishSensor = [&](const String &suffix,
                           const String &name,
                           const String &dev_class,
                           const String &unit,
                           const String &valTpl,
                           const String &entity_category,
                           const String &icon,
                           bool measurement) {
    DynamicJsonDocument doc(512);
    if (name.length()) doc["name"] = String(device_name) + " " + name;
    doc["uniq_id"] = uid + suffix;
    if (dev_class.length()) doc["dev_cla"] = dev_class;
    if (unit.length()) doc["unit_of_meas"] = unit;
    if (entity_category.length()) doc["ent_cat"] = entity_category;
    if (icon.length()) doc["ic"] = icon;
    if (measurement)   doc["stat_cla"] = "measurement";
    doc["stat_t"]  = haStateTopic();
    doc["val_tpl"] = valTpl;
    doc["avty_t"]  = avail;
    doc["dev"]     = d;
    String payload;
    serializeJson(doc, payload);
    String topic = "homeassistant/sensor/" + base + suffix + "/config";
    if (!mqttClient.publish(topic.c_str(), payload.c_str(), true)) {
        Serial.print("❌ FAILED HA DISCOVERY: "); Serial.println(name);
    }
  };

  // Sensors
  publishSensor("_temp", "Temperature", "temperature", use_fahrenheit ? "°F" : "°C", "{{ value_json.temperature }}", "", "mdi:thermometer", true);
  publishSensor("_hum", "Humidity", "humidity", "%", "{{ value_json.humidity }}", "", "mdi:water-percent", true);
  publishSensor("_rssi", "Signal", "signal_strength", "dBm", "{{ value_json.rssi }}", "diagnostic", "mdi:wifi", true);
  publishSensor("_uptime", "Uptime", "", "", "{{ value_json.uptime }}", "diagnostic", "mdi:timer-outline", false);
  publishSensor("_heap", "Free Heap", "data_size", "B", "{{ value_json.heap }}", "diagnostic", "mdi:memory", true);
  publishSensor("_ip", "IP Address", "", "", "{{ value_json.ip }}", "diagnostic", "mdi:ip", false);
  publishSensor("_ssid", "WiFi SSID", "", "", "{{ value_json.ssid }}", "diagnostic", "mdi:wifi-settings", false);
  publishSensor("_fw", "Firmware", "", "", "{{ value_json.fw }}", "diagnostic", "mdi:chip", false);

  // Binary Sensors
  {
    DynamicJsonDocument doc(512);
    doc["name"] = String(device_name) + " High Temp Alert";
    doc["uniq_id"] = uid + "_alert_high";
    doc["dev_cla"] = "heat";
    doc["ent_cat"] = "diagnostic";
    doc["stat_t"] = haStateTopic();
    doc["val_tpl"] = "{{ value_json.alert_high }}";
    doc["avty_t"] = avail;
    doc["ic"] = "mdi:thermometer-alert";
    doc["dev"] = d;
    String payload; serializeJson(doc, payload);
    mqttClient.publish(("homeassistant/binary_sensor/" + base + "_alert_high/config").c_str(), payload.c_str(), true);
  }
  {
    DynamicJsonDocument doc(512);
    doc["name"] = String(device_name) + " Warning Temp Alert";
    doc["uniq_id"] = uid + "_alert_warn";
    doc["dev_cla"] = "heat";
    doc["ent_cat"] = "diagnostic";
    doc["stat_t"] = haStateTopic();
    doc["val_tpl"] = "{{ value_json.alert_warn }}";
    doc["avty_t"] = avail;
    doc["ic"] = "mdi:thermometer-alert";
    doc["dev"] = d;
    String payload; serializeJson(doc, payload);
    mqttClient.publish(("homeassistant/binary_sensor/" + base + "_alert_warn/config").c_str(), payload.c_str(), true);
  }
  {
    DynamicJsonDocument doc(512);
    doc["name"] = String(device_name) + " Availability";
    doc["uniq_id"] = uid + "_avail";
    doc["dev_cla"] = "connectivity";
    doc["stat_t"] = avail;
    doc["pl_on"] = "online";
    doc["pl_off"] = "offline";
    doc["ent_cat"] = "diagnostic";
    doc["ic"] = "mdi:lan-connect";
    doc["dev"] = d;
    String payload; serializeJson(doc, payload);
    mqttClient.publish(("homeassistant/binary_sensor/" + base + "_avail/config").c_str(), payload.c_str(), true);
  }

  // OTA Switch
  {
    DynamicJsonDocument doc(512);
    doc["name"]     = String(device_name) + " OTA Update";
    doc["uniq_id"]  = uid + "_ota";
    doc["cmd_t"]    = "home/" + base + "/ota";
    doc["pl_on"]    = "check";          
    doc["pl_off"]   = "idle";
    doc["icon"]     = "mdi:cloud-download";
    doc["avty_t"]   = avail;
    doc["dev"]      = d;
    String payload; serializeJson(doc, payload);
    mqttClient.publish(("homeassistant/switch/" + base + "_ota/config").c_str(), payload.c_str(), true);
  }

  mqttClient.publish(avail.c_str(), "online", true);
  Serial.println(F("[HA] Discovery payloads processed"));
}

void mqttPushState() {
  if (!mqttClient.connected()) return;
  DynamicJsonDocument doc(512);
  doc["temperature"] = isnan(lastTemp) ? 0 : lastTemp;
  doc["humidity"] = isnan(lastHum) ? 0 : lastHum;
  doc["rssi"]        = WiFi.RSSI();
  doc["uptime"]      = getUptime();
  doc["heap"]        = ESP.getFreeHeap();
  doc["ip"]          = WiFi.localIP().toString();
  doc["ssid"]        = WiFi.SSID();
  doc["fw"]          = FW_VERSION;
  doc["alert_high"]  = alertHigh ? "ON" : "OFF";
  doc["alert_warn"]  = alertWarn ? "ON" : "OFF";
  String out;
  serializeJson(doc, out);
  mqttClient.publish(haAvailTopic().c_str(), "online", true);
  mqttClient.publish(haStateTopic().c_str(), out.c_str(), true);
}


// ---------------------------------------------------------
// ✅ NEW: GITHUB OTA UPDATE FUNCTION
// ---------------------------------------------------------
// Helper: save a URL into LittleFS
static bool saveUrlToFS(const String &url, const String &path) {
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient https;
  if (!https.begin(client, url)) return false;
  int httpCode = https.GET();
  if (httpCode != HTTP_CODE_OK) { https.end(); return false; }
  File f = LittleFS.open(path, "w");
  if (!f) { https.end(); return false; }
  const size_t bufSz = 1024;
  uint8_t buffer[bufSz];
  while (https.getStream().connected()) {
    size_t available = (size_t)https.getStream().available();
    if (available) {
      int read = https.getStream().readBytes((char*)buffer, min((size_t)available, bufSz));
      if (read > 0) f.write(buffer, read);
    } else { if (https.getSize() == 0) break; delay(10); }
  }
  f.close();
  https.end();
  return true;
}

// Helper: Apply update from LittleFS file
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

#ifdef MBEDTLS
static bool verify_ecdsa_signature_file_mbedtls(const char *path, const char *sigBase64, const char *pubkey_pem) {
  mbedtls_pk_context pk; mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *)pubkey_pem, strlen(pubkey_pem)+1);
  if (ret != 0) { Serial.printf("mbedtls_pk_parse_public_key failed: -0x%04x\n", -ret); mbedtls_pk_free(&pk); return false; }
  size_t sigDerLen = 0; unsigned char *sigDer = NULL;
  size_t outLen = (strlen(sigBase64) * 3) / 4 + 4; sigDer = (unsigned char*)malloc(outLen);
  if (!sigDer) { mbedtls_pk_free(&pk); return false; }
  if ((ret = mbedtls_base64_decode(sigDer, outLen, &sigDerLen, (const unsigned char*)sigBase64, strlen(sigBase64))) != 0) { Serial.printf("mbedtls_base64_decode failed: -0x%04x\n", -ret); free(sigDer); mbedtls_pk_free(&pk); return false; }
  mbedtls_sha256_context shaCtx; mbedtls_sha256_init(&shaCtx); mbedtls_sha256_starts_ret(&shaCtx, 0);
  File f = LittleFS.open(path, "r"); if (!f) { free(sigDer); mbedtls_pk_free(&pk); return false; }
  const size_t bufSz = 1024; unsigned char buf[bufSz]; while (f.available()) { size_t r = f.readBytes((char*)buf, bufSz); mbedtls_sha256_update_ret(&shaCtx, buf, r); } f.close();
  unsigned char digest[32]; mbedtls_sha256_finish_ret(&shaCtx, digest); mbedtls_sha256_free(&shaCtx);
  ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, digest, sizeof(digest), sigDer, sigDerLen);
  if (ret != 0) { Serial.printf("mbedtls_pk_verify failed: -0x%04x\n", -ret); free(sigDer); mbedtls_pk_free(&pk); return false; }
  free(sigDer); mbedtls_pk_free(&pk); return true;
}
#endif

void checkGitHubUpdate() {
  Serial.println(F("[OTA] Checking GitHub for updates..."));
  
  WiFiClientSecure client;
  client.setInsecure(); // Needed for GitHub HTTPS (skips cert validation)
  
  HTTPClient https;
  
  // 1. Get version.json
  if (https.begin(client, URL_VERSION_JSON)) {
    int httpCode = https.GET();
    if (httpCode == HTTP_CODE_OK) {
      String payload = https.getString();
      Serial.println("[OTA] JSON: " + payload);
      
      DynamicJsonDocument doc(512);
      deserializeJson(doc, payload);
      
      String newVer = doc["version"];
      String binUrl = doc["bin"];
      String expectedSha = doc.containsKey("sha256") ? doc["sha256"].as<String>() : String("");
      String sigB64 = doc.containsKey("sig") ? doc["sig"].as<String>() : String("");
      String sigAlgo = doc.containsKey("sig_algo") ? doc["sig_algo"].as<String>() : String("");
      
      if (newVer != FW_VERSION) {
        Serial.println("[OTA] New version found: " + newVer);
        Serial.println("[OTA] Starting download from: " + binUrl);
        
        // 2. If a signature is present, we'll verify it against the file.
        if (sigB64.length() > 0) {
#ifdef MBEDTLS
          Serial.println(F("[OTA] Signature present, verifying before update..."));
          const char *tmpPath = "/newfw.bin";
          if (!saveUrlToFS(binUrl, tmpPath)) {
            Serial.println(F("[OTA] Failed to download firmware to FS"));
          } else {
            // Check SHA256 if provided
            if (expectedSha.length() > 0) {
              // compute sha256 using mbedtls
              mbedtls_sha256_context shaCtx;
              mbedtls_sha256_init(&shaCtx);
              mbedtls_sha256_starts_ret(&shaCtx, 0);
              File f = LittleFS.open(tmpPath, "r");
              if (!f) {
                Serial.println(F("[OTA] Failed to open downloaded file for hash"));
              } else {
                const size_t bufSz = 1024;
                uint8_t buf[bufSz];
                while (f.available()) {
                  size_t r = f.readBytes((char*)buf, bufSz);
                  mbedtls_sha256_update_ret(&shaCtx, buf, r);
                }
                f.close();
                unsigned char digest[32];
                mbedtls_sha256_finish_ret(&shaCtx, digest);
                mbedtls_sha256_free(&shaCtx);
                char hexDigest[65] = {0};
                for (int i = 0; i < 32; i++) sprintf(hexDigest + i*2, "%02x", digest[i]);
                String computedHex(hexDigest);
                if (expectedSha.length() && computedHex != expectedSha) {
                  Serial.println(F("[OTA] SHA mismatch, aborting OTA"));
                } else {
                  if (verify_ecdsa_signature_file_mbedtls(tmpPath, sigB64.c_str(), OTA_PUBKEY_PEM)) {
                    Serial.println(F("[OTA] Signature OK, applying update from FS..."));
                    if (!applyUpdateFromFS(tmpPath)) {
                      Serial.println(F("[OTA] Update from FS failed"));
                    }
                  } else {
                    Serial.println(F("[OTA] Signature verification failed, aborting OTA"));
                  }
                }
              }
            } else {
              // No expected sha; just verify signature
              if (verify_ecdsa_signature_file_mbedtls(tmpPath, sigB64.c_str(), OTA_PUBKEY_PEM)) {
                if (!applyUpdateFromFS(tmpPath)) {
                  Serial.println(F("[OTA] Update from FS failed"));
                }
              } else {
                Serial.println(F("[OTA] Signature verification failed, aborting OTA"));
              }
            }
          }
#else
          Serial.println(F("[OTA] Signature found but MBEDTLS not enabled; aborting for safety."));
#endif
        } else {
          // No signature: fallback to typical HTTP OTA
          t_httpUpdate_return ret = ESPhttpUpdate.update(client, binUrl);
          switch (ret) {
            case HTTP_UPDATE_FAILED:
              Serial.printf("HTTP_UPDATE_FAILED Error (%d): %s\n", ESPhttpUpdate.getLastError(), ESPhttpUpdate.getLastErrorString().c_str());
              break;
            case HTTP_UPDATE_NO_UPDATES:
              Serial.println("HTTP_UPDATE_NO_UPDATES");
              break;
            case HTTP_UPDATE_OK:
              Serial.println("HTTP_UPDATE_OK");
              break;
          }
        }
      } else {
        Serial.println(F("[OTA] System is up to date."));
      }
    } else {
      Serial.printf("[OTA] Failed to get version.json, error: %s\n", https.errorToString(httpCode).c_str());
    }
    https.end();
  } else {
    Serial.println(F("[OTA] Connection to GitHub failed"));
  }
}

// MQTT Callback (Trigger OTA via HA Switch)
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String t = String(topic);
  String msg;
  for (unsigned int i = 0; i < length; i++) msg += (char)payload[i];

  if (t == "home/" + sanitize(device_name) + "/ota") {
    if (msg == "check") {
      Serial.println(F("[MQTT] Manual OTA check triggered"));
      // Reset switch state in HA immediately
      mqttClient.publish(("home/" + sanitize(device_name) + "/ota").c_str(), "idle"); 
      checkGitHubUpdate();
    }
  }
}

bool mqttReconnect() {
  if (!mqttConfigured) return false;
  if (mqttClient.connected()) return true;

  String clientId = "Ultimum-" + WiFi.macAddress();
  String avail = haAvailTopic();

  bool ok;
  if (strlen(mqtt_user) > 0) {
    ok = mqttClient.connect(clientId.c_str(), mqtt_user, mqtt_pass, avail.c_str(), 1, true, "offline");
  } else {
    ok = mqttClient.connect(clientId.c_str(), NULL, NULL, avail.c_str(), 1, true, "offline");
  }

  if (ok) {
    mqttClient.publish(avail.c_str(), "online", true);
    mqttClient.subscribe(("home/" + sanitize(device_name) + "/ota").c_str());
    delay(300);
    sendHaDiscovery();
    mqttPushState();
    lastHADiscovery = millis();
    lastHAStatePush = millis();
    Serial.println(F("[MQTT] Connected"));
  }
  return ok;
}

// -------------------- WEBHOOK + SINRIC --------------------

void sendWebhook(float t, float h) {
  if (!enable_webhook || strlen(webhook_url) < 5) return;
  WiFiClient wc;
  HTTPClient http;
  if (!http.begin(wc, webhook_url)) return;
  http.addHeader("Content-Type", "application/json");
  DynamicJsonDocument doc(256);
  doc["device"] = device_name;
  doc["temp"]   = t;
  doc["hum"]    = h;
  doc["rssi"]   = WiFi.RSSI();
  String payload; serializeJson(doc, payload);
  http.POST(payload);
  http.end();
}

void sendSinric(float t, float h) {
  if (!enable_sinric || strlen(sinric_app_key) == 0 || strlen(sinric_dev_id) == 0) return;
  SinricProTemperaturesensor &mySensor = SinricPro[sinric_dev_id];
  mySensor.sendTemperatureEvent(t, h);
}

// -------------------- WEB UI HTML --------------------

String htmlRoot() {
  String html;
  html += "<!DOCTYPE html><html><head><meta charset='utf-8'><title>";
  html += device_name;
  html += "</title><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>";
  html += "<style>body{margin:0;font-family:Segoe UI,Arial;background:#0f172a;color:#e5e7eb;}.container{max-width:900px;margin:0 auto;padding:20px;}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:16px;}.card{background:#020617;border-radius:14px;padding:12px 14px;border:1px solid #1f2937;box-shadow:0 15px 30px rgba(0,0,0,.35);}.label{font-size:12px;opacity:.7;text-transform:uppercase;letter-spacing:.08em;}.val{font-size:26px;font-weight:600;margin-top:4px;}.sub{font-size:12px;opacity:.6;margin-top:6px;}.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}.pill{font-size:11px;padding:4px 8px;border-radius:999px;background:#111827;color:#9ca3af;border:1px solid #1f2937;}.status-ok{color:#22c55e;} .status-warn{color:#f59e0b;} .status-high{color:#ef4444;}a.btn,button.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:999px;font-size:13px;border:1px solid #1f2937;background:#020617;color:#e5e7eb;text-decoration:none;cursor:pointer;}a.btn:hover,button.btn:hover{background:#111827;}#chartWrap{background:#020617;border-radius:16px;padding:12px 12px 16px;border:1px solid #1f2937;}</style></head><body>";
  html += "<div class='container'><div class='topbar'><div><div class='label'>ESP8266 ULTIMUM</div><div style='font-size:18px;font-weight:600;'>" + String(device_name) + "</div></div>";
  html += "<div style='display:flex;gap:8px;align-items:center;'><span class='pill'>FW " FW_VERSION "</span><a class='btn' href='/settings'>⚙ Settings</a></div></div>";
  html += "<div class='cards'><div class='card'><div class='label'>Temperature</div><div class='val' id='tVal'>--</div><div class='sub' id='tAlert'></div></div>";
  html += "<div class='card'><div class='label'>Humidity</div><div class='val' id='hVal'>--</div></div>";
  html += "<div class='card'><div class='label'>WiFi Signal</div><div class='val' id='rssiVal'>--</div><div class='sub' id='ssidVal'></div></div>";
  html += "<div class='card'><div class='label'>Uptime</div><div class='val' id='uptimeVal'>--</div></div></div>";
  html += "<div id='chartWrap'><canvas id='chart' height='260'></canvas></div>";
  html += "<div style='margin-top:14px;font-size:12px;opacity:.6;'>IP: " + WiFi.localIP().toString() + " &bull; SSID: " + WiFi.SSID() + " &bull; Heap: " + String(ESP.getFreeHeap()) + " B</div></div>";
  html += "<script>let ws;let chart;let labels=[],temps=[],hums=[];function connectWS(){let proto=(location.protocol==='https:')?'wss://':'ws://';ws=new WebSocket(proto+location.host+'/ws');ws.onmessage=(ev)=>{let d=JSON.parse(ev.data);if(d.type==='state'){updateUI(d);pushChart(d)}};ws.onclose=()=>setTimeout(connectWS,3000);}function initChart(){const ctx=document.getElementById('chart').getContext('2d');chart=new Chart(ctx,{type:'line',data:{labels:labels,datasets:[{label:'Temp',data:temps,borderWidth:2,tension:.25},{label:'Hum',data:hums,borderWidth:2,tension:.25}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#9ca3af',font:{size:11}}}},scales:{x:{ticks:{color:'#6b7280',maxTicksLimit:6},grid:{display:false}},y:{ticks:{color:'#6b7280'},grid:{color:'rgba(31,41,55,.6)'}}}}});}function pushChart(d){let ts=new Date().toLocaleTimeString();labels.push(ts);temps.push(d.temp);hums.push(d.hum);if(labels.length>60){labels.shift();temps.shift();hums.shift();}chart.update('none');}function updateUI(d){document.getElementById('tVal').innerHTML=d.temp.toFixed(1)+'°'+d.unit;document.getElementById('hVal').innerHTML=d.hum.toFixed(0)+'%';document.getElementById('rssiVal').innerHTML=d.rssi+' dBm';document.getElementById('uptimeVal').innerHTML=d.uptime;document.getElementById('ssidVal').innerHTML='SSID: '+(d.ssid||'');let a=document.getElementById('tAlert');a.className='sub';if(d.alertHigh){a.innerHTML='High temperature!';a.className+=' status-high';}else if(d.alertWarn){a.innerHTML='Warning threshold';a.className+=' status-warn';}else{a.innerHTML='Normal range';a.className+=' status-ok';}}window.addEventListener('load',()=>{initChart();connectWS();});</script></body></html>";
  return html;
}

String htmlSettings() {
  String html;
  html += "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Settings</title><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<style>body{font-family:Segoe UI,Arial;background:#020617;color:#e5e7eb;margin:0;} .wrap{max-width:900px;margin:0 auto;padding:20px;} fieldset{border:1px solid #1f2937;border-radius:10px;margin-bottom:16px;padding:14px;} legend{padding:0 6px;font-size:13px;opacity:.8;} label{display:block;font-size:13px;margin-top:6px;margin-bottom:2px;} input[type=text],input[type=password]{width:100%;padding:6px 8px;border-radius:6px;border:1px solid #374151;background:#020617;color:#e5e7eb;font-size:13px;} .row{display:grid;grid-template-columns:1fr 1fr;gap:10px;} button{margin-top:10px;padding:8px 14px;border-radius:999px;border:1px solid #1f2937;background:#111827;color:#e5e7eb;cursor:pointer;} button:hover{background:#1f2937;} .badge{display:inline-block;font-size:11px;padding:3px 8px;border-radius:999px;border:1px solid #7f1d1d;color:#fca5a5;background:#450a0a;margin-left:8px;}</style></head><body><div class='wrap'>";
  html += "<h2>Settings - " + String(device_name) + "</h2>";
  if (usingDefaultAdmin()) html += "<div class='badge'>⚠ Change default admin credentials!</div>";
  if (usingDefaultViewer()) html += "<div class='badge'>⚠ Change default viewer credentials!</div>";
  html += "<form method='POST' action='/settings/save'>";
  html += "<fieldset><legend>Device</legend><label>Device Name</label><input type='text' name='name' value='" + String(device_name) + "'><label>Room</label><input type='text' name='room' value='" + String(device_room) + "'></fieldset>";
  html += "<fieldset><legend>Users</legend><div class='row'><div><label>Admin User</label><input type='text' name='admin_user' value='" + String(admin_user) + "'><label>Admin Pass</label><input type='password' name='admin_pass' value='" + String(admin_pass) + "'></div><div><label>Viewer User</label><input type='text' name='viewer_user' value='" + String(viewer_user) + "'><label>Viewer Pass</label><input type='password' name='viewer_pass' value='" + String(viewer_pass) + "'></div></div></fieldset>";
  html += "<fieldset><legend>MQTT</legend><label>Server</label><input type='text' name='mqtt_server' value='" + String(mqtt_server) + "'><div class='row'><div><label>Port</label><input type='text' name='mqtt_port' value='" + String(mqtt_port) + "'></div><div><label>User</label><input type='text' name='mqtt_user' value='" + String(mqtt_user) + "'></div></div><label>Password</label><input type='password' name='mqtt_pass' value='" + String(mqtt_pass) + "'></fieldset>";
  html += "<fieldset><legend>Calibration & Alerts</legend><div class='row'><div><label>Temperature Offset</label><input type='text' name='temp_off' value='" + String(temp_offset) + "'></div><div><label>Humidity Offset</label><input type='text' name='hum_off' value='" + String(hum_offset) + "'></div></div><div class='row'><div><label>Warning Threshold</label><input type='text' name='warn_thr' value='" + String(alert_temp_warn) + "'></div><div><label>High Threshold</label><input type='text' name='high_thr' value='" + String(alert_temp_high) + "'></div></div><label><input type='checkbox' name='use_f' " + String(use_fahrenheit ? "checked" : "") + "> Use Fahrenheit</label></fieldset>";
  html += "<fieldset><legend>Webhook</legend><label><input type='checkbox' name='wh_en' " + String(enable_webhook ? "checked" : "") + "> Enable Webhook</label><label>Webhook URL</label><input type='text' name='wh_url' value='" + String(webhook_url) + "'></fieldset>";
  html += "<fieldset><legend>Sinric Pro</legend><label><input type='checkbox' name='sin_en' " + String(enable_sinric ? "checked" : "") + "> Enable Sinric Pro</label><label>App Key</label><input type='text' name='sin_key' value='" + String(sinric_app_key) + "'><label>App Secret</label><input type='text' name='sin_sec' value='" + String(sinric_app_secret) + "'><label>Device ID</label><input type='text' name='sin_id' value='" + String(sinric_dev_id) + "'></fieldset>";
  html += "<button type='submit'>Save & Reboot</button> <a href='/'><button type='button'>Back</button></a></form></div></body></html>";
  return html;
}

// -------------------- REST API --------------------
void handleApiState(AsyncWebServerRequest *request) {
  if (!ensureViewerOrAdmin(request)) return;
  DynamicJsonDocument doc(512);
  doc["device"] = device_name;
  doc["temperature"] = isnan(lastTemp) ? 0 : lastTemp;
  doc["humidity"]    = isnan(lastHum) ? 0 : lastHum;
  doc["fw"]   = FW_VERSION;
  String out; serializeJson(doc, out);
  request->send(200, "application/json", out);
}

void handleApiConfig(AsyncWebServerRequest *request) {
  if (!ensureAdmin(request)) return;
  DynamicJsonDocument doc(512);
  doc["device_name"] = device_name;
  doc["mqtt_server"] = mqtt_server;
  String out; serializeJson(doc, out);
  request->send(200, "application/json", out);
}

void handleApiReboot(AsyncWebServerRequest *request) {
  if (!ensureAdmin(request)) return;
  request->send(200, "text/plain", "Rebooting");
  delay(500); ESP.restart();
}

void handleApiOta(AsyncWebServerRequest *request) {
  if (!ensureAdmin(request)) return;
  // Trigger update check via API
  checkGitHubUpdate();
  request->send(200, "text/plain", "OTA check triggered. Check Serial/Logs.");
}

// -------------------- SETUP & LOOP --------------------

void setupWeb() {
  ws.onEvent(onWsEvent);
  server.addHandler(&ws);
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) { if (!ensureViewerOrAdmin(request)) return; request->send(200, "text/html", htmlRoot()); });
  server.on("/settings", HTTP_GET, [](AsyncWebServerRequest *request) { if (!ensureAdmin(request)) return; request->send(200, "text/html", htmlSettings()); });
  server.on("/settings/save", HTTP_POST, [](AsyncWebServerRequest *request) {
    if (!ensureAdmin(request)) return;
    if (request->hasParam("name", true))       strcpy(device_name, request->getParam("name", true)->value().c_str());
    if (request->hasParam("room", true))       strcpy(device_room, request->getParam("room", true)->value().c_str());
    if (request->hasParam("admin_user", true)) strcpy(admin_user,  request->getParam("admin_user", true)->value().c_str());
    if (request->hasParam("admin_pass", true)) strcpy(admin_pass,  request->getParam("admin_pass", true)->value().c_str());
    if (request->hasParam("viewer_user", true))strcpy(viewer_user, request->getParam("viewer_user", true)->value().c_str());
    if (request->hasParam("viewer_pass", true))strcpy(viewer_pass, request->getParam("viewer_pass", true)->value().c_str());
    if (request->hasParam("mqtt_server", true)) strcpy(mqtt_server, request->getParam("mqtt_server", true)->value().c_str());
    if (request->hasParam("mqtt_port", true))   strcpy(mqtt_port,   request->getParam("mqtt_port", true)->value().c_str());
    if (request->hasParam("mqtt_user", true))   strcpy(mqtt_user,   request->getParam("mqtt_user", true)->value().c_str());
    if (request->hasParam("mqtt_pass", true))   strcpy(mqtt_pass,   request->getParam("mqtt_pass", true)->value().c_str());
    if (request->hasParam("temp_off", true)) temp_offset  = request->getParam("temp_off", true)->value().toFloat();
    if (request->hasParam("hum_off", true))  hum_offset   = request->getParam("hum_off", true)->value().toFloat();
    if (request->hasParam("warn_thr", true)) alert_temp_warn = request->getParam("warn_thr", true)->value().toFloat();
    if (request->hasParam("high_thr", true)) alert_temp_high = request->getParam("high_thr", true)->value().toFloat();
    use_fahrenheit = request->hasParam("use_f", true);
    enable_webhook = request->hasParam("wh_en", true);
    if (request->hasParam("wh_url", true)) strcpy(webhook_url, request->getParam("wh_url", true)->value().c_str());
    enable_sinric = request->hasParam("sin_en", true);
    if (request->hasParam("sin_key", true)) strcpy(sinric_app_key, request->getParam("sin_key", true)->value().c_str());
    if (request->hasParam("sin_sec", true)) strcpy(sinric_app_secret, request->getParam("sin_sec", true)->value().c_str());
    if (request->hasParam("sin_id", true))  strcpy(sinric_dev_id, request->getParam("sin_id", true)->value().c_str());
    saveConfig();
    mqttConfigured = strlen(mqtt_server) > 0;
    request->send(200, "text/html", "Saved. Rebooting...");
    delay(800); ESP.restart();
  });

  server.on("/api/state", HTTP_GET, handleApiState);
  server.on("/api/config", HTTP_GET, handleApiConfig);
  server.on("/api/reboot", HTTP_POST, handleApiReboot);
  server.on("/api/ota",    HTTP_POST, handleApiOta);
  server.begin();
}

void setupSinric() {
  if (!enable_sinric || strlen(sinric_app_key) == 0) return;
  SinricPro.onConnected([](){ Serial.println("[Sinric] Connected"); });
  SinricPro.onDisconnected([](){ Serial.println("[Sinric] Disconnected"); });
  SinricProTemperaturesensor &mySensor = SinricPro[sinric_dev_id];
  (void)mySensor; 
  SinricPro.begin(sinric_app_key, sinric_app_secret);
}

void setup() {
  Serial.begin(115200);
  delay(200);
  loadConfig();
  dht.begin();

  DNSServer dns;
  AsyncWiFiManager wm(&server, &dns);
  wm.autoConnect(WIFI_AP_SSID, WIFI_AP_PASS);
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  mqttClient.setServer(mqtt_server, atoi(mqtt_port));
  mqttClient.setCallback(mqttCallback);
  mqttClient.setBufferSize(1024);

  String mdnsName = sanitize(device_name);
  if (MDNS.begin(mdnsName.c_str())) Serial.println("mDNS: " + mdnsName + ".local");

  setupWeb();
  setupSinric();

  if (mqttConfigured) mqttReconnect(); 
  Serial.println("Ultimum v" FW_VERSION " started");
}

void loop() {
  if (mqttConfigured) {
    if (!mqttClient.connected()) mqttReconnect();
    mqttClient.loop();
  }
  if (enable_sinric) SinricPro.handle();

  unsigned long now = millis();

  if (now - lastSensorRead > sensorInterval) {
    lastSensorRead = now;
    readSensor();
    broadcastStateWS();
  }

  if (now - lastMqttPush > pushInterval) {
    lastMqttPush = now;
    if (!isnan(lastTemp) && !isnan(lastHum)) {
      mqttPushState();
      sendWebhook(lastTemp, lastHum);
      sendSinric(lastTemp, lastHum);
    }
  }

  if (mqttConfigured && mqttClient.connected()) {
    if (millis() - lastHADiscovery > haRediscoveryInterval) {
      lastHADiscovery = millis();
      sendHaDiscovery();
    }
    if (millis() - lastHAStatePush > haStateInterval) {
      lastHAStatePush = millis();
      mqttPushState();
    }
  }
  
  // ✅ AUTO OTA CHECK TIMER
  if (now - lastOtaCheck > OTA_CHECK_INTERVAL) {
    lastOtaCheck = now;
    if (WiFi.status() == WL_CONNECTED) {
      checkGitHubUpdate();
    }
  }
}
#include <Arduino.h>

#ifndef FW_VERSION
#define FW_VERSION "3.5.1-ULTIMUM"
#endif

void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("Ultimum Mock Firmware starting...");
  Serial.print("FW_VERSION: ");
  Serial.println(FW_VERSION);
}

void loop() {
  delay(1000);
}
