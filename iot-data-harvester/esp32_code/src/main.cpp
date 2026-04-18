/**
 * Project: QuakeGuard - Professional Seismic Node
 * Version: 3.2.0-PROV (Provisioning Edition)
 * Target Hardware: ESP32-C3 SuperMini + ADXL345
 * Author: GiZano
 *
 * CHANGELOG v3.2.0:
 * - FEATURE: Automated Device Handshake (Provisioning).
 * - LOGIC: Removed hardcoded SENSOR_ID. ID is now retrieved from Server and stored in NVS.
 * - SECURITY: Added 'ENROLLMENT_TOKEN' for secure registration.
 */

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_ADXL345_U.h>
#include <WiFi.h>
#include <WiFiManager.h>
#include <HTTPClient.h> // Required for Provisioning POST request
#include <ArduinoJson.h>
#include <Preferences.h>
#include <time.h>

// Cryptographic Libraries
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

// --------------------------------------------------------------------------
// HARDWARE PIN DEFINITIONS
// --------------------------------------------------------------------------
#define I2C_SDA_PIN 7
#define I2C_SCL_PIN 8
#define I2C_CLOCK_SPEED 100000 

// Global Sensor Pointer
Adafruit_ADXL345_Unified *accel = NULL;

// --------------------------------------------------------------------------
// SERVER & ENROLLMENT CONFIGURATION
// --------------------------------------------------------------------------
#ifndef SERVER_HOST
  #define SERVER_HOST "192.168.1.50"
#endif
#ifndef SERVER_PORT
  #define SERVER_PORT 8000
#endif
#ifndef SERVER_PATH
  #define SERVER_PATH "/measurements/"
#endif
#ifndef SERVER_REGISTER_PATH
  #define SERVER_REGISTER_PATH "/devices/register"
#endif

// SECRET TOKEN FOR REGISTRATION (Must match backend)
#define ENROLLMENT_TOKEN "S3cret_Qu4k3_K3y" 

const char* SERVER_HOST_CONF     = SERVER_HOST;
const int   SERVER_PORT_CONF     = SERVER_PORT;
const char* SERVER_PATH_CONF     = SERVER_PATH;
const char* SERVER_REG_PATH_CONF = SERVER_REGISTER_PATH;

// GLOBAL DYNAMIC SENSOR ID (Default 0 = Unregistered)
int globalSensorID = 0;

// --------------------------------------------------------------------------
// RTOS HANDLES & STRUCTURES
// --------------------------------------------------------------------------
QueueHandle_t eventQueue;

struct SeismicEvent {
    float magnitude;            
    unsigned long event_millis; 
};

// DSP PARAMETERS
const float ALPHA_LTA     = 0.05f; 
const float ALPHA_STA     = 0.40f; 
const float TRIGGER_RATIO = 1.8f; 
const float NOISE_FLOOR   = 0.04f; 

// --------------------------------------------------------------------------
// CRYPTO SUBSYSTEM
// --------------------------------------------------------------------------
Preferences preferences;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_pk_context pk_context;

void initCrypto() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_context);

    const char *pers = "quake_guard_signer";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    preferences.begin("quake-keys", false);

    if (!preferences.isKey("priv_key")) {
        Serial.println("[SEC] Generating New ECDSA Key Pair...");
        mbedtls_pk_setup(&pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_context), mbedtls_ctr_drbg_random, &ctr_drbg);
        unsigned char priv_buf[128];
        int ret = mbedtls_pk_write_key_der(&pk_context, priv_buf, sizeof(priv_buf));
        preferences.putBytes("priv_key", priv_buf + sizeof(priv_buf) - ret, ret);
        Serial.println("[SEC] Keys Generated.");
    } else {
        Serial.println("[SEC] Loading Existing Keys...");
        size_t len = preferences.getBytesLength("priv_key");
        uint8_t buf[len];
        preferences.getBytes("priv_key", buf, len);
        mbedtls_pk_parse_key(&pk_context, buf, len, NULL, 0);
    }
}

/**
 * @brief Extracts the Public Key as a Hex String for JSON transmission.
 */
String getPublicKeyHex() {
    unsigned char pub_buf[128];
    int ret = mbedtls_pk_write_pubkey_der(&pk_context, pub_buf, sizeof(pub_buf));
    // mbedtls writes at the END of the buffer
    int len = ret;
    int start_index = sizeof(pub_buf) - len;

    String hexKey = "";
    for(int i = start_index; i < sizeof(pub_buf); i++) {
        char buf[3];
        sprintf(buf, "%02x", pub_buf[i]);
        hexKey += buf;
    }
    return hexKey;
}

String signMessage(String message) {
    unsigned char hash[32];
    unsigned char sig[MBEDTLS_ECDSA_MAX_LEN];
    size_t sig_len = 0;
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, (const unsigned char*)message.c_str(), message.length());
    mbedtls_md_finish(&ctx, hash);
    mbedtls_md_free(&ctx);
    mbedtls_pk_sign(&pk_context, MBEDTLS_MD_SHA256, hash, 0, sig, &sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    String hexSig = "";
    for(size_t i = 0; i < sig_len; i++) { char buf[3]; sprintf(buf, "%02x", sig[i]); hexSig += buf; }
    return hexSig;
}

// --------------------------------------------------------------------------
// PROVISIONING LOGIC (NEW)
// --------------------------------------------------------------------------
bool performProvisioning() {
    Serial.println("\n[PROV] Starting Device Handshake...");
    
    if(WiFi.status() != WL_CONNECTED) {
        Serial.println("[PROV] Error: No WiFi connection.");
        return false;
    }

    HTTPClient http;
    String url = String("http://") + SERVER_HOST_CONF + ":" + SERVER_PORT_CONF + SERVER_REG_PATH_CONF;
    
    Serial.printf("[PROV] Connecting to: %s\n", url.c_str());
    http.begin(url);
    http.addHeader("Content-Type", "application/json");

    // Construct Payload
    JsonDocument doc;
    doc["public_key_hex"] = getPublicKeyHex();
    doc["mac_address"] = WiFi.macAddress();
    doc["enrollment_token"] = ENROLLMENT_TOKEN;
    
    String requestBody;
    serializeJson(doc, requestBody);

    // Execute POST
    int httpResponseCode = http.POST(requestBody);

    if (httpResponseCode == 200 || httpResponseCode == 201) {
        String response = http.getString();
        JsonDocument resDoc;
        deserializeJson(resDoc, response);
        
        int newID = resDoc["sensor_id"];
        if (newID > 0) {
            // Save to NVS
            preferences.begin("quake-config", false);
            preferences.putInt("sensor_id", newID);
            preferences.end();
            
            globalSensorID = newID;
            Serial.printf("[PROV] SUCCESS! Assigned Sensor ID: %d\n", globalSensorID);
            http.end();
            return true;
        } else {
            Serial.println("[PROV] Error: Server returned invalid ID.");
        }
    } else {
        Serial.printf("[PROV] Registration Failed. HTTP Code: %d\n", httpResponseCode);
        Serial.println("[PROV] Server Response: " + http.getString());
    }
    
    http.end();
    return false;
}

// --------------------------------------------------------------------------
// TASK: SENSOR
// --------------------------------------------------------------------------
void sensorTask(void *pvParameters) {
    float lta = 0.0f, sta = 0.0f, prev_raw_mag = 9.81f, filtered_mag = 0.0f;
    sensors_event_t event;
    
    while (accel == NULL) vTaskDelay(pdMS_TO_TICKS(100));

    // Wait until we have a valid ID before monitoring? 
    // Technically we can monitor, but we can't send valid data without ID.
    // We proceed, but the Network Task will handle the ID check.

    Serial.println("[SENSOR] Task Active. Stabilizing...");
    for(int i=0; i<20; i++) { 
        if(accel->getEvent(&event)) { 
             float mag = sqrt(pow(event.acceleration.x, 2) + pow(event.acceleration.y, 2) + pow(event.acceleration.z, 2));
             lta = mag; sta = mag; prev_raw_mag = mag;
        }
        vTaskDelay(pdMS_TO_TICKS(50)); 
    }
    Serial.println("[SENSOR] Ready.");

    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xFrequency = pdMS_TO_TICKS(10); 
    bool inAlarm = false;
    unsigned long alarmStart = 0;

    for(;;) {
        vTaskDelayUntil(&xLastWakeTime, xFrequency);
        if (!accel->getEvent(&event)) continue; 

        float raw_mag = sqrt(pow(event.acceleration.x, 2) + pow(event.acceleration.y, 2) + pow(event.acceleration.z, 2));

        if (raw_mag < 2.0f) continue; // Dropout protection
        
        filtered_mag = 0.9f * (filtered_mag + raw_mag - prev_raw_mag);
        prev_raw_mag = raw_mag;
        float abs_signal = abs(filtered_mag);

        if (abs_signal < NOISE_FLOOR) abs_signal = 0.0f;

        lta = (ALPHA_LTA * abs_signal) + ((1.0f - ALPHA_LTA) * lta);
        sta = (ALPHA_STA * abs_signal) + ((1.0f - ALPHA_STA) * sta);
        
        if (lta < 0.05f) lta = 0.05f; 
        float ratio = sta / lta;

        if (ratio >= TRIGGER_RATIO && sta > NOISE_FLOOR && !inAlarm) {
            Serial.printf("[SENSOR] EARTHQUAKE! Ratio: %.2f (Mag: %.3f G)\n", ratio, sta);
            SeismicEvent evt; evt.magnitude = ratio; evt.event_millis = millis();
            xQueueSend(eventQueue, &evt, 0);
            inAlarm = true; alarmStart = millis();
        }
        if (inAlarm && (millis() - alarmStart > 5000)) inAlarm = false;
    }
}

// --------------------------------------------------------------------------
// TASK: NETWORK
// --------------------------------------------------------------------------
void networkTask(void *pvParameters) {
    WiFiClient client;
    client.setTimeout(2000); 

    // Wait for WiFi
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");

    SeismicEvent receivedEvt;
    for(;;) {
        if (xQueueReceive(eventQueue, &receivedEvt, portMAX_DELAY) == pdTRUE) {
            
            // Check if we have a valid ID. If not, we cannot report.
            if (globalSensorID == 0) {
                Serial.println("[NET] Warning: Seismic Event detected but Device is not Registered!");
                // Optionally try provisioning again here?
                continue;
            }

            if (WiFi.status() != WL_CONNECTED) { 
                Serial.println("[NET] Reconnecting WiFi...");
                WiFi.reconnect();
                vTaskDelay(pdMS_TO_TICKS(2000));
                if(WiFi.status() != WL_CONNECTED) continue; 
            }
            
            time_t now_unix; time(&now_unix);
            unsigned long age_ms = millis() - receivedEvt.event_millis;
            time_t evt_time = now_unix - (age_ms / 1000);
            
            int val = (int)(receivedEvt.magnitude * 100);
            String payload = String(val) + ":" + String(evt_time);
            String sig = signMessage(payload);

            JsonDocument doc;
            doc["value"] = val; 
            doc["misurator_id"] = globalSensorID; // USE DYNAMIC ID
            doc["device_timestamp"] = evt_time; 
            doc["signature_hex"] = sig;
            String json; serializeJson(doc, json);

            Serial.println("[NET] Sending Event...");
            if (client.connect(SERVER_HOST_CONF, SERVER_PORT_CONF)) {
                client.println(String("POST ") + SERVER_PATH_CONF + " HTTP/1.1");
                client.println(String("Host: ") + SERVER_HOST_CONF);
                client.println("Content-Type: application/json");
                client.print("Content-Length: "); client.println(json.length());
                client.println("Connection: close"); client.println();
                client.println(json);
                
                while(client.connected() || client.available()) { 
                    if(client.available()) client.readStringUntil('\n'); 
                }
                client.stop();
                Serial.println("[NET] Sent OK.");
            } else {
                Serial.println("[NET] Connection Failed.");
            }
        }
    }
}

// --------------------------------------------------------------------------
// SETUP
// --------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    while(!Serial) delay(10); 
    delay(2000); 

    Serial.println("\n\n[BOOT] QuakeGuard v3.2 PROV");
    
    // 1. CRYPTO INIT (Keys needed for provisioning)
    initCrypto();
    
    // 2. CHECK NVS FOR ID
    preferences.begin("quake-config", false); // Namespace for config
    globalSensorID = preferences.getInt("sensor_id", 0);
    preferences.end();

    if (globalSensorID > 0) {
        Serial.printf("[BOOT] Device Registered. ID: %d\n", globalSensorID);
    } else {
        Serial.println("[BOOT] Device UNREGISTERED. Entering Provisioning Mode...");
    }

    // 3. WIFIMANAGER (Connect to Network)
    WiFiManager wm;
    wm.setConfigPortalTimeout(180); 
    
    Serial.println("[NET] Initializing WiFiManager...");
    if (!wm.autoConnect("QuakeGuard-Setup")) {
        Serial.println("[NET] WiFi Failed. Offline Mode.");
    } else {
        Serial.println("[NET] WiFi Connected.");
        
        // 4. PROVISIONING (Only if not registered)
        if (globalSensorID == 0) {
            bool success = performProvisioning();
            if (!success) {
                Serial.println("[FATAL] Provisioning Failed. Retrying on next boot.");
                // We can choose to halt or continue monitoring locally.
                // Continuing allows diagnostics via Serial.
            }
        }
    }

    // 5. HARDWARE INIT
    Serial.printf("[HARDWARE] I2C Init: SDA=%d, SCL=%d @ %dHz\n", I2C_SDA_PIN, I2C_SCL_PIN, I2C_CLOCK_SPEED);
    
    pinMode(I2C_SDA_PIN, INPUT_PULLUP);
    pinMode(I2C_SCL_PIN, INPUT_PULLUP);
    digitalWrite(I2C_SDA_PIN, HIGH);
    digitalWrite(I2C_SCL_PIN, HIGH);
    delay(50);
    
    Wire.end(); 
    Wire.setPins(I2C_SDA_PIN, I2C_SCL_PIN);
    Wire.begin();
    Wire.setClock(I2C_CLOCK_SPEED); 
    delay(100); 

    Serial.println("[HARDWARE] Allocating Sensor...");
    if (accel != NULL) delete accel;
    accel = new Adafruit_ADXL345_Unified(12345);

    if(!accel->begin(0x53)) {
        if(!accel->begin(0x1D)) {
            Serial.println("[FATAL] Sensor Hardware Error.");
        }
    } else {
        accel->setDataRate(ADXL345_DATARATE_100_HZ);
        accel->setRange(ADXL345_RANGE_16_G);
        Serial.println("[SYS] Sensor OK.");
    }

    // 6. START TASKS
    eventQueue = xQueueCreate(20, sizeof(SeismicEvent));
    xTaskCreate(sensorTask, "SensorTask", 4096, NULL, 5, NULL);
    xTaskCreate(networkTask, "NetworkTask", 8192, NULL, 1, NULL);

    Serial.println("[SYS] System Running.");
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}