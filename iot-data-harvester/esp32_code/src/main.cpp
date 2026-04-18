/**
 * Project: QuakeFinder - Distributed Seismic Detection System
 * Version: 3.0.0-REFACTORED (Local HTTP)
 * Target Hardware: ESP32-C3 + ADXL345
 *
 * Description:
 * Refactored firmware for high-performance DSP analysis and 
 * non-blocking HTTP dispatch using FreeRTOS.
 */

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_ADXL345_U.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <Preferences.h>
#include <time.h>

// --- Cryptographic Libraries (MbedTLS) ---
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

// --------------------------------------------------------------------------
// CONFIGURATION MACROS
// --------------------------------------------------------------------------
#ifndef WIFI_SSID
  #define WIFI_SSID "DEFAULT_DEV_SSID"
#endif

#ifndef WIFI_PASS
  #define WIFI_PASS "DEFAULT_DEV_PASS"
#endif

#ifndef SERVER_HOST
  #define SERVER_HOST "192.168.1.50"
#endif

#ifndef SERVER_PORT
  #define SERVER_PORT 8000
#endif

#ifndef SERVER_PATH
  #define SERVER_PATH "/misurations/"
#endif

#ifndef SENSOR_ID
  #define SENSOR_ID 101
#endif

// --------------------------------------------------------------------------
// HARDWARE & DSP DEFINITIONS
// --------------------------------------------------------------------------
constexpr int SDA_PIN = 8;
constexpr int SCL_PIN = 9;

constexpr float ALPHA_LTA = 0.05f;
constexpr float ALPHA_STA = 0.40f;
constexpr float TRIGGER_RATIO = 1.8f;
constexpr float HPF_ALPHA = 0.9f;

Adafruit_ADXL345_Unified accel = Adafruit_ADXL345_Unified(12345);

struct SeismicEvent {
    float magnitude;
    unsigned long event_millis;
};

QueueHandle_t eventQueue;

// --------------------------------------------------------------------------
// CRYPTOGRAPHY SUBSYSTEM
// --------------------------------------------------------------------------
Preferences preferences;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_pk_context pk_context;

void initCrypto() {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk_context);

    const char *pers = "quake_signer_dev";
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

    preferences.begin("quake-keys", false);

    if (!preferences.isKey("priv_key")) {
        Serial.println("[SEC] Generating new ECDSA Key Pair (NIST256p)...");

        mbedtls_pk_setup(&pk_context, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk_context), mbedtls_ctr_drbg_random, &ctr_drbg);

        unsigned char priv_buf[128];
        int key_len = mbedtls_pk_write_key_der(&pk_context, priv_buf, sizeof(priv_buf));

        preferences.putBytes("priv_key", priv_buf + sizeof(priv_buf) - key_len, key_len);
        Serial.println("[SEC] Keys generated and stored in NVS.");
    } else {
        Serial.println("[SEC] Loading keys from NVS...");
        size_t len = preferences.getBytesLength("priv_key");
        uint8_t buf[len];
        preferences.getBytes("priv_key", buf, len);
        mbedtls_pk_parse_key(&pk_context, buf, len, NULL, 0);
    }

    // Output Public Key
    unsigned char pub_buf[128];
    int pub_len = mbedtls_pk_write_pubkey_der(&pk_context, pub_buf, sizeof(pub_buf));

    Serial.print("[SEC] DEVICE PUBLIC KEY (HEX): ");
    for(int i = sizeof(pub_buf) - pub_len; i < sizeof(pub_buf); i++) {
        Serial.printf("%02x", pub_buf[i]);
    }
    Serial.println();
}

String signMessage(const String& message) {
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
    for(size_t i = 0; i < sig_len; i++) {
        char buf[3];
        sprintf(buf, "%02x", sig[i]);
        hexSig += buf;
    }
    return hexSig;
}

// --------------------------------------------------------------------------
// TASK 1: SENSOR ACQUISITION (Real-Time DSP)
// --------------------------------------------------------------------------
void sensorTask(void *pvParameters) {
    float lta = 0.0f, sta = 0.0f, prev_raw_mag = 9.81f, filtered_mag = 0.0f;
    sensors_event_t event;

    // Stabilization phase
    for(int i = 0; i < 20; i++) {
        accel.getEvent(&event);
        float mag = sqrt(pow(event.acceleration.x, 2) + pow(event.acceleration.y, 2) + pow(event.acceleration.z, 2));
        lta = sta = mag;
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    TickType_t xLastWakeTime = xTaskGetTickCount();
    const TickType_t xFrequency = pdMS_TO_TICKS(10); // 100Hz

    bool inAlarm = false;
    unsigned long alarmStart = 0;

    for(;;) {
        vTaskDelayUntil(&xLastWakeTime, xFrequency);

        accel.getEvent(&event);
        float raw_mag = sqrt(pow(event.acceleration.x, 2) + pow(event.acceleration.y, 2) + pow(event.acceleration.z, 2));

        // Digital High Pass Filter
        filtered_mag = HPF_ALPHA * (filtered_mag + raw_mag - prev_raw_mag);
        prev_raw_mag = raw_mag;
        float abs_signal = abs(filtered_mag);

        // STA/LTA Algorithm
        lta = (ALPHA_LTA * abs_signal) + ((1.0f - ALPHA_LTA) * lta);
        sta = (ALPHA_STA * abs_signal) + ((1.0f - ALPHA_STA) * sta);
        if (lta < 0.01f) lta = 0.01f; // Prevent division by zero

        float ratio = sta / lta;

        if (ratio >= TRIGGER_RATIO && !inAlarm) {
            Serial.printf("[SENSOR] Event Detected! Ratio: %.2f\n", ratio);

            SeismicEvent evt = { ratio, millis() };
            xQueueSend(eventQueue, &evt, 0);

            inAlarm = true;
            alarmStart = millis();
        }

        if (inAlarm && (millis() - alarmStart > 2000)) {
            inAlarm = false; // Reset alarm state after 2 seconds
        }
    }
}

// --------------------------------------------------------------------------
// TASK 2: NETWORK DISPATCH
// --------------------------------------------------------------------------
void networkTask(void *pvParameters) {
    WiFiClient client;

    Serial.printf("[NET] Connecting to WiFi: %s\n", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);

    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        Serial.print(".");
    }
    Serial.println("\n[NET] WiFi Connected");

    // NTP Time Sync
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");
    Serial.print("[NET] Syncing Time");
    while (time(NULL) < 100000) {
        Serial.print(".");
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    Serial.println(" OK");

    SeismicEvent receivedEvt;

    for(;;) {
        if (xQueueReceive(eventQueue, &receivedEvt, portMAX_DELAY) == pdTRUE) {
            
            if (WiFi.status() != WL_CONNECTED) {
                Serial.println("[NET] WiFi lost. Reconnecting...");
                WiFi.disconnect();
                WiFi.reconnect();
                vTaskDelay(pdMS_TO_TICKS(2000));
                continue;
            }

            time_t now_unix;
            time(&now_unix);
            unsigned long age_ms = millis() - receivedEvt.event_millis;
            time_t event_unix_timestamp = now_unix - (age_ms / 1000);

            int value_to_send = (int)(receivedEvt.magnitude * 100);
            String payloadData = String(value_to_send) + ":" + String(event_unix_timestamp);
            String signature = signMessage(payloadData);

            JsonDocument doc;
            doc["value"] = value_to_send;
            doc["misurator_id"] = SENSOR_ID;
            doc["device_timestamp"] = event_unix_timestamp;
            doc["signature_hex"] = signature;

            String jsonString;
            serializeJson(doc, jsonString);

            if (client.connect(SERVER_HOST, SERVER_PORT)) {
                client.println(String("POST ") + SERVER_PATH + " HTTP/1.1");
                client.println(String("Host: ") + SERVER_HOST);
                client.println("Content-Type: application/json");
                client.print("Content-Length: ");
                client.println(jsonString.length());
                client.println("Connection: close");
                client.println();
                client.println(jsonString);

                while (client.connected()) {
                    if (client.readStringUntil('\n') == "\r") break;
                }
                Serial.println("[NET] Server Response: " + client.readStringUntil('\n'));
                client.stop();
            } else {
                Serial.printf("[NET] Connection Failed to %s:%d\n", SERVER_HOST, SERVER_PORT);
            }
        }
    }
}

// --------------------------------------------------------------------------
// MAIN ENTRY POINTS
// --------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    delay(2000);

    Wire.begin(SDA_PIN, SCL_PIN);
    if(!accel.begin()) {
        Serial.println("[FATAL] ADXL345 init failed");
        while(1) { vTaskDelay(100); }
    }
    
    accel.setDataRate(ADXL345_DATARATE_100_HZ);
    accel.setRange(ADXL345_RANGE_16_G);
    initCrypto();

    eventQueue = xQueueCreate(20, sizeof(SeismicEvent));

    // Core 1 handles both by default on RISC-V C3, but priorities manage execution
    xTaskCreate(sensorTask, "SensorTask", 4096, NULL, 5, NULL);
    xTaskCreate(networkTask, "NetworkTask", 8192, NULL, 1, NULL);

    Serial.println("[SYS] System Started (Environment: REFACTORED DEV).");
}

void loop() {
    vTaskDelete(NULL); // Free up the loop task memory since FreeRTOS handles the rest
}