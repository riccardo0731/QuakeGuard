/**
 * Project: QuakeGuard - Professional Seismic Node
 * Version: 3.1.0-PRO
 * Target Hardware: ESP32-C3 SuperMini + ADXL345
 * Author: GiZano
 *
 * CHANGELOG v3.1.0:
 * - CRITICAL: I2C Clock increased to 100kHz (Standard Mode) for timing compliance.
 * - FEATURE: Integrated WiFiManager (No more hardcoded credentials).
 * - STABILITY: Added 2000ms timeout to HTTP Client to prevent task blocking.
 * - SYSTEM: Config Portal timeout set to 180s to allow offline sensor operation.
 */

#include <Arduino.h>
#include <Wire.h>
#include <Adafruit_Sensor.h>
#include <Adafruit_ADXL345_U.h>
#include <WiFi.h>
#include <WiFiManager.h> // Requires "tzapu/WiFiManager" library
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

// I2C Frequency: 100kHz (Standard Mode)
// 10kHz was insufficient for 100Hz sampling rate loop times.
#define I2C_CLOCK_SPEED 100000 

// Global Sensor Pointer
// Dynamic allocation is strictly required here to delay constructor execution
// until AFTER Wire.setPins(7,8) is called.
Adafruit_ADXL345_Unified *accel = NULL;

// --------------------------------------------------------------------------
// SERVER CONFIGURATION
// --------------------------------------------------------------------------
// WiFi Credentials are now handled by WiFiManager and stored in NVS.

#ifndef SERVER_HOST
  #define SERVER_HOST "192.168.1.50"
#endif
#ifndef SERVER_PORT
  #define SERVER_PORT 8000
#endif
#ifndef SERVER_PATH
  #define SERVER_PATH "/measurements/"
#endif
#ifndef SENSOR_ID
  #define SENSOR_ID 101
#endif

const char* SERVER_HOST_CONF   = SERVER_HOST;
const int   SERVER_PORT_CONF   = SERVER_PORT;
const char* SERVER_PATH_CONF   = SERVER_PATH;
const int   SENSOR_ID_CONF     = SENSOR_ID;

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

    // Export Public Key
    unsigned char pub_buf[128];
    int ret_pub = mbedtls_pk_write_pubkey_der(&pk_context, pub_buf, sizeof(pub_buf));
    int pub_len = ret_pub;

    Serial.print("[SEC] DEVICE PUBLIC KEY (HEX): ");
    for(int i = sizeof(pub_buf) - pub_len; i < sizeof(pub_buf); i++) {
        Serial.printf("%02x", pub_buf[i]);
    }
    Serial.println();
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
// TASK: SENSOR (OPTIMIZED)
// --------------------------------------------------------------------------
void sensorTask(void *pvParameters) {
    float lta = 0.0f, sta = 0.0f, prev_raw_mag = 9.81f, filtered_mag = 0.0f;
    sensors_event_t event;
    
    while (accel == NULL) vTaskDelay(pdMS_TO_TICKS(100));

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

        // Dropout Protection (< 0.2G)
        if (raw_mag < 2.0f) continue; 
        
        filtered_mag = 0.9f * (filtered_mag + raw_mag - prev_raw_mag);
        prev_raw_mag = raw_mag;
        float abs_signal = abs(filtered_mag);

        // Noise Gate
        if (abs_signal < NOISE_FLOOR) abs_signal = 0.0f;

        // STA/LTA
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
// TASK: NETWORK (WITH WATCHDOG & TIMEOUT)
// --------------------------------------------------------------------------
void networkTask(void *pvParameters) {
    WiFiClient client;
    
    // Explicit Timeout to prevent hanging on unresponsive servers
    client.setTimeout(2000); 

    // Wait for WiFiManager to handle initial connection in setup
    // or connecting via saved credentials
    while (WiFi.status() != WL_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    
    configTime(0, 0, "pool.ntp.org", "time.nist.gov");

    SeismicEvent receivedEvt;
    for(;;) {
        if (xQueueReceive(eventQueue, &receivedEvt, portMAX_DELAY) == pdTRUE) {
            
            // Connection Watchdog
            if (WiFi.status() != WL_CONNECTED) { 
                Serial.println("[NET] WiFi Lost. Attempting Reconnect...");
                WiFi.reconnect();
                // Give it some time to reconnect
                int retry = 0;
                while(WiFi.status() != WL_CONNECTED && retry < 5) {
                    vTaskDelay(pdMS_TO_TICKS(1000));
                    retry++;
                }
                if(WiFi.status() != WL_CONNECTED) continue; // Skip this event if no net
            }
            
            time_t now_unix; time(&now_unix);
            unsigned long age_ms = millis() - receivedEvt.event_millis;
            time_t evt_time = now_unix - (age_ms / 1000);
            
            int val = (int)(receivedEvt.magnitude * 100);
            String payload = String(val) + ":" + String(evt_time);
            String sig = signMessage(payload);

            JsonDocument doc;
            doc["value"] = val; 
            doc["misurator_id"] = SENSOR_ID_CONF;
            doc["device_timestamp"] = evt_time; 
            doc["signature_hex"] = sig;
            String json; serializeJson(doc, json);

            Serial.println("[NET] Sending...");
            if (client.connect(SERVER_HOST_CONF, SERVER_PORT_CONF)) {
                client.println(String("POST ") + SERVER_PATH_CONF + " HTTP/1.1");
                client.println(String("Host: ") + SERVER_HOST_CONF);
                client.println("Content-Type: application/json");
                client.print("Content-Length: "); client.println(json.length());
                client.println("Connection: close"); 
                client.println();
                client.println(json);
                
                // Read response with timeout protection
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
// SETUP (WIFIMANAGER + HARDWARE INIT)
// --------------------------------------------------------------------------
void setup() {
    Serial.begin(115200);
    while(!Serial) delay(10); 
    delay(2000); 

    Serial.println("\n\n[BOOT] QuakeGuard v3.1 PRO");
    
    // 1. CRYPTO INIT
    initCrypto();
    
    Serial.println("\n--- 10 SECONDS TO COPY PUBLIC KEY ---");
    for(int i=10; i>0; i--) { Serial.printf(" %d...", i); delay(1000); }
    Serial.println("\n");

    // 2. WIFIMANAGER (BLOCKING PORTAL)
    // Create Config Portal "QuakeGuard-Setup". 
    // If no saved creds, user must connect to this AP and configure WiFi.
    WiFiManager wm;
    wm.setConfigPortalTimeout(180); // 3 minutes timeout, then boot anyway (offline mode)
    
    Serial.println("[NET] Initializing WiFiManager...");
    if (!wm.autoConnect("QuakeGuard-Setup")) {
        Serial.println("[NET] Failed to connect or timeout. Booting in Offline Mode.");
    } else {
        Serial.println("[NET] WiFi Connected via WiFiManager.");
    }

    // 3. HARDWARE INIT
    Serial.printf("[HARDWARE] I2C Init: SDA=%d, SCL=%d @ %dHz\n", I2C_SDA_PIN, I2C_SCL_PIN, I2C_CLOCK_SPEED);
    
    // Bus Recovery
    pinMode(I2C_SDA_PIN, INPUT_PULLUP);
    pinMode(I2C_SCL_PIN, INPUT_PULLUP);
    digitalWrite(I2C_SDA_PIN, HIGH);
    digitalWrite(I2C_SCL_PIN, HIGH);
    delay(50);
    
    Wire.end(); 
    Wire.setPins(I2C_SDA_PIN, I2C_SCL_PIN);
    Wire.begin();
    Wire.setClock(I2C_CLOCK_SPEED); // 100kHz Standard Mode
    delay(100); 

    Serial.println("[HARDWARE] Allocating Sensor...");
    if (accel != NULL) delete accel;
    accel = new Adafruit_ADXL345_Unified(12345);

    if(!accel->begin(0x53)) {
        Serial.println("[WARN] Try 0x1D...");
        if(!accel->begin(0x1D)) {
            Serial.println("[FATAL] Sensor Hardware Error.");
        }
    } else {
        accel->setDataRate(ADXL345_DATARATE_100_HZ);
        accel->setRange(ADXL345_RANGE_16_G);
        Serial.println("[SYS] Sensor OK.");
    }

    // 4. RTOS
    eventQueue = xQueueCreate(20, sizeof(SeismicEvent));
    xTaskCreate(sensorTask, "SensorTask", 4096, NULL, 5, NULL);
    xTaskCreate(networkTask, "NetworkTask", 8192, NULL, 1, NULL);

    Serial.println("[SYS] System Running.");
}

void loop() {
    vTaskDelay(pdMS_TO_TICKS(1000));
}