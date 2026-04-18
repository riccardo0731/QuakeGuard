<div align="center">

# 🌋 QuakeGuard 
### Electro-Domestic Seismic Alarm System

**Full-Stack IoT Architecture for Real-Time Earthquake Detection**

![C++](https://img.shields.io/badge/C++-Hardware_Logic-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Python](https://img.shields.io/badge/Python-FastAPI-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![React Native](https://img.shields.io/badge/React_Native-Mobile-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-PostGIS-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Message_Broker-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Containerization-2496ED?style=for-the-badge&logo=docker&logoColor=white)

</div>

---

## 📖 Overview
**QuakeGuard** is an advanced Full-Stack IoT architecture designed for the real-time detection, analysis, and reporting of seismic events. 

The system utilizes intelligent edge sensors (ESP32) that analyze vibrations locally and transmit cryptographically secured data to an asynchronous hybrid Cloud. The backend is specifically engineered to handle the massive traffic spikes (**Thundering Herd** effect) typical during widespread earthquake events, ensuring reliable alarm delivery without bottlenecking.

---

## 🏗 System Architecture


The project is highly modular, following **Microservices** and **Event-Driven Design** principles across three main layers:

### 1. 📡 IoT Edge (Data Harvester)
* **Hardware:** ESP32-C3 SuperMini paired with an ADXL345 Accelerometer.
* **Edge Computing:** 100Hz sampling rate, applying Digital High-Pass Filters (HPF) and the **STA/LTA** (Short Term/Long Term Average) seismic algorithm directly on the device.
* **Security:** Hardware-level digital signing of payloads using **ECDSA (NIST256p)**.
* **Resilience:** Temporal timestamp reconstruction to mitigate network latency and out-of-order packet deliveries.

### 2. ☁️ Backend (Data Elaborator)
* **Core API:** Built with **FastAPI** (Python) for high-performance asynchronous routing.
* **Event Pattern:** Producer-Consumer architecture leveraging **Redis** as a Message Broker to decouple ingestion from processing.
* **Persistence:** **PostgreSQL + PostGIS** for robust geospatial data management.
* **Background Workers:** Dedicated processes for queue consumption, event validation, and alarm aggregation.
* **Performance:** Fully asynchronous management capable of handling >500 Req/s on standard commercial hardware.

### 3. 📱 Frontend (Mobile Monitor)
* **Framework:** **React Native** (Expo) for cross-platform compatibility.
* **Features:** Interactive dashboard with real-time visual and haptic alarms via Adaptive Polling, alongside a live sensor network map.

---

## 🔐 Security & Cryptography

Data integrity is paramount in emergency systems. Every telemetry packet transmitted by the edge sensors is cryptographically signed.

```json
{ 
  "value": 250, 
  "timestamp": 17000000, 
  "signature": "a1b2c3d4e5f6..." 
}
```

The backend rigorously verifies the signature (**SHA256 + ECDSA**) against the sensor's registered public key before accepting the payload. This architecture strictly prevents **Man-in-the-Middle** (MitM) and **Spoofing** attacks, ensuring that alarms cannot be falsely triggered by malicious actors.

---

## 🚀 Quick Start (Local Deployment)

### Prerequisites
* Docker & Docker Compose
* PlatformIO (VS Code Extension)
* Node.js & Expo Go (Mobile App)

### 1. Launch the Cloud Backend
Deploy the API, Database, and Message Broker via Docker:
```bash
cd "Backend - Data Elaborator"
docker-compose up --build -d
```
*The backend will be live at `http://localhost:8000`. API documentation is auto-generated at `http://localhost:8000/docs`.*

### 2. Configure and Flash the IoT Edge Device
1. Modify `IoT - Data Harvester/esp32_config.env` with your local IP and WiFi credentials.
2. Upload the firmware to the ESP32 via PlatformIO.
3. **⚠️ IMPORTANT:** On the first boot, copy the generated `PUBLIC KEY` from the serial monitor and register the device via the Swagger UI (`http://localhost:8000/docs`).

### 3. Launch the Mobile Dashboard
```bash
cd "Frontend - Mobile App"
npm install
npx expo start
```
*Scan the generated QR code with your smartphone (ensure your phone is on the same WiFi network as your backend).*

---

<div align="center">

**Developed by [GiZano](https://giovanni-zanotti.is-a.dev)**
<br>
*Version 3.0.0 (Stable) | MIT License*

</div>
