"""
QuakeGuard Backend Service API (v2.6 - Provisioning Restored)
-------------------------------------------------------------
Core API Gateway.
Features:
1. Auto-Provisioning (Device Handshake).
2. IoT Data Ingestion (ECDSA Validation).
3. Real-Time Alert Distribution (Redis Pub/Sub -> WebSocket).
"""

import json
import asyncio
import time
import hashlib
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from contextlib import asynccontextmanager

# FastAPI & Pydantic
from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

# Database & Redis
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from sqlalchemy.exc import OperationalError
from redis import asyncio as aioredis

# Cryptography
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from ecdsa.errors import MalformedPointError
from ecdsa.util import sigdecode_der, sigdecode_string 
from geoalchemy2.elements import WKTElement

# Local Modules
from src.database import get_db, engine
import src.models as models
import src.schemas as schemas

# --- CONFIGURATION ---
MAX_TIMESTAMP_SKEW = 60
REDIS_URL = "redis://redis:6379/0"

# ⚠️ SECURITY: Shared Secret for Device Provisioning (Must match Firmware)
ENROLLMENT_TOKEN = os.getenv("ENROLLMENT_TOKEN", "S3cret_Qu4k3_K3y")

# ==========================================
# WEBSOCKET CONNECTION MANAGER
# ==========================================

class ConnectionManager:
    """Manages active WebSocket connections for broadcasting alerts."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        # print(f"📱 Client Connected. Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

ws_manager = ConnectionManager()

# ==========================================
# BACKGROUND SERVICES
# ==========================================

async def redis_listener():
    """Listens to Redis 'quake_alerts' channel and broadcasts via WebSocket."""
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = redis.pubsub()
    await pubsub.subscribe("quake_alerts")
    print("🎧 Backend listening on Redis Pub/Sub: 'quake_alerts'")
    
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                # print(f"🔥 RELAYING ALERT: {message['data']}")
                await ws_manager.broadcast(message['data'])
    except Exception as e:
        print(f"❌ Redis Listener Error: {e}")
    finally:
        await redis.close()

# ==========================================
# LIFESPAN & INIT
# ==========================================

def wait_for_db(retries=10, delay=3):
    print("Checking Database connection...")
    for i in range(retries):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            print("✅ Database is up and running!")
            return
        except OperationalError:
            print(f"⏳ Waiting for DB... ({i+1}/{retries})")
            time.sleep(delay)
    raise Exception("❌ DB Connection Failed.")

@asynccontextmanager
async def lifespan(app: FastAPI):
    wait_for_db()
    models.Base.metadata.create_all(bind=engine)
    redis_task = asyncio.create_task(redis_listener())
    yield
    redis_task.cancel()

app = FastAPI(title="QuakeGuard Backend", version="2.6.0", lifespan=lifespan)
redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)

# ==========================================
# CRYPTO UTILS
# ==========================================

def verify_device_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        if not public_key_hex or not signature_hex: return False
        key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        message_bytes = message.encode('utf-8')
        try:
            vk = VerifyingKey.from_der(key_bytes)
        except:
            vk = VerifyingKey.from_string(key_bytes, curve=NIST256p)
        try:
            return vk.verify(sig_bytes, message_bytes, sigdecode=sigdecode_der, hashfunc=hashlib.sha256)
        except:
            try:
                return vk.verify(sig_bytes, message_bytes, sigdecode=sigdecode_string, hashfunc=hashlib.sha256)
            except:
                return False
    except:
        return False

# ==========================================
# 🚨 PROVISIONING ENDPOINT (RESTORED) 🚨
# ==========================================

# Internal Schema for Provisioning Request
class DeviceRegistrationRequest(BaseModel):
    public_key_hex: str
    mac_address: str
    enrollment_token: str
    firmware_version: Optional[str] = "1.0.0"

@app.post("/devices/register", status_code=201, tags=["Registration"])
def register_device(payload: DeviceRegistrationRequest, db: Session = Depends(get_db)):
    """
    Auto-Provisioning Endpoint.
    Allows new sensors to register themselves securely using a shared secret.
    """
    # 1. SECURITY CHECK
    if payload.enrollment_token != ENROLLMENT_TOKEN:
        print(f"⛔ Unauthorized registration attempt from {payload.mac_address}")
        # Artificial delay to slow down brute-force attacks
        time.sleep(1)
        raise HTTPException(status_code=403, detail="Invalid Enrollment Token")

    # 2. IDEMPOTENCY CHECK (Check by Public Key OR Mac Address)
    existing_sensor = db.query(models.Misurator).filter(
        (models.Misurator.public_key_hex == payload.public_key_hex) |
        (models.Misurator.mac_address == payload.mac_address)
    ).first()

    if existing_sensor:
        # Update metadata if changed (e.g. firmware update)
        if existing_sensor.firmware_version != payload.firmware_version:
            existing_sensor.firmware_version = payload.firmware_version
            db.commit()

        return {
            "sensor_id": existing_sensor.id,
            "status": "existing",
            "message": "Device already registered",
            "zone_id": existing_sensor.zone_id
        }

    # 3. NEW DEVICE REGISTRATION
    # Ensure a default zone exists
    default_zone = db.query(models.Zone).first()
    if not default_zone:
        default_zone = models.Zone(city="Default Staging Zone")
        db.add(default_zone)
        db.commit()
        db.refresh(default_zone)
    
    # Create new sensor record
    # Note: We initialize lat/lon to 0.0. These should be updated via GPS later.
    gps_point = "POINT(0 0)"
    
    new_sensor = models.Misurator(
        active=True,
        zone_id=default_zone.id,
        latitude=0.0,
        longitude=0.0,
        location=WKTElement(gps_point, srid=4326),
        public_key_hex=payload.public_key_hex,
        # IMPORTANT: Persist hardware identifiers
        mac_address=payload.mac_address,
        firmware_version=payload.firmware_version
    )
    
    try:
        db.add(new_sensor)
        db.commit()
        db.refresh(new_sensor)
        print(f"🎉 New Device Enrolled: ID {new_sensor.id} (MAC: {payload.mac_address})")
        
        return {
            "sensor_id": new_sensor.id,
            "status": "created",
            "message": "Device successfully enrolled",
            "zone_id": default_zone.id
        }
    except Exception as e:
        db.rollback()
        print(f"❌ DB Error during registration: {e}")
        raise HTTPException(status_code=500, detail="Registration failed")


# ==========================================
# STANDARD API ENDPOINTS
# ==========================================

@app.post("/zones/", response_model=schemas.Zone, status_code=201, tags=["Registration"])
def create_zone(zone: schemas.ZoneCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Zone).filter(models.Zone.city == zone.city).first()
    if existing: return existing 
    db_zone = models.Zone(city=zone.city)
    db.add(db_zone)
    db.commit()
    db.refresh(db_zone)
    return db_zone

@app.get("/zones/", response_model=List[schemas.Zone], tags=["Data Retrieval"])
def get_zones(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Zone).offset(skip).limit(limit).all()

@app.post("/misurators/", response_model=schemas.Misurator, status_code=201, tags=["Registration"])
def create_misurator(misurator: schemas.MisuratorCreate, db: Session = Depends(get_db)):
    """Manual registration (Admin panel)"""
    existing = db.query(models.Misurator).filter(models.Misurator.public_key_hex == misurator.public_key_hex).first()
    if existing: return existing
    zone = db.query(models.Zone).filter(models.Zone.id == misurator.zone_id).first()
    if not zone: raise HTTPException(404, detail="Zone not found")
    
    gps_point = f"POINT({misurator.longitude} {misurator.latitude})"
    db_misurator = models.Misurator(
        active=misurator.active, zone_id=misurator.zone_id,
        latitude=misurator.latitude, longitude=misurator.longitude,
        location=WKTElement(gps_point, srid=4326), public_key_hex=misurator.public_key_hex
    )
    db.add(db_misurator)
    db.commit()
    db.refresh(db_misurator)
    return db_misurator

@app.get("/misurators/", response_model=List[schemas.Misurator], tags=["Data Retrieval"])
def get_misurators(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Misurator).offset(skip).limit(limit).all()

@app.post("/misurations/", status_code=202, tags=["Ingestion"])
async def create_misuration_async(misuration: schemas.MisurationCreate, db: Session = Depends(get_db)):
    misurator = db.query(models.Misurator).filter(models.Misurator.id == misuration.misurator_id).first()
    if not misurator or not misurator.active: raise HTTPException(403, detail="Sensor unauthorized")

    # 1. Signature
    message = f"{misuration.value}:{int(misuration.device_timestamp)}"
    loop = asyncio.get_event_loop()
    is_valid = await loop.run_in_executor(None, verify_device_signature, misurator.public_key_hex, message, misuration.signature_hex)
    if not is_valid: raise HTTPException(401, detail="Invalid digital signature")
    
    # 2. Replay
    if abs(time.time() - misuration.device_timestamp) > MAX_TIMESTAMP_SKEW:
        raise HTTPException(403, detail="Replay Attack Detected")

    # 3. Queue
    payload = misuration.model_dump()
    payload['zone_id'] = misurator.zone_id 
    await redis_client.lpush("seismic_events", json.dumps(payload))
    return {"status": "accepted"}

@app.get("/zones/{zone_id}/alerts", response_model=List[schemas.AlertResponse], tags=["Data Retrieval"])
def get_zone_alerts(zone_id: int, limit: int = 10, db: Session = Depends(get_db)):
    return db.query(models.Alert).filter(models.Alert.zone_id == zone_id).order_by(desc(models.Alert.timestamp)).limit(limit).all()

@app.get("/sensors/{misurator_id}/statistics", tags=["Analytics"])
def get_sensor_statistics(misurator_id: int, db: Session = Depends(get_db)):
    sensor = db.query(models.Misurator).filter(models.Misurator.id == misurator_id).first()
    if not sensor: raise HTTPException(404, detail="Sensor not found")
    stats = db.query(
        func.count(models.Misuration.id).label("count"),
        func.avg(models.Misuration.value).label("average"),
        func.max(models.Misuration.value).label("max_value"),
        func.min(models.Misuration.value).label("min_value")
    ).filter(models.Misuration.misurator_id == misurator_id).first()
    return {
        "misurator_id": misurator_id, "total_readings": stats.count,
        "average_value": round(stats.average, 2) if stats.average else 0.0,
        "max_recorded": stats.max_value, "min_recorded": stats.min_value,
        "generated_at": datetime.utcnow().isoformat()
    }

@app.get("/health", tags=["System"])
async def health_check(db: Session = Depends(get_db)):
    return {"status": "ok"}

# ==========================================
# WS ENDPOINTS
# ==========================================

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

@app.post("/simulate-alert", tags=["Testing"])
async def simulate_alert(zone_id: int, magnitude: float):
    alert = {
        "type": "CRITICAL_TEST", "zone_id": zone_id,
        "magnitude": magnitude, "message": "⚠️ SIMULATION TEST",
        "timestamp": datetime.utcnow().isoformat()
    }
    redis = aioredis.from_url(REDIS_URL, decode_responses=True)
    await redis.publish("quake_alerts", json.dumps(alert))
    await redis.close()
    return {"status": "Simulated Alert Broadcasted"}