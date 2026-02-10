"""
QuakeGuard Backend Service API
-------------------------------
Core API Gateway.
Responsiblities:
1. IoT Data Ingestion (ECDSA Validation).
2. Data Retrieval (REST).
3. Real-Time Alert Distribution (Redis Pub/Sub -> WebSocket).
"""

import json
import asyncio
import time
import hashlib
from datetime import datetime
from typing import List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from sqlalchemy.exc import OperationalError
from redis import asyncio as aioredis

# --- CRYPTOGRAPHY ---
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from ecdsa.errors import MalformedPointError
from ecdsa.util import sigdecode_der, sigdecode_string 
from geoalchemy2.elements import WKTElement

# --- LOCAL MODULES ---
from src.database import get_db, engine
import src.models as models
import src.schemas as schemas

# ==========================================
# INFRASTRUCTURE INITIALIZATION
# ==========================================

def wait_for_db(retries=10, delay=3):
    """
    Blocks startup until the PostgreSQL database is ready.
    Crucial for container orchestration to prevent race conditions.
    """
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
    raise Exception("❌ DB Connection Failed after multiple retries.")

# 1. Initialize Database
wait_for_db()
models.Base.metadata.create_all(bind=engine)

# 2. Initialize FastAPI
app = FastAPI(title="QuakeGuard Backend", version="2.2.0")

# 3. Initialize Redis Client (Async)
redis_client = aioredis.from_url("redis://redis:6379/0", decode_responses=True)


# ==========================================
# REAL-TIME NOTIFICATION SYSTEM (PUBSUB)
# ==========================================

class ConnectionManager:
    """
    Manages active WebSocket connections for broadcasting alerts.
    """
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        """Accepts a new connection and adds it to the pool."""
        await websocket.accept()
        self.active_connections.append(websocket)
        # print(f"🔌 Client Connected. Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Removes a connection from the pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        """
        Pushes a message to all connected clients.
        Handles stale connections gracefully.
        """
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                # If sending fails, assume client disconnected abruptly
                pass

manager = ConnectionManager()

async def redis_alert_listener():
    """
    Background Task:
    Subscribes to the Redis 'quake_alerts' channel.
    When the Worker publishes a critical alert, this listener receives it
    and triggers a WebSocket broadcast.
    """
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("quake_alerts")
    print("🎧 Redis Pub/Sub Listener active on channel: 'quake_alerts'")

    async for message in pubsub.listen():
        if message["type"] == "message":
            alert_payload = message["data"]
            # print(f"⚡ Broadcasting Alert: {alert_payload}")
            await manager.broadcast(alert_payload)

@app.on_event("startup")
async def startup_event():
    """Starts the Redis Listener task when the API boots up."""
    asyncio.create_task(redis_alert_listener())

@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket Endpoint:
    Clients (Mobile Apps/Dashboards) connect here to receive real-time updates.
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive. 
            # We assume clients listen only, but we must await receive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ==========================================
# UTILITY: CRYPTO VERIFICATION
# ==========================================

def verify_device_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    """
    Verifies ECDSA signature (NIST256p + SHA256).
    Supports DER (MbedTLS) and RAW formats.
    """
    try:
        if not public_key_hex or not signature_hex: return False
        key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        message_bytes = message.encode('utf-8')

        # Attempt DER decoding (Standard)
        try:
            vk = VerifyingKey.from_der(key_bytes)
        except:
            # Fallback to RAW
            vk = VerifyingKey.from_string(key_bytes, curve=NIST256p)
        
        # Verify Signature
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
# REST API ENDPOINTS
# ==========================================

@app.post("/zones/", response_model=schemas.Zone, status_code=201, tags=["Registration"])
def create_zone(zone: schemas.ZoneCreate, db: Session = Depends(get_db)):
    """Registers a new zone."""
    existing = db.query(models.Zone).filter(models.Zone.city == zone.city).first()
    if existing: return existing 
    db_zone = models.Zone(city=zone.city)
    db.add(db_zone)
    db.commit()
    db.refresh(db_zone)
    return db_zone

@app.get("/zones/", response_model=List[schemas.Zone], tags=["Data Retrieval"])
def get_zones(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """Lists available zones."""
    return db.query(models.Zone).offset(skip).limit(limit).all()

@app.post("/misurators/", response_model=schemas.Misurator, status_code=201, tags=["Registration"])
def create_misurator(misurator: schemas.MisuratorCreate, db: Session = Depends(get_db)):
    """Registers an IoT Sensor with its Public Key."""
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
    """Lists registered sensors."""
    return db.query(models.Misurator).offset(skip).limit(limit).all()

@app.post("/misurations/", status_code=202, tags=["Ingestion"])
async def create_misuration_async(misuration: schemas.MisurationCreate, db: Session = Depends(get_db)):
    """
    High-Frequency Ingestion.
    Validates Signature + Replay Attack (60s window) -> Pushes to Redis Queue.
    """
    misurator = db.query(models.Misurator).filter(models.Misurator.id == misuration.misurator_id).first()
    if not misurator or not misurator.active: raise HTTPException(403, detail="Sensor unauthorized")

    # 1. Reconstruct Message
    message = f"{misuration.value}:{int(misuration.device_timestamp)}"
    
    # 2. Verify Signature (CPU-bound offload)
    loop = asyncio.get_event_loop()
    is_valid = await loop.run_in_executor(None, verify_device_signature, misurator.public_key_hex, message, misuration.signature_hex)

    if not is_valid: raise HTTPException(401, detail="Invalid digital signature")

    # 3. Check Replay Attack (Timestamp Validity)
    server_now = time.time()
    device_ts = misuration.device_timestamp
    if abs(server_now - device_ts) > 60:
         raise HTTPException(403, detail="Replay Attack Detected: Timestamp invalid")

    # 4. Enqueue for Worker
    payload = misuration.model_dump()
    payload['zone_id'] = misurator.zone_id 
    await redis_client.lpush("seismic_events", json.dumps(payload))
    
    return {"status": "accepted"}

@app.get("/zones/{zone_id}/alerts", response_model=List[schemas.AlertResponse], tags=["Data Retrieval"])
def get_zone_alerts(zone_id: int, limit: int = 10, db: Session = Depends(get_db)):
    """Fetches persistent alerts from DB."""
    return db.query(models.Alert).filter(models.Alert.zone_id == zone_id).order_by(desc(models.Alert.timestamp)).limit(limit).all()

@app.get("/sensors/{misurator_id}/statistics", tags=["Analytics"])
def get_sensor_statistics(misurator_id: int, db: Session = Depends(get_db)):
    """Calculates real-time sensor statistics."""
    sensor = db.query(models.Misurator).filter(models.Misurator.id == misurator_id).first()
    if not sensor: raise HTTPException(404, detail="Sensor not found")
    
    stats = db.query(
        func.count(models.Misuration.id).label("count"),
        func.avg(models.Misuration.value).label("average"),
        func.max(models.Misuration.value).label("max_value"),
        func.min(models.Misuration.value).label("min_value")
    ).filter(models.Misuration.misurator_id == misurator_id).first()
    
    return {
        "misurator_id": misurator_id,
        "total_readings": stats.count,
        "average_value": round(stats.average, 2) if stats.average else 0.0,
        "max_recorded": stats.max_value,
        "min_recorded": stats.min_value,
        "generated_at": datetime.utcnow().isoformat()
    }

@app.get("/health", tags=["System"])
async def health_check(db: Session = Depends(get_db)):
    """Liveness probe."""
    return {"status": "ok"}