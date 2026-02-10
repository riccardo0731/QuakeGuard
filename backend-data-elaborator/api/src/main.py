"""
QuakeGuard Backend Service API (v2.0 - Security Hardened)
---------------------------------------------------------
Features:
- ECDSA SHA-256 Verification (DER/RAW)
- Replay Attack Protection (Timestamp Window)
- High Concurrency DB Pooling
"""

import json
import asyncio
import time
import hashlib
from datetime import datetime
from typing import List, Dict, Any

from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from sqlalchemy.exc import OperationalError
from redis import asyncio as aioredis

# --- CRYPTO IMPORTS ---
from ecdsa import VerifyingKey, NIST256p, BadSignatureError
from ecdsa.errors import MalformedPointError
from ecdsa.util import sigdecode_der, sigdecode_string 

from geoalchemy2.elements import WKTElement

from src.database import get_db, engine
import src.models as models
import src.schemas as schemas

# --- CONFIGURATION ---
MAX_TIMESTAMP_SKEW = 60  # Seconds. Rejects messages older than 1 min.

# 1. Wait for DB
def wait_for_db(retries=10, delay=3):
    print("Checking Database connection...")
    for i in range(retries):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            print("✅ Database is up and running!")
            return
        except OperationalError:
            print(f"⏳ Database not ready yet... waiting {delay}s ({i+1}/{retries})")
            time.sleep(delay)
    raise Exception("❌ Could not connect to Database.")

wait_for_db()
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="QuakeGuard Backend", version="2.0.0")
redis_client = aioredis.from_url("redis://redis:6379/0", decode_responses=True)

# --- UTILITY ---
def verify_device_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        if not public_key_hex or not signature_hex: return False
        key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        message_bytes = message.encode('utf-8')

        try:
            vk = VerifyingKey.from_der(key_bytes)
        except (ValueError, MalformedPointError):
            vk = VerifyingKey.from_string(key_bytes, curve=NIST256p)
        
        try:
            return vk.verify(sig_bytes, message_bytes, sigdecode=sigdecode_der, hashfunc=hashlib.sha256)
        except Exception:
            try:
                return vk.verify(sig_bytes, message_bytes, sigdecode=sigdecode_string, hashfunc=hashlib.sha256)
            except BadSignatureError:
                return False
    except Exception as e:
        print(f"⚠️ Crypto Error: {e}")
        return False

# --- ENDPOINTS ---

@app.post("/zones/", response_model=schemas.Zone, status_code=201)
def create_zone(zone: schemas.ZoneCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Zone).filter(models.Zone.city == zone.city).first()
    if existing: return existing 
    db_zone = models.Zone(city=zone.city)
    db.add(db_zone)
    db.commit()
    db.refresh(db_zone)
    return db_zone

@app.get("/zones/", response_model=List[schemas.Zone])
def get_zones(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Zone).offset(skip).limit(limit).all()

@app.post("/misurators/", response_model=schemas.Misurator, status_code=201)
def create_misurator(misurator: schemas.MisuratorCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Misurator).filter(models.Misurator.public_key_hex == misurator.public_key_hex).first()
    if existing: return existing

    zone = db.query(models.Zone).filter(models.Zone.id == misurator.zone_id).first()
    if not zone: raise HTTPException(404, "Zone not found")
    
    gps_point = f"POINT({misurator.longitude} {misurator.latitude})"
    db_misurator = models.Misurator(
        active=misurator.active, zone_id=misurator.zone_id,
        latitude=misurator.latitude, longitude=misurator.longitude,
        location=WKTElement(gps_point, srid=4326),
        public_key_hex=misurator.public_key_hex
    )
    db.add(db_misurator)
    db.commit()
    db.refresh(db_misurator)
    return db_misurator

@app.get("/misurators/", response_model=List[schemas.Misurator])
def get_misurators(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Misurator).offset(skip).limit(limit).all()

@app.post("/misurations/", status_code=202)
async def create_misuration_async(misuration: schemas.MisurationCreate, db: Session = Depends(get_db)):
    misurator = db.query(models.Misurator).filter(models.Misurator.id == misuration.misurator_id).first()
    if not misurator or not misurator.active:
        raise HTTPException(403, "Sensor unauthorized")

    # 1. Message Reconstruction
    message = f"{misuration.value}:{int(misuration.device_timestamp)}"
    
    # 2. Signature Verification (CPU Bound)
    loop = asyncio.get_event_loop()
    is_valid = await loop.run_in_executor(None, verify_device_signature, misurator.public_key_hex, message, misuration.signature_hex)

    if not is_valid:
        raise HTTPException(401, "Invalid digital signature")

    # 3. REPLAY ATTACK CHECK (The New Guard) 🛡️
    # We check time AFTER verifying signature (so we know timestamp is authentic)
    server_now = time.time()
    device_ts = misuration.device_timestamp
    if abs(server_now - device_ts) > MAX_TIMESTAMP_SKEW:
        print(f"⚠️ Replay Blocked! Skew: {server_now - device_ts:.2f}s")
        raise HTTPException(403, "Replay Attack Detected: Timestamp out of bounds")

    # 4. Enqueue
    payload = misuration.model_dump()
    payload['zone_id'] = misurator.zone_id 
    await redis_client.lpush("seismic_events", json.dumps(payload))
    
    return {"status": "accepted"}

@app.get("/zones/{zone_id}/alerts", response_model=List[schemas.AlertResponse])
def get_zone_alerts(zone_id: int, limit: int = 10, db: Session = Depends(get_db)):
    return db.query(models.Alert).filter(models.Alert.zone_id == zone_id).order_by(desc(models.Alert.timestamp)).limit(limit).all()

@app.get("/sensors/{misurator_id}/statistics")
def get_sensor_statistics(misurator_id: int, db: Session = Depends(get_db)):
    # This endpoint is CRITICAL for the End-to-End Stress Test verification
    sensor = db.query(models.Misurator).filter(models.Misurator.id == misurator_id).first()
    if not sensor: raise HTTPException(404, "Sensor not found")

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

@app.get("/health")
async def health_check(db: Session = Depends(get_db)):
    return {"status": "ok"}