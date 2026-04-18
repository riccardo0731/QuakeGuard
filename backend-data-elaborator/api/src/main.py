"""
QuakeGuard Backend Service API
-------------------------------
Core API Gateway.
Responsibilities:
1. IoT Data Ingestion (ECDSA Validation).
2. Data Retrieval (REST).
3. Real-Time Alert Distribution (Redis Pub/Sub -> WebSocket).
"""

import json
import asyncio
import time
import hashlib
import os
from datetime import datetime
from typing import List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
from sqlalchemy.exc import OperationalError
from redis import asyncio as aioredis

# --- CRYPTOGRAPHY ---
from ecdsa import VerifyingKey, NIST256p
from ecdsa.util import sigdecode_der, sigdecode_string
from geoalchemy2.elements import WKTElement

# --- LOCAL MODULES ---
from src.database import get_db, engine
import src.models as models
import src.schemas as schemas

# --- CONFIGURATION ---
MAX_TIMESTAMP_SKEW = 60
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

# ⚠️ SECURITY: Shared Secret for Device Provisioning (Must match Firmware)
ENROLLMENT_TOKEN = os.getenv("ENROLLMENT_TOKEN", "S3cret_Qu4k3_K3y")

# ⚠️ SECURITY: API Key for IoT Endpoints
IOT_API_KEY = os.getenv("IOT_API_KEY", "SuperSecretIoTKey2024")

# ==========================================
# INFRASTRUCTURE INITIALIZATION
# ==========================================

def wait_for_db(retries: int = 10, delay: int = 3) -> None:
    """Blocks startup until the PostgreSQL database is ready."""
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

# 2. Initialize Redis Client (Async)
redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)


# ==========================================
# REAL-TIME NOTIFICATION SYSTEM (PUBSUB)
# ==========================================

class ConnectionManager:
    """Manages active WebSocket connections for broadcasting alerts."""
    
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"📱 Client Connected. Active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"📱 Client Disconnected. Active: {len(self.active_connections)}")

    async def broadcast(self, message: str) -> None:
        """Pushes a message to all connected clients."""
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception as e:
                # FIXED [B110:try_except_pass]: We now log the exception and schedule cleanup
                print(f"⚠️ Failed to broadcast to a client: {e}")
                dead_connections.append(connection)
                
        # Clean up any connections that threw errors
        for dead in dead_connections:
            self.disconnect(dead)

manager = ConnectionManager()

async def redis_alert_listener() -> None:
    """Background Task: Subscribes to Redis 'quake_alerts' and broadcasts."""
    pubsub = redis_client.pubsub()
    await pubsub.subscribe("quake_alerts")
    print("🎧 Redis Pub/Sub Listener active on channel: 'quake_alerts'")

    async for message in pubsub.listen():
        if message["type"] == "message":
            alert_payload = message["data"]
            await manager.broadcast(alert_payload)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages the startup and shutdown lifecycle of the FastAPI app."""
    listener_task = asyncio.create_task(redis_alert_listener())
    yield
    listener_task.cancel()

# 3. Initialize FastAPI
app = FastAPI(title="QuakeGuard Backend", version="2.2.0", lifespan=lifespan)

# ==========================================
# SECURITY MIDDLEWARE & DEPENDENCIES
# ==========================================

class IoTAuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Exclude public endpoints, websockets, and health checks from Auth
        if request.url.path.startswith(("/docs", "/openapi", "/health", "/ws")):
            return await call_next(request)
            
        # Extract the key from headers
        api_key = request.headers.get("X-API-Key")
        
        if api_key != IOT_API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Invalid or missing X-API-Key header"}
            )
            
        return await call_next(request)

app.add_middleware(IoTAuthenticationMiddleware)

async def rate_limiter(request: Request):
    """
    Fixed-window rate limiter using Redis. 
    Restricts ingestion per IP to prevent Thundering Herd / DoS attacks.
    """
    client_ip = request.client.host
    current_second = int(time.time())
    
    # Create a unique Redis key for this IP for the current second
    key = f"rate_limit:{client_ip}:{current_second}"
    
    # Increment the request count
    request_count = await redis_client.incr(key)
    
    # Set expiration on the key the first time it is created
    if request_count == 1:
        await redis_client.expire(key, 5) 
        
    # Threshold: Allow max 50 requests per second per IP
    if request_count > 50:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Too many requests from this IP."
        )


@app.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):
    """Clients connect here to receive real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        manager.disconnect(websocket)

# ==========================================
# UTILITY: CRYPTO VERIFICATION
# ==========================================

def verify_device_signature(public_key_hex: str, message: str, signature_hex: str) -> bool:
    """
    Verifies ECDSA signature (NIST256p + SHA256).
    Supports DER (MbedTLS) and RAW formats.
    """
    if not public_key_hex or not signature_hex:
        return False
        
    try:
        key_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        message_bytes = message.encode('utf-8')

        try:
            vk = VerifyingKey.from_der(key_bytes)
        except Exception:
            vk = VerifyingKey.from_string(key_bytes, curve=NIST256p)
        
        try:
            return vk.verify(sig_bytes, message_bytes, sigdecode=sigdecode_der, hashfunc=hashlib.sha256)
        except Exception:
            try:
                return vk.verify(sig_bytes, message_bytes, sigdecode=sigdecode_string, hashfunc=hashlib.sha256)
            except Exception:
                return False
    except Exception:
        return False

# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.post("/zones/", response_model=schemas.Zone, status_code=status.HTTP_201_CREATED, tags=["Registration"])
def create_zone(zone: schemas.ZoneCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Zone).filter(models.Zone.city == zone.city).first()
    if existing:
        return existing 
        
    db_zone = models.Zone(city=zone.city)
    db.add(db_zone)
    db.commit()
    db.refresh(db_zone)
    return db_zone

@app.get("/zones/", response_model=List[schemas.Zone], tags=["Data Retrieval"])
def get_zones(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Zone).offset(skip).limit(limit).all()

@app.post("/misurators/", response_model=schemas.Misurator, status_code=status.HTTP_201_CREATED, tags=["Registration"])
def create_misurator(misurator: schemas.MisuratorCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Misurator).filter(models.Misurator.public_key_hex == misurator.public_key_hex).first()
    if existing:
        return existing

    zone = db.query(models.Zone).filter(models.Zone.id == misurator.zone_id).first()
    if not zone:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Zone not found")
    
    gps_point = f"POINT({misurator.longitude} {misurator.latitude})"
    db_misurator = models.Misurator(
        active=misurator.active, 
        zone_id=misurator.zone_id,
        latitude=misurator.latitude, 
        longitude=misurator.longitude,
        location=WKTElement(gps_point, srid=4326), 
        public_key_hex=misurator.public_key_hex
    )
    db.add(db_misurator)
    db.commit()
    db.refresh(db_misurator)
    return db_misurator

@app.get("/misurators/", response_model=List[schemas.Misurator], tags=["Data Retrieval"])
def get_misurators(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return db.query(models.Misurator).offset(skip).limit(limit).all()

@app.post("/misurations/", status_code=status.HTTP_202_ACCEPTED, tags=["Ingestion"], dependencies=[Depends(rate_limiter)])
async def create_misuration_async(misuration: schemas.MisurationCreate, db: Session = Depends(get_db)):
    misurator = db.query(models.Misurator).filter(models.Misurator.id == misuration.misurator_id).first()
    if not misurator or not misurator.active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Sensor unauthorized")

    # 1. Reconstruct Message
    message = f"{misuration.value}:{int(misuration.device_timestamp)}"
    
    # 2. Verify Signature
    loop = asyncio.get_running_loop()
    is_valid = await loop.run_in_executor(None, verify_device_signature, misurator.public_key_hex, message, misuration.signature_hex)

    if not is_valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid digital signature")

    # 3. Check Replay Attack
    if abs(time.time() - misuration.device_timestamp) > 60:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Replay Attack Detected: Timestamp invalid")

    # 4. Enqueue for Worker
    payload = misuration.model_dump()
    payload['zone_id'] = misurator.zone_id
    
    # Offload the rest to the Redis queue for async processing
    await redis_client.lpush("seismic_events", json.dumps(payload))
    return {"status": "accepted"}