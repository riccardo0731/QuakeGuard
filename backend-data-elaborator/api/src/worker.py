"""
QuakeGuard Background Worker
-----------------------------
Consumes seismic events from the Redis queue, persists data to PostgreSQL,
and detects critical seismic thresholds to generate persistent Alerts.
"""

import json
import redis
import time
from datetime import datetime
from typing import Dict, Any

from src.database import SessionLocal
from src.models import Misuration, Alert

# --- CONFIGURATION ---
REDIS_HOST = 'redis'
REDIS_PORT = 6379
ALERT_THRESHOLD = 50       
ALERT_WINDOW_SECONDS = 10  
ALERT_COOLDOWN = 60        

redis_sync = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

def process_event(event: Dict[str, Any]) -> None:
    """Processes a single seismic event from the queue."""
    zone_id = event['zone_id']
    
    with SessionLocal() as db:
        # 1. Persist raw measurement
        new_misuration = Misuration(
            value=event['value'],
            misurator_id=event['misurator_id']
        )
        db.add(new_misuration)
        
        # 2. Update real-time alert counter
        zone_counter_key = f"zone:{zone_id}:alerts"
        pipe = redis_sync.pipeline()
        pipe.incr(zone_counter_key)
        pipe.expire(zone_counter_key, ALERT_WINDOW_SECONDS) 
        current_count = pipe.execute()[0]

        # 3. Check Threshold & Generate Alert
        if current_count >= ALERT_THRESHOLD:
            cooldown_key = f"zone:{zone_id}:alarm_cooldown"
            
            if not redis_sync.exists(cooldown_key):
                print(f"🚨 CRITICAL ALARM! Zone {zone_id} has {current_count} events!")
                
                new_alert = Alert(
                    zone_id=zone_id,
                    severity=float(current_count) / 10.0, 
                    message=f"Seismic Swarm Detected: {current_count} sensors triggered.",
                    timestamp=datetime.utcnow()
                )
                db.add(new_alert)
                redis_sync.setex(cooldown_key, ALERT_COOLDOWN, "active")
        
        db.commit()

def run_worker() -> None:
    """Continuous loop consuming messages."""
    print(f"👷 Worker started. Threshold: {ALERT_THRESHOLD} events / {ALERT_WINDOW_SECONDS}s")
    
    while True:
        try:
            _, data = redis_sync.brpop("seismic_events")
            event = json.loads(data)
            process_event(event)
        except Exception as e:
            print(f"❌ Error processing event: {e}")
            time.sleep(1)

if __name__ == "__main__":
    time.sleep(5)  # Warm-up delay to let Postgres initialize
    run_worker()