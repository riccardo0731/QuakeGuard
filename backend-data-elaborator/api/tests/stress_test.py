"""
QuakeGuard Critical Stress Test Suite (v2.1 - The Real Deal)
------------------------------------------------------------
Features:
- Client-side Semaphore Throttling
- Smart Polling for End-to-End DB Verification
- Active Security Attacks (Invalid Sig + Replay)
- Dynamic Infrastructure
"""

import asyncio
import aiohttp
import time
import random
import os
import uuid
import hashlib
from typing import List, Tuple
from dataclasses import dataclass

from ecdsa import SigningKey, NIST256p
from ecdsa.util import sigencode_der

# --- CONFIGURATION ---
API_URL = os.getenv("API_URL", "http://localhost:8000")
NUM_SENSORS = int(os.getenv("NUM_SENSORS", 200)) 
CONCURRENCY_LIMIT = int(os.getenv("CONCURRENCY_LIMIT", 50)) 
TIMEOUT_SECONDS = 30
POLLING_RETRIES = 10 # Max seconds to wait for worker persistence

@dataclass
class TestStats:
    req_sent: int = 0
    req_success: int = 0
    req_failed: int = 0
    auth_rejected: int = 0
    replay_rejected: int = 0
    latency_accum: float = 0.0

class VirtualSensor:
    def __init__(self):
        self.sk = SigningKey.generate(curve=NIST256p)
        self.vk = self.sk.verifying_key
        self.public_key_hex = self.vk.to_der().hex()
        self.sensor_id: int = 0
        self.lat = round(random.uniform(-90, 90), 6)
        self.lon = round(random.uniform(-180, 180), 6)
        self.sent_count = 0 

    def sign_message(self, message: str) -> str:
        return self.sk.sign(message.encode('utf-8'), hashfunc=hashlib.sha256, sigencode=sigencode_der).hex()

class MaliciousSensor(VirtualSensor):
    def sign_with_wrong_key(self, message: str) -> str:
        fake_sk = SigningKey.generate(curve=NIST256p)
        return fake_sk.sign(message.encode('utf-8'), hashfunc=hashlib.sha256, sigencode=sigencode_der).hex()

# --- UTILS ---

async def create_dynamic_zone(session: aiohttp.ClientSession) -> int:
    city_name = f"TestZone_{uuid.uuid4().hex[:8]}"
    async with session.post(f"{API_URL}/zones/", json={"city": city_name}) as resp:
        if resp.status not in [200, 201]: raise Exception(f"Zone creation failed: {resp.status}")
        data = await resp.json()
        return data['id']

async def register_sensor(session, sensor, zone_id, sem):
    async with sem:
        payload = { "active": True, "zone_id": zone_id, "latitude": sensor.lat, "longitude": sensor.lon, "public_key_hex": sensor.public_key_hex }
        try:
            async with session.post(f"{API_URL}/misurators/", json=payload) as resp:
                if resp.status in [200, 201]:
                    data = await resp.json()
                    sensor.sensor_id = data['id']
                    return True
                return False
        except: return False

async def send_measurement(session, sensor, sem, is_malicious=None) -> Tuple[int, float]:
    value = random.randint(100, 999)
    timestamp = int(time.time())
    
    if is_malicious == 'REPLAY':
        timestamp -= 7200 # 2 hours ago (Ancient History)

    message = f"{value}:{timestamp}"
    
    if is_malicious == 'BAD_SIG':
        signature = sensor.sign_with_wrong_key(message)
    else:
        signature = sensor.sign_message(message)

    payload = { "value": value, "misurator_id": sensor.sensor_id, "device_timestamp": timestamp, "signature_hex": signature }

    start_t = time.perf_counter()
    async with sem:
        try:
            async with session.post(f"{API_URL}/misurations/", json=payload, timeout=TIMEOUT_SECONDS) as resp:
                await resp.read()
                return resp.status, time.perf_counter() - start_t
        except Exception:
            return 999, 0.0

# --- PHASES ---

async def run_load_test(session, sensors, sem) -> TestStats:
    stats = TestStats()
    print(f"🔥 Phase 1: Firehose ({len(sensors)} concurrent requests)...")
    tasks = []
    for s in sensors:
        tasks.append(send_measurement(session, s, sem))
        s.sent_count += 1 

    results = await asyncio.gather(*tasks)
    for status_code, latency in results:
        stats.req_sent += 1
        stats.latency_accum += latency
        if status_code == 202: stats.req_success += 1
        else: stats.req_failed += 1
    return stats

async def run_security_test(session, zone_id, sem) -> TestStats:
    stats = TestStats()
    print("\n⚔️  Phase 2: Security Attacks...")
    bad_sensor = MaliciousSensor()
    await register_sensor(session, bad_sensor, zone_id, sem)
    
    # Attack A: Bad Sig
    print("   👉 A: Bad Signature...", end=" ")
    status_a, _ = await send_measurement(session, bad_sensor, sem, is_malicious='BAD_SIG')
    if status_a == 401: 
        print("✅ Blocked (401)")
        stats.auth_rejected += 1
    else: print(f"💀 FAILED (Got {status_a})")

    # Attack B: Replay
    print("   👉 B: Replay Attack...", end=" ")
    status_b, _ = await send_measurement(session, bad_sensor, sem, is_malicious='REPLAY')
    if status_b == 403: 
        print("✅ Blocked (403)")
        stats.replay_rejected += 1
    else: print(f"💀 FAILED (Got {status_b})")
    
    return stats

async def verify_persistence_with_polling(session, sensors, sem) -> bool:
    print(f"\n🔍 Phase 3: E2E Verification (Polling DB)...")
    sample_size = min(50, len(sensors))
    samples = sensors[:sample_size]
    verified = 0

    async with sem:
        for s in samples:
            # Polling Logic per Sensor
            for attempt in range(POLLING_RETRIES):
                async with session.get(f"{API_URL}/sensors/{s.sensor_id}/statistics") as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data['total_readings'] >= s.sent_count:
                            verified += 1
                            break # Success for this sensor
                await asyncio.sleep(1) # Backoff
            
            if data['total_readings'] < s.sent_count:
                print(f"   ⚠️ Timeout Sensor {s.sensor_id}: DB has {data['total_readings']}, Sent {s.sent_count}")

    print(f"   ✅ Persistence Rate: {(verified/sample_size)*100:.1f}% ({verified}/{sample_size})")
    return verified == sample_size

# --- MAIN ---

async def main():
    print(f"🚀 QUAKEGUARD CRITICAL TEST v2.1")
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async with aiohttp.ClientSession() as session:
        # Setup
        try:
            zone_id = await create_dynamic_zone(session)
            sensors = [VirtualSensor() for _ in range(NUM_SENSORS)]
            await asyncio.gather(*[register_sensor(session, s, zone_id, sem) for s in sensors])
            print(f"📝 Registered {NUM_SENSORS} sensors.")
        except Exception as e:
            print(f"❌ Setup Failed: {e}")
            return

        # Execution
        load_stats = await run_load_test(session, sensors, sem)
        sec_stats = await run_security_test(session, zone_id, sem)
        e2e_passed = await verify_persistence_with_polling(session, sensors, sem)

    # Report
    print("\n" + "="*40)
    print("📊 MISSION REPORT")
    print("="*40)
    print(f"Traffic:      {load_stats.req_success}/{load_stats.req_sent} Accepted")
    print(f"Sec (BadSig): {sec_stats.auth_rejected} Blocked")
    print(f"Sec (Replay): {sec_stats.replay_rejected} Blocked")
    print(f"Persistence:  {'PASS' if e2e_passed else 'FAIL'}")
    print("="*40)

    if load_stats.req_failed == 0 and e2e_passed and sec_stats.auth_rejected > 0 and sec_stats.replay_rejected > 0:
        print("🏆 SYSTEM CERTIFIED")
    else:
        print("⚠️ SYSTEM FAILURE")

if __name__ == "__main__":
    try:
        import sys
        if sys.platform == 'win32': asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    except: pass
    asyncio.run(main())