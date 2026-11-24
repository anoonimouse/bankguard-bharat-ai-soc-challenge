from database import SessionLocal
import models

db = SessionLocal()

print("--- User Device Profiles ---")
profiles = db.query(models.UserDeviceProfile).all()
for p in profiles:
    print(f"Customer ID: {p.customer_id}")
    print(f"  Device Key Pub: {p.device_key_pub[:30]}...")
    print(f"  SIM Hash Baseline: {p.sim_hash_baseline}")
    print(f"  Is Locked: {p.is_locked}")
    print(f"  Last Seen IP: {p.last_seen_ip}")
    print(f"  Last Active: {p.last_active}")

print("\n--- Telecom SIM Swap Registry ---")
registry = db.query(models.TelecomSimSwapRegistry).all()
for r in registry:
    print(f"Phone Number: {r.phone_number}")
    print(f"  SIM Swapped At: {r.sim_swapped_at}")

print("\n--- Fraud Reports (SIM_SWAP) ---")
reports = db.query(models.FraudReport).filter(models.FraudReport.report_type.in_(["SIM_SWAP", "TELECOM_SIM_SWAP"])).all()
for rep in reports:
    print(f"Type: {rep.report_type} | Status: {rep.status} | Content: {rep.content}")
