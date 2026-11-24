import sys
import os
import traceback

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import SessionLocal
import models
import api_schemas as schemas
from main import device_reverify

class MockClient:
    def __init__(self, host):
        self.host = host

class MockRequest:
    def __init__(self, host="127.0.0.1"):
        self.client = MockClient(host)

def run_diagnostic():
    print("Initializing database session...")
    db = SessionLocal()
    
    # 1. Check if there are profiles
    print("\n1. Checking existing UserDeviceProfile records...")
    try:
        profiles = db.query(models.UserDeviceProfile).all()
        print(f"Found {len(profiles)} profiles.")
        for p in profiles:
            print(f" - Customer: {p.customer_id}, Baseline SIM Hash: {p.sim_hash_baseline}, Locked: {p.is_locked}")
    except Exception as e:
        print("ERROR querying UserDeviceProfile:")
        traceback.print_exc()
        return

    # 2. Check if the target customer profile exists
    customer_id = "89012345678"
    print(f"\n2. Fetching profile for customer_id: {customer_id}...")
    profile = db.query(models.UserDeviceProfile).filter(models.UserDeviceProfile.customer_id == customer_id).first()
    if not profile:
        print(f"WARNING: Customer {customer_id} does not exist in UserDeviceProfile. Creating a mock one to test reverification...")
        try:
            profile = models.UserDeviceProfile(
                customer_id=customer_id,
                device_key_pub="MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy3Ydevicekey",
                sim_hash_baseline="test_hash_baseline",
                is_locked=True
            )
            db.add(profile)
            db.commit()
            print("Successfully created mock UserDeviceProfile.")
        except Exception as e:
            print("ERROR creating mock profile:")
            traceback.print_exc()
            return

    # 3. Simulate calling device_reverify
    print(f"\n3. Simulating device_reverify endpoint call for customer_id={customer_id}...")
    payload = schemas.DeviceReverifyRequest(
        customer_id=customer_id,
        sim_hash="new_sim_hash_test_123",
        otp="123456"
    )
    request = MockRequest()
    
    try:
        res = device_reverify(payload=payload, request=request, db=db)
        print("SUCCESS! device_reverify executed without throwing errors.")
        print("Response:", res)
    except Exception as e:
        print("CRITICAL: device_reverify threw an exception:")
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    run_diagnostic()
