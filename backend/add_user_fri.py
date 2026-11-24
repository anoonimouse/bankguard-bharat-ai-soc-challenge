from database import SessionLocal
from models import FriEntry, FriIdentifier
db = SessionLocal()

entry = FriEntry(risk_level="Very High", fraud_category="UPI Fraud", reason="Reported by multiple users for fake KYC scams.")
db.add(entry)
db.commit()
db.refresh(entry)

id1 = FriIdentifier(entry_id=entry.id, identifier_type="upi", identifier_value="pillai.dinesh@axl")
id2 = FriIdentifier(entry_id=entry.id, identifier_type="mobile", identifier_value="8610854875")
id3 = FriIdentifier(entry_id=entry.id, identifier_type="bank_account", identifier_value="041245228657580")

db.add_all([id1, id2, id3])
db.commit()
print("Added successfully!")
