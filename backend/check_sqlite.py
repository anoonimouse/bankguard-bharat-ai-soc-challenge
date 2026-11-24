from database import SessionLocal
from models import FriIdentifier, FriEntry
db = SessionLocal()

results = db.query(FriIdentifier).all()
print("Total identifiers in DB:", len(results))
