from database import SessionLocal
from models import FriIdentifier
db = SessionLocal()
results = db.query(FriIdentifier).filter(FriIdentifier.identifier_value == 'manojy3888@ybl').all()
for r in results:
    print(r.identifier_value, r.risk_level)
