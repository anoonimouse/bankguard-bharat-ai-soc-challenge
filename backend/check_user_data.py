from database import SessionLocal
from models import FriIdentifier
db = SessionLocal()
results = db.query(FriIdentifier).filter(FriIdentifier.identifier_value.in_(['pillai.dinesh@axl', '8610854875', '041245228657580'])).all()
for r in results:
    print(r.identifier_value, r.risk_level)
