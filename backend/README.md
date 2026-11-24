# BankGuard Threat Intelligence Backend

The BankGuard backend is a FastAPI-powered threat intelligence service and central registry designed to complement the mobile SDK's on-device security capabilities.

## Role & Responsibilities

1. **Fraud Risk Indicator (FRI) Lookups**: Real-time validation for suspicious UPI IDs, mobile numbers, and bank account numbers against curated fraud registries.
2. **Package & Certificate Hash Verification**: Allows client applications to cross-verify APK certificates against known-good genuine banking hashes.
3. **Telemetry Ingestion**: Ingests anonymous threat events (quarantined APKs, intercepted phishing links, tampering attempts) for administrative review.
4. **Offline-First Compatibility**: In accordance with the Bharat AI-SoC Challenge specifications, the mobile application does not require this backend for threat classification—local on-device heuristics and ExecuTorch models execute autonomously.

## Key Files & Structure

- `main.py` - Core FastAPI application entrypoint, route bindings, and lifecycle events.
- `database.py` - SQLAlchemy database connection setup (supports local SQLite `bankguard.db` and cloud PostgreSQL).
- `models.py` - Database models for FRI entities, threat events, device registries, and audit logs.
- `schemas.py` & `api_schemas.py` - Pydantic validation schemas for incoming requests and outgoing responses.
- `auth.py` - Authentication and API key verification middleware.
- `health_router.py` - Health check endpoints for orchestration and container monitoring.
- `seed_fri.py` - Utility to populate initial test Fraud Risk Indicators.
- `threat_keywords.json` - Curated dictionary of multilingual fraud cues and brand markers.

## Getting Started

### 1. Install Dependencies
```bash
cd backend
python -m venv venv
venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

### 2. Configure Environment
Copy `.env.example` to `.env` and configure your database and port settings:
```env
DATABASE_URL=sqlite:///./bankguard.db
SECRET_KEY=bankguard_secret_key_demo
```

### 3. Initialize Database & Run Server
```bash
python seed_fri.py
uvicorn main.py:app --host 0.0.0.0 --port 8000 --reload
```

Interactive OpenAPI documentation is available at `http://localhost:8000/docs`.
