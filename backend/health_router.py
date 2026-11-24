"""
Health Router -- System Health Dashboard endpoints.

All endpoints are read-only and designed to never crash the backend.
Exceptions are caught and returned as degraded status.
"""

import os
import sys
import time
import json
import platform
import datetime
import logging
from typing import Optional

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, inspect

import database
import models

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])

# Uptime tracking -- set when module loads (backend boot)
_start_time = time.time()


# ------------------------------------------------------------------ helpers
def _safe_count(db: Session, model) -> int:
    """Count rows in a table without crashing if it doesnt exist."""
    try:
        return db.query(func.count(model.id)).scalar() or 0
    except Exception:
        return 0


def _format_uptime(seconds: float) -> str:
    """Turn raw seconds into a human readable string."""
    days = int(seconds // 86400)
    hours = int((seconds % 86400) // 3600)
    minutes = int((seconds % 3600) // 60)
    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# ============================================================
# 1. GET /health -- basic ping and uptime
# ============================================================
@router.get("")
def health_ping():
    uptime = time.time() - _start_time
    return {
        "status": "healthy",
        "version": "1.0.0",
        "uptime_seconds": round(uptime, 1),
        "uptime_formatted": _format_uptime(uptime),
        "python_version": platform.python_version(),
        "timestamp": datetime.datetime.utcnow().isoformat(),
    }


# ============================================================
# 2. GET /health/database -- DB connection and record counts
# ============================================================
@router.get("/database")
def health_database(db: Session = Depends(database.get_db)):
    try:
        connected = True
        db_url = str(database.SQLALCHEMY_DATABASE_URL)
        engine_type = "postgresql"
        db_name = db_url.split("/")[-1].split("?")[0]

        # count each table we know about
        tables = {
            "fri_entries": _safe_count(db, models.FriEntry),
            "fri_identifiers": _safe_count(db, models.FriIdentifier),
            "fraud_reports": _safe_count(db, models.FraudReport),
            "suspicious_domains": _safe_count(db, models.SuspiciousDomain),
        }
        total = sum(tables.values())

        # last insert timestamp -- grab most recent fraud report
        last_insert = None
        try:
            latest = db.query(models.FraudReport.reported_at).order_by(
                models.FraudReport.reported_at.desc()
            ).first()
            if latest:
                last_insert = latest[0].isoformat()
        except Exception:
            pass

        # grab all FRI entries w/ identifiers for the paginated table
        fri_entries = []
        try:
            entries = (
                db.query(models.FriEntry)
                .order_by(models.FriEntry.id)
                .all()
            )
            for e in entries:
                fri_entries.append({
                    "id": e.id,
                    "risk_level": e.risk_level,
                    "fraud_category": e.fraud_category,
                    "reason": e.reason,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                    "identifiers": [
                        {"type": ident.identifier_type, "value": ident.identifier_value}
                        for ident in e.identifiers
                    ],
                })
        except Exception as exc:
            logger.warning(f"Failed to load FRI entries for health page: {exc}")

        return {
            "connected": connected,
            "engine": engine_type,
            "database_name": db_name,
            "tables": tables,
            "total_records": total,
            "last_insert_timestamp": last_insert,
            "fri_entries": fri_entries,
        }
    except Exception as exc:
        return {
            "connected": False,
            "engine": "unknown",
            "database_name": "unknown",
            "tables": {},
            "total_records": 0,
            "last_insert_timestamp": None,
            "fri_entries": [],
            "error": str(exc),
        }


# ============================================================
# 3. GET /health/model -- ML model metadata and artifacts
# ============================================================
@router.get("/model")
def health_model():
    ml_dir = os.path.join(os.path.dirname(__file__), "ml")
    result = {
        "model_loaded": False,
        "text_model_loaded": False,
        "model_version": None,
        "training_date": None,
        "feature_count": 0,
        "optimal_threshold": None,
        "performance": {},
        "artifacts_present": {},
        "model_file_size_mb": 0,
    }

    # check each expected artifact
    expected_artifacts = [
        "xgb_phishing_model.pkl",
        "text_classifier.py",
        "feature_names.json",
        "optimal_threshold.json",
        "model_metadata.json",
        "feature_engineering.py",
        "whitelist.py",
        "url_classifier.py",
        "__init__.py",
    ]

    for fname in expected_artifacts:
        fpath = os.path.join(ml_dir, fname)
        result["artifacts_present"][fname] = os.path.exists(fpath)

    # model file size
    pkl_path = os.path.join(ml_dir, "xgb_phishing_model.pkl")
    if os.path.exists(pkl_path):
        result["model_file_size_mb"] = round(os.path.getsize(pkl_path) / (1024 * 1024), 2)

    # read metadata
    meta_path = os.path.join(ml_dir, "model_metadata.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            result["model_version"] = meta.get("model_version")
            result["training_date"] = meta.get("training_date")
            result["feature_count"] = meta.get("feature_count", 0)
            result["performance"] = meta.get("performance", {})
        except Exception:
            pass

    # read threshold
    thresh_path = os.path.join(ml_dir, "optimal_threshold.json")
    if os.path.exists(thresh_path):
        try:
            with open(thresh_path, "r", encoding="utf-8") as f:
                result["optimal_threshold"] = json.load(f).get("threshold")
        except Exception:
            pass

    # check if classifier is actually loaded in memory
    try:
        from ml import get_classifier
        clf = get_classifier()
        if clf and clf.is_loaded:
            result["model_loaded"] = True
        from ml import get_text_classifier
        text_clf = get_text_classifier()
        if text_clf and text_clf.is_loaded:
            result["text_model_loaded"] = True
    except Exception:
        pass

    return result


# ============================================================
# 4. GET /health/url-intelligence -- external layer status
# ============================================================
@router.get("/url-intelligence")
def health_url_intelligence():
    import urllib.request
    import urllib.error

    layers = {}

    # -- PhishDestroy (free, no key) --
    try:
        start = time.time()
        req = urllib.request.Request(
            "https://api.destroy.tools/v1/check?domain=google.com",
            headers={"User-Agent": "BankGuard-HealthCheck/1.0"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            elapsed = (time.time() - start) * 1000
            layers["phishdestroy"] = {
                "reachable": resp.status == 200,
                "response_time_ms": round(elapsed, 1),
                "last_checked": datetime.datetime.utcnow().isoformat(),
            }
    except Exception as exc:
        layers["phishdestroy"] = {
            "reachable": False,
            "response_time_ms": None,
            "last_checked": datetime.datetime.utcnow().isoformat(),
            "error": str(exc),
        }

    # -- Google Safe Browsing --
    gsb_key = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    try:
        if gsb_key:
            start = time.time()
            url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}"
            payload = json.dumps({
                "client": {"clientId": "bankguard", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": "https://google.com"}],
                },
            }).encode("utf-8")
            req = urllib.request.Request(
                url, data=payload, method="POST",
                headers={"Content-Type": "application/json", "User-Agent": "BankGuard/1.0"},
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                elapsed = (time.time() - start) * 1000
                layers["google_safe_browsing"] = {
                    "configured": True,
                    "reachable": resp.status == 200,
                    "response_time_ms": round(elapsed, 1),
                    "api_key_present": True,
                }
        else:
            layers["google_safe_browsing"] = {
                "configured": False,
                "reachable": False,
                "response_time_ms": None,
                "api_key_present": False,
            }
    except Exception as exc:
        layers["google_safe_browsing"] = {
            "configured": bool(gsb_key),
            "reachable": False,
            "response_time_ms": None,
            "api_key_present": bool(gsb_key),
            "error": str(exc),
        }

    # -- ML Model layer --
    try:
        from ml import get_classifier
        clf = get_classifier()
        if clf and clf.is_loaded:
            # quick inference to measure speed
            start = time.time()
            clf.predict("https://google.com")
            elapsed = (time.time() - start) * 1000
            layers["ml_model"] = {
                "loaded": True,
                "inference_time_ms": round(elapsed, 1),
            }
        else:
            layers["ml_model"] = {"loaded": False, "inference_time_ms": None}
    except Exception:
        layers["ml_model"] = {"loaded": False, "inference_time_ms": None}

    # -- Whitelist counts --
    whitelist_entries = {"tier1_count": 0, "tier2_count": 0, "tier3_count": 0, "total": 0}
    try:
        from ml.whitelist import TIER_1_BANK_IN_DOMAINS, TIER_2_LEGACY_DOMAINS, TIER_3_GENERAL_TRUSTED
        whitelist_entries["tier1_count"] = len(TIER_1_BANK_IN_DOMAINS)
        whitelist_entries["tier2_count"] = len(TIER_2_LEGACY_DOMAINS)
        whitelist_entries["tier3_count"] = len(TIER_3_GENERAL_TRUSTED)
        whitelist_entries["total"] = sum([
            whitelist_entries["tier1_count"],
            whitelist_entries["tier2_count"],
            whitelist_entries["tier3_count"],
        ])
    except Exception:
        pass

    return {"layers": layers, "whitelist_entries": whitelist_entries}


# ============================================================
# 5. GET /health/telemetry -- SDK telemetry feed
# ============================================================
@router.get("/telemetry")
def health_telemetry(db: Session = Depends(database.get_db)):
    """
    There's no dedicated telemetry table, so we pull from FraudReport
    which logs every URL and APK scan event.
    """
    try:
        total = _safe_count(db, models.FraudReport)
        now = datetime.datetime.utcnow()
        day_ago = now - datetime.timedelta(hours=24)

        events_24h = 0
        try:
            events_24h = (
                db.query(func.count(models.FraudReport.id))
                .filter(models.FraudReport.reported_at >= day_ago)
                .scalar() or 0
            )
        except Exception:
            pass

        last_ts = None
        recent = []
        try:
            rows = (
                db.query(models.FraudReport)
                .order_by(models.FraudReport.reported_at.desc())
                .limit(10)
                .all()
            )
            for r in rows:
                recent.append({
                    "id": r.id,
                    "event_type": r.report_type,
                    "source": r.source or "unknown",
                    "content": r.content,
                    "risk_score": r.risk_score,
                    "timestamp": r.reported_at.isoformat() if r.reported_at else None,
                })
            if rows:
                last_ts = rows[0].reported_at.isoformat() if rows[0].reported_at else None
        except Exception:
            pass

        return {
            "endpoint_active": True,
            "total_events_received": total,
            "events_last_24h": events_24h,
            "last_event_timestamp": last_ts,
            "recent_events": recent,
        }
    except Exception as exc:
        return {
            "endpoint_active": False,
            "total_events_received": 0,
            "events_last_24h": 0,
            "last_event_timestamp": None,
            "recent_events": [],
            "error": str(exc),
        }


# ============================================================
# 6. GET /health/apk-scanner -- Androguard status
# ============================================================
@router.get("/apk-scanner")
def health_apk_scanner(db: Session = Depends(database.get_db)):
    androguard_available = False
    androguard_version = None

    try:
        import androguard
        androguard_available = True
        androguard_version = getattr(androguard, "__version__", "unknown")
    except ImportError:
        pass

    # recent APK scans from fraud reports
    recent_scans = []
    total_scans = 0
    try:
        total_scans = (
            db.query(func.count(models.FraudReport.id))
            .filter(models.FraudReport.report_type == "APK")
            .scalar() or 0
        )
        rows = (
            db.query(models.FraudReport)
            .filter(models.FraudReport.report_type == "APK")
            .order_by(models.FraudReport.reported_at.desc())
            .limit(5)
            .all()
        )
        for r in rows:
            # map risk_score float to verdict string
            verdict = "SAFE"
            if r.risk_score and r.risk_score > 0.75:
                verdict = "MALICIOUS"
            elif r.risk_score and r.risk_score > 0.25:
                verdict = "SUSPICIOUS"
            recent_scans.append({
                "package_name": r.content,
                "app_name": r.content,
                "verdict": verdict,
                "risk_score": r.risk_score,
                "timestamp": r.reported_at.isoformat() if r.reported_at else None,
            })
    except Exception:
        pass

    return {
        "androguard_available": androguard_available,
        "androguard_version": androguard_version,
        "endpoint_active": True,
        "total_apks_scanned": total_scans,
        "recent_scans": recent_scans,
    }


# ============================================================
# 7. GET /health/fri-summary -- FRI aggregated stats
# ============================================================
@router.get("/fri-summary")
def health_fri_summary(db: Session = Depends(database.get_db)):
    try:
        total = _safe_count(db, models.FriEntry)

        # by risk level
        by_risk = {}
        try:
            rows = (
                db.query(models.FriEntry.risk_level, func.count(models.FriEntry.id))
                .group_by(models.FriEntry.risk_level)
                .all()
            )
            for level, count in rows:
                key = (level or "unknown").lower().replace(" ", "_")
                by_risk[key] = count
        except Exception:
            pass

        # by fraud category
        by_category = {}
        try:
            rows = (
                db.query(models.FriEntry.fraud_category, func.count(models.FriEntry.id))
                .group_by(models.FriEntry.fraud_category)
                .all()
            )
            for cat, count in rows:
                key = (cat or "unknown").lower().replace(" ", "_")
                by_category[key] = count
        except Exception:
            pass

        # by identifier type
        by_ident = {}
        try:
            rows = (
                db.query(models.FriIdentifier.identifier_type, func.count(models.FriIdentifier.id))
                .group_by(models.FriIdentifier.identifier_type)
                .all()
            )
            for itype, count in rows:
                by_ident[itype or "unknown"] = count
        except Exception:
            pass

        # FRI check stats -- we dont track per-check hits yet, so return zeros
        return {
            "total_entries": total,
            "by_risk_level": by_risk,
            "by_fraud_category": by_category,
            "by_identifier_type": by_ident,
            "total_fri_checks_performed": 0,
            "total_fri_hits": 0,
            "hit_rate_percent": 0.0,
        }
    except Exception as exc:
        return {
            "total_entries": 0,
            "by_risk_level": {},
            "by_fraud_category": {},
            "by_identifier_type": {},
            "total_fri_checks_performed": 0,
            "total_fri_hits": 0,
            "hit_rate_percent": 0.0,
            "error": str(exc),
        }


# ============================================================
# 8. GET /health/fraud-reports -- recent fraud reports
# ============================================================
@router.get("/fraud-reports")
def health_fraud_reports(db: Session = Depends(database.get_db)):
    try:
        total = _safe_count(db, models.FraudReport)
        now = datetime.datetime.utcnow()
        day_ago = now - datetime.timedelta(hours=24)

        reports_24h = 0
        try:
            reports_24h = (
                db.query(func.count(models.FraudReport.id))
                .filter(models.FraudReport.reported_at >= day_ago)
                .scalar() or 0
            )
        except Exception:
            pass

        recent = []
        try:
            rows = (
                db.query(models.FraudReport)
                .order_by(models.FraudReport.reported_at.desc())
                .limit(5)
                .all()
            )
            for r in rows:
                recent.append({
                    "id": r.id,
                    "report_type": r.report_type,
                    "url_or_identifier": r.content,
                    "source": r.source,
                    "timestamp": r.reported_at.isoformat() if r.reported_at else None,
                })
        except Exception:
            pass

        return {
            "total_reports": total,
            "reports_last_24h": reports_24h,
            "recent_reports": recent,
        }
    except Exception as exc:
        return {
            "total_reports": 0,
            "reports_last_24h": 0,
            "recent_reports": [],
            "error": str(exc),
        }


# ============================================================
# 9. GET /health/environment -- system environment info
# ============================================================
@router.get("/environment")
def health_environment():
    ml_dir = os.path.join(os.path.dirname(__file__), "ml")

    artifacts = {}
    expected = [
        "xgb_phishing_model.pkl",
        "feature_names.json",
        "optimal_threshold.json",
        "model_metadata.json",
        "feature_engineering.py",
        "whitelist.py",
    ]
    for fname in expected:
        fpath = os.path.join(ml_dir, fname)
        if os.path.exists(fpath):
            stat = os.stat(fpath)
            size = stat.st_size
            modified = datetime.datetime.fromtimestamp(stat.st_mtime).isoformat()
            # pick reasonable unit
            if size > 1024 * 1024:
                size_label = f"{round(size / (1024 * 1024), 2)} MB"
            else:
                size_label = f"{round(size / 1024, 1)} KB"
            artifacts[fname] = {
                "present": True,
                "size": size_label,
                "modified": modified,
            }
        else:
            artifacts[fname] = {"present": False, "size": None, "modified": None}

    # dependency versions
    xgb_version = None
    try:
        import xgboost
        xgb_version = xgboost.__version__
    except Exception:
        pass

    ag_version = None
    try:
        import androguard
        ag_version = getattr(androguard, "__version__", "unknown")
    except Exception:
        pass

    return {
        "python_version": platform.python_version(),
        "os": f"{platform.system()} {platform.release()}",
        "ml_artifacts_directory": ml_dir,
        "ml_artifacts": artifacts,
        "xgboost_version": xgb_version,
        "androguard_version": ag_version,
    }
