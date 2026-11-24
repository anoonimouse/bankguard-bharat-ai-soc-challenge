"""
JWT authentication module for the BankGuard admin dashboard.

Provides:
- Password hashing via bcrypt
- JWT token creation and verification
- FastAPI dependency for protecting admin endpoints
- Initial admin seeding from environment variables

Required env vars:
    JWT_SECRET  -- 64-char hex key (generate with: openssl rand -hex 32)
    ADMIN_USER  -- initial admin username (optional, defaults to 'admin')
    ADMIN_PASS  -- initial admin password (required for first boot)
"""

import os
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

import database
import models

# --- Configuration ---

SECRET_KEY = os.environ.get("JWT_SECRET", "")
if not SECRET_KEY:
    # Dev fallback -- in production JWT_SECRET must be set
    SECRET_KEY = "dev-insecure-fallback-key-change-in-production"
    print("[WARN] JWT_SECRET not set -- using insecure fallback (never do this in production)")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_EXPIRE_MINUTES", "480"))  # 8h default

# --- Password hashing ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# --- JWT tokens ---

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- FastAPI dependency: require valid admin token ---

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(database.get_db),
) -> models.AdminUser:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(models.AdminUser).filter(
        models.AdminUser.username == username,
        models.AdminUser.is_active == True,
    ).first()

    if user is None:
        raise credentials_exception
    return user

# --- Initial admin seeding ---

def ensure_initial_admin():
    """
    Create the initial admin account from env vars if the admin_users table
    is empty. Runs once at startup.
    """
    db = database.SessionLocal()
    try:
        count = db.query(models.AdminUser).count()
        if count > 0:
            return  # admins already exist

        admin_user = os.environ.get("ADMIN_USER", "admin")
        admin_pass = os.environ.get("ADMIN_PASS", "")
        if not admin_pass:
            print("[WARN] No ADMIN_PASS env var set -- skipping initial admin creation")
            print("       Set ADMIN_USER and ADMIN_PASS to create the first admin account")
            return

        user = models.AdminUser(
            username=admin_user,
            hashed_password=hash_password(admin_pass),
        )
        db.add(user)
        db.commit()
        print(f"[PASS] Initial admin account '{admin_user}' created successfully")
    finally:
        db.close()
