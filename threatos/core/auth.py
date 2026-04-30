from __future__ import annotations
import bcrypt, os, secrets, uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from jose import JWTError, jwt
from sqlalchemy import delete, select, func
from sqlalchemy.ext.asyncio import AsyncSession

from threatos.models.user import VALID_ROLES, User

# ── Config ────────────────────────────────────────────────────────────────────
def _get_secret(key: str, default: str) -> str:
    val = os.environ.get(key, default)
    if val == default:
        import logging
        logging.getLogger(__name__).warning(
            "Using default %s — set a strong random value in .env", key)
    return val

SECRET_KEY         = _get_secret("JWT_SECRET_KEY",         "CHANGE_ME_ACCESS_SECRET_64_CHARS")
REFRESH_SECRET_KEY = _get_secret("JWT_REFRESH_SECRET_KEY", "CHANGE_ME_REFRESH_SECRET_64_CHARS")
ALGORITHM          = "HS256"
ACCESS_EXPIRE      = int(os.environ.get("JWT_ACCESS_EXPIRE_MINUTES",  "480"))
REFRESH_EXPIRE     = int(os.environ.get("JWT_REFRESH_EXPIRE_DAYS",    "30"))
MAX_LOGIN_ATTEMPTS = int(os.environ.get("MAX_LOGIN_ATTEMPTS",         "5"))
LOGIN_LOCKOUT_MIN  = int(os.environ.get("LOGIN_LOCKOUT_MINUTES",      "15"))

# ── Password ──────────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def generate_api_key() -> str:
    return secrets.token_hex(32)

def generate_secret_key() -> str:
    """Generate a cryptographically strong 64-char secret key."""
    return secrets.token_hex(32)

# ── JWT ───────────────────────────────────────────────────────────────────────
def _make_jti() -> str:
    return str(uuid.uuid4())

def create_access_token(data: dict[str, Any]) -> tuple[str, str]:
    """Returns (token, jti)"""
    jti     = _make_jti()
    payload = {**data, "jti": jti,
               "exp": datetime.now(UTC) + timedelta(minutes=ACCESS_EXPIRE),
               "type": "access"}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM), jti

def create_refresh_token(data: dict[str, Any]) -> tuple[str, str]:
    """Returns (token, jti)"""
    jti     = _make_jti()
    payload = {**data, "jti": jti,
               "exp": datetime.now(UTC) + timedelta(days=REFRESH_EXPIRE),
               "type": "refresh"}
    return jwt.encode(payload, REFRESH_SECRET_KEY, algorithm=ALGORITHM), jti

def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

def decode_refresh_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, REFRESH_SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None

# Keep backward compat
def decode_token(token: str) -> dict | None:
    return decode_access_token(token)

# ── Token blacklist ───────────────────────────────────────────────────────────
async def blacklist_token(db: AsyncSession, jti: str, user_id: str,
                           expires_at: datetime) -> None:
    from threatos.models.token_blacklist import TokenBlacklist
    entry = TokenBlacklist(jti=jti, user_id=user_id,
                            revoked_at=datetime.now(UTC), expires_at=expires_at)
    db.add(entry)
    await db.flush()

async def is_token_blacklisted(db: AsyncSession, jti: str) -> bool:
    from threatos.models.token_blacklist import TokenBlacklist
    result = await db.execute(
        select(TokenBlacklist).where(TokenBlacklist.jti == jti))
    return result.scalar_one_or_none() is not None

async def cleanup_expired_tokens(db: AsyncSession) -> int:
    """Remove expired blacklist entries — call periodically."""
    from threatos.models.token_blacklist import TokenBlacklist
    result = await db.execute(
        delete(TokenBlacklist).where(
            TokenBlacklist.expires_at < datetime.now(UTC)
        ).returning(TokenBlacklist.jti)
    )
    return len(result.fetchall())

async def revoke_all_user_tokens(db: AsyncSession, user_id: str) -> None:
    """Revoke all active tokens for a user (force re-login)."""
    from threatos.models.token_blacklist import TokenBlacklist
    # We can't enumerate all tokens but we can mark a revocation timestamp
    # New tokens check this timestamp against their iat claim
    user = await get_user_by_id(db, user_id)
    if user:
        user.tokens_revoked_at = datetime.now(UTC)
        await db.flush()

# ── Rate limiting ─────────────────────────────────────────────────────────────
async def record_login_attempt(db: AsyncSession, ip_address: str,
                                username: str | None, success: bool) -> None:
    from threatos.models.login_attempt import LoginAttempt
    attempt = LoginAttempt(
        id=str(uuid.uuid4()), ip_address=ip_address,
        username=username, success=success,
        attempted_at=datetime.now(UTC),
    )
    db.add(attempt)
    await db.flush()

async def is_rate_limited(db: AsyncSession, ip_address: str) -> tuple[bool, int]:
    """
    Returns (is_limited, attempts_remaining).
    Blocks IP after MAX_LOGIN_ATTEMPTS failures in LOGIN_LOCKOUT_MIN minutes.
    """
    from threatos.models.login_attempt import LoginAttempt
    cutoff = datetime.now(UTC) - timedelta(minutes=LOGIN_LOCKOUT_MIN)
    result = await db.execute(
        select(func.count(LoginAttempt.id))
        .where(LoginAttempt.ip_address  == ip_address,
               LoginAttempt.success     == False,
               LoginAttempt.attempted_at >= cutoff)
    )
    failures = int(result.scalar() or 0)
    remaining = max(0, MAX_LOGIN_ATTEMPTS - failures)
    return failures >= MAX_LOGIN_ATTEMPTS, remaining

async def cleanup_old_attempts(db: AsyncSession) -> None:
    """Clean login attempts older than 24 hours."""
    from threatos.models.login_attempt import LoginAttempt
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    await db.execute(delete(LoginAttempt).where(LoginAttempt.attempted_at < cutoff))

# ── User CRUD ─────────────────────────────────────────────────────────────────
async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
    result = await db.execute(
        select(User).where(User.username == username.lower().strip()))
    return result.scalar_one_or_none()

async def get_user_by_id(db: AsyncSession, user_id: str) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()

async def get_user_by_api_key(db: AsyncSession, api_key: str) -> User | None:
    result = await db.execute(select(User).where(User.api_key == api_key))
    return result.scalar_one_or_none()

async def list_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return list(result.scalars().all())

async def create_user(db: AsyncSession, username: str, email: str,
                      password: str, role: str = "analyst",
                      full_name: str | None = None) -> User:
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role!r}")
    user = User(
        username=username.lower().strip(),
        email=email.lower().strip(),
        full_name=full_name,
        password_hash=hash_password(password),
        role=role, is_active=True,
        created_at=datetime.now(UTC),
    )
    db.add(user)
    await db.flush()
    return user

async def authenticate_user(db: AsyncSession, username: str,
                             password: str) -> User | None:
    user = await get_user_by_username(db, username)
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login = datetime.now(UTC)
    await db.flush()
    return user

async def ensure_admin_exists(db: AsyncSession) -> None:
    result = await db.execute(select(func.count(User.id)))
    if (result.scalar() or 0) == 0:
        admin_password = os.environ.get("THREATOS_ADMIN_PASSWORD", "ThreatOS@2026")
        await create_user(db, username="admin", email="admin@threatos.local",
                          password=admin_password, role="admin",
                          full_name="ThreatOS Admin")
        import logging
        logging.getLogger(__name__).info(
            "Default admin created — CHANGE PASSWORD IMMEDIATELY")
