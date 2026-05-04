"""API authentication middleware.

Provides API key and optional JWT-based authentication for the
AegisThreat API server.

MVP: Static API key from environment variable.
Phase 2+: JWT with OAuth2 / OIDC integration.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from typing import Optional

from fastapi import Header, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)

# Default security scheme
security = HTTPBearer(auto_error=False)

# Hardcoded API key for MVP (override via AEGIS_API_KEY env var)
_API_KEY = os.environ.get("AEGIS_API_KEY", "")

# Whether auth is enforced
_AUTH_ENABLED = bool(_API_KEY) or os.environ.get("AEGIS_AUTH_REQUIRED", "").lower() in ("true", "1", "yes")


def is_auth_enabled() -> bool:
    return _AUTH_ENABLED


def verify_api_key(api_key: Optional[str]) -> bool:
    """Verify an API key against the configured key.

    Uses constant-time comparison to prevent timing attacks.
    """
    if not _AUTH_ENABLED:
        return True
    if not api_key or not _API_KEY:
        return False
    return hmac.compare_digest(api_key, _API_KEY)


async def require_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = None,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> None:
    """FastAPI dependency that requires authentication.

    Accepts either:
    - Bearer token in Authorization header
    - X-API-Key header

    If neither is configured (MVP default), all requests are allowed.
    """
    if not _AUTH_ENABLED:
        return

    # Check Bearer token
    if credentials and credentials.credentials:
        if verify_api_key(credentials.credentials):
            return
        raise HTTPException(status_code=403, detail="Invalid bearer token")

    # Check X-API-Key header
    if x_api_key:
        if verify_api_key(x_api_key):
            return
        raise HTTPException(status_code=403, detail="Invalid API key")

    raise HTTPException(status_code=401, detail="Authentication required (Bearer token or X-API-Key header)")


def generate_api_key() -> str:
    """Generate a new random API key."""
    import secrets
    return f"aegis-{secrets.token_hex(24)}"


def configure_api_key(key: str) -> None:
    """Set the API key at runtime."""
    global _API_KEY, _AUTH_ENABLED
    _API_KEY = key
    _AUTH_ENABLED = bool(key)
