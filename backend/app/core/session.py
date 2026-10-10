"""Session manager for AegisDNS providing per-run session token authentication."""

import uuid
from typing import Optional
from fastapi import Header, HTTPException, status, APIRouter

# Generate per-run session token upon server start
SERVER_SESSION_TOKEN: str = uuid.uuid4().hex

router = APIRouter(prefix="/api", tags=["session"])


def get_session_token() -> str:
    """Return the active per-run session token."""
    return SERVER_SESSION_TOKEN


def verify_session_token(x_aegisdns_token: Optional[str] = Header(None, alias="X-AegisDNS-Token")):
    """FastAPI dependency enforcing valid X-AegisDNS-Token header for sensitive control actions."""
    if not x_aegisdns_token or x_aegisdns_token != SERVER_SESSION_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing session token in X-AegisDNS-Token header."
        )


@router.get("/session")
async def get_session():
    """Retrieve active per-run session token for frontend state initialization."""
    return {"token": SERVER_SESSION_TOKEN}
