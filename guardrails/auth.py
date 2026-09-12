import os
from typing import Dict, Any, Optional
import jwt
from jwt import PyJWKClient
from fastapi import Header, HTTPException, status
from backend.telemetry import log_safety_event

# 1. Clerk Configurations & JWKS Dynamic Key Fetcher Setup
CLERK_ISSUER_URL = os.getenv("CLERK_ISSUER_URL", "https://your-clerk-app.clerk.accounts.dev")
JWKS_URL = f"{CLERK_ISSUER_URL.rstrip('/')}/.well-known/jwks.json"

# PyJWKClient caches the public keys locally to keep verification ultra-fast
_jwks_client = PyJWKClient(JWKS_URL)

def verify_jwt_token(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    Enterprise Clerk JWT Authenticator.
    Validates incoming Bearer JWT tokens dynamically via Clerk's JWKS endpoint.
    Integrates directly with backend/telemetry.py for safety audit logs.
    """
    # 1. Missing Authorization Header Check
    if not authorization:
        log_safety_event(
            user_id="ANONYMOUS",
            event_type="CLERK_AUTH_MISSING_HEADER",
            details="Incoming request rejected due to missing Authorization header."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Authorization header is required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Bearer Scheme Validation
    try:
        scheme, token = authorization.split(" ", 1)
        if scheme.lower() != "bearer":
            raise ValueError("Header does not start with Bearer scheme.")
    except ValueError as err:
        log_safety_event(
            user_id="ANONYMOUS",
            event_type="CLERK_AUTH_MALFORMED_HEADER",
            details=f"Malformed Authorization header: '{authorization}'"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Authorization header format must be 'Bearer <token>'.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 3. Fetch Public Signing Key from Clerk JWKS & Verify Cryptographic Signature
    try:
        # Dynamically match token header 'kid' (Key ID) with Clerk's public JWKS keys
        signing_key = _jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=CLERK_ISSUER_URL,
            options={"verify_aud": False}  # Clerk default session tokens don't require audience check
        )

        # Extract Clerk User ID ('sub' claim)
        user_id = payload.get("sub", "UNKNOWN_CLERK_USER")
        payload["user_id"] = user_id
        
        return payload

    except jwt.ExpiredSignatureError:
        log_safety_event(
            user_id="EXPIRED_CLERK_USER",
            event_type="CLERK_AUTH_EXPIRED",
            details="Provided Clerk JWT token session has expired."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Session token has expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except (jwt.PyJWTError, Exception) as error:
        log_safety_event(
            user_id="ANONYMOUS",
            event_type="CLERK_AUTH_INVALID",
            details=f"Clerk JWKS Signature/Payload error: {str(error)}"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication failed: Invalid or untrusted Clerk token signature.",
            headers={"WWW-Authenticate": "Bearer"},
        )