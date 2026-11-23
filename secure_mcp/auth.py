"""Identity: user tokens (from the company IdP) and short-lived per-server tokens.

Flow:  user JWT  --(gateway verifies)-->  Identity  --(gateway mints)-->  server JWT
The model never sees either token. MCP servers trust ONLY the server JWT, so a model
(or a compromised agent process) cannot pick which user it is acting as.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass

import jwt

ISSUER = "acme-idp"
GATEWAY_AUDIENCE = "mcp-gateway"
# Dev defaults only. In production load these from a secret manager, never from source.
IDP_SECRET = os.environ.get("IDP_SECRET") or "dev-idp-secret-change-me-0123456789abcdef"
GATEWAY_SECRET = os.environ.get("GATEWAY_SECRET") or "dev-gateway-secret-change-me-0123456789"


class AuthError(Exception):
    pass


@dataclass(frozen=True)
class Identity:
    user_id: str
    role: str  # employee | manager | admin
    department: str


def issue_user_token(user_id: str, role: str, department: str, ttl: int = 900,
                     secret: str = IDP_SECRET) -> str:
    """What the IdP (Keycloak/Auth0/Entra) would give the user after SSO. Used by demo/tests."""
    now = int(time.time())
    return jwt.encode(
        {"sub": user_id, "role": role, "dept": department, "iss": ISSUER,
         "aud": GATEWAY_AUDIENCE, "iat": now, "exp": now + ttl},
        secret, algorithm="HS256")


def verify_user_token(token: str, secret: str = IDP_SECRET) -> Identity:
    try:
        claims = jwt.decode(
            token, secret, algorithms=["HS256"],  # pinned: rejects alg=none / alg confusion
            audience=GATEWAY_AUDIENCE, issuer=ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]})
    except jwt.PyJWTError as e:
        raise AuthError(f"invalid token: {type(e).__name__}") from e
    if claims.get("role") not in {"employee", "manager", "admin"}:
        raise AuthError("invalid token: unknown role")
    return Identity(claims["sub"], claims["role"], claims.get("dept", ""))


def mint_server_token(identity: Identity, server: str, ttl: int = 30) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": identity.user_id, "role": identity.role, "dept": identity.department,
         "aud": f"mcp-server:{server}", "iss": "mcp-gateway", "iat": now, "exp": now + ttl},
        GATEWAY_SECRET, algorithm="HS256")


def verify_server_token(token: str, server: str) -> Identity:
    """Called INSIDE each MCP server. Audience is per-server, so a token minted for
    'docs' cannot be replayed against 'hr'."""
    try:
        c = jwt.decode(token, GATEWAY_SECRET, algorithms=["HS256"],
                       audience=f"mcp-server:{server}", issuer="mcp-gateway",
                       options={"require": ["exp", "iss", "aud", "sub"]})
    except jwt.PyJWTError as e:
        raise PermissionError("caller identity could not be verified") from e
    return Identity(c["sub"], c["role"], c.get("dept", ""))
