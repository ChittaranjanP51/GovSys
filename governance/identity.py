"""Identity governance for humans AND AI agents.

Humans
  * local mode   : built-in OIDC-style IdP (RS256 JWTs, PBKDF2 password store)
  * keycloak mode: Resource-owner login against Keycloak, tokens verified via JWKS

AI agents
  * Every agent is a workload with a SPIFFE ID (spiffe://<trust-domain>/agent/<name>).
  * The workload issuer mints short-lived JWT-SVID-style tokens bound to the human
    they act for (RFC 8693 "act" claim) and to the delegation chain. SPIRE can replace
    this issuer without changing callers: verify_agent_token() is the only consumer.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid
from functools import lru_cache
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .config import ROOT, settings

ISSUER = "https://idp.govsys.local"
WORKLOAD_ISSUER = f"spiffe://{settings.trust_domain}/issuer"
AUDIENCE = "govsys"
KEY_DIR = settings.data_dir / "keys"
USER_STORE = settings.data_dir / "idp" / "users.json"
AGENT_REGISTRY = ROOT / "infra" / "opa" / "policies" / "data.json"   # single source of truth


class AuthError(Exception):
    pass


# ----------------------------------------------------------------- keys
def _load_or_create_key(name: str) -> rsa.RSAPrivateKey:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    path = KEY_DIR / f"{name}.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return key


@lru_cache
def _idp_key():
    return _load_or_create_key("idp_signing")


@lru_cache
def _workload_key():
    return _load_or_create_key("workload_signing")


# ------------------------------------------------------- password store
def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def _check_password(password: str, stored: str) -> bool:
    _, iters, salt_b64, dk_b64 = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt_b64), int(iters))
    return hmac.compare_digest(dk, base64.b64decode(dk_b64))


def build_user_store(identities_file: Path = ROOT / "config" / "identities.json") -> None:
    """Hash the demo identities into the IdP store (called by bootstrap)."""
    users = json.loads(identities_file.read_text())["users"]
    store = {u["username"]: {k: v for k, v in u.items() if k != "password"}
             | {"password_hash": hash_password(u["password"])} for u in users}
    USER_STORE.parent.mkdir(parents=True, exist_ok=True)
    USER_STORE.write_text(json.dumps(store, indent=2))


def _directory() -> dict:
    if not USER_STORE.exists():
        raise AuthError("IdP user store missing - run scripts/bootstrap.py")
    return json.loads(USER_STORE.read_text())


def directory_status(username: str) -> str:
    """Current account status from the directory (continuous verification)."""
    if settings.identity_provider == "keycloak":
        # Keycloak refuses disabled users at login; this catches users suspended AFTER
        # their token was issued, using the HR directory mirror in iam.staff.
        from .data_governance import reader_connection
        try:
            with reader_connection() as c:
                row = c.execute("SELECT status FROM iam.staff WHERE username = %s", (username,)).fetchone()
        except Exception:  # noqa: BLE001 - directory unreachable => fail closed
            return "unverifiable (directory unavailable)"
        return row["status"] if row else "not in staff directory"
    return _directory().get(username, {}).get("status", "unknown")


# ---------------------------------------------------------- human tokens
def issue_user_token(username: str) -> str:
    """Mint a token for a directory user (no password check). Used by login() and
    by the red-team suite to simulate a stale/stolen token."""
    u = _directory()[username]
    now = int(time.time())
    claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": username, "name": u["name"],
              "department": u["department"], "roles": u["roles"], "status": u["status"],
              "typ": "human", "iat": now, "exp": now + settings.token_ttl_s, "jti": str(uuid.uuid4())}
    return jwt.encode(claims, _idp_key(), algorithm="RS256", headers={"kid": "idp-1"})


def login(username: str, password: str) -> str:
    if settings.identity_provider == "keycloak":
        return _keycloak_login(username, password)
    u = _directory().get(username)
    if not u or not _check_password(password, u["password_hash"]):
        raise AuthError("invalid username or password")
    if u["status"] != "active":
        raise AuthError(f"account '{username}' is {u['status']}")
    return issue_user_token(username)


def verify_user_token(token: str) -> dict:
    """Verify signature, issuer, audience, expiry and current account status."""
    if not token:
        raise AuthError("no bearer token presented")
    if settings.identity_provider == "keycloak":
        return _keycloak_verify(token)
    try:
        claims = jwt.decode(token, _idp_key().public_key(), algorithms=["RS256"],
                            audience=AUDIENCE, issuer=ISSUER)
    except jwt.PyJWTError as e:
        raise AuthError(f"token rejected: {e}") from e
    status = directory_status(claims["sub"])
    if status != "active":
        raise AuthError(f"account '{claims['sub']}' is {status} in the directory")
    claims["status"] = status
    return claims


# -------------------------------------------------------------- Keycloak
def _kc_base() -> str:
    return f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"


def _keycloak_login(username: str, password: str) -> str:
    r = httpx.post(f"{_kc_base()}/protocol/openid-connect/token", timeout=10, data={
        "grant_type": "password", "client_id": settings.keycloak_client_id,
        "username": username, "password": password, "scope": "openid"})
    if r.status_code != 200:
        raise AuthError(f"Keycloak login failed: {r.json().get('error_description', r.text)}")
    return r.json()["access_token"]


@lru_cache
def _jwks_client() -> jwt.PyJWKClient:
    return jwt.PyJWKClient(f"{_kc_base()}/protocol/openid-connect/certs")


def _keycloak_verify(token: str) -> dict:
    try:
        key = _jwks_client().get_signing_key_from_jwt(token).key
        c = jwt.decode(token, key, algorithms=["RS256"], issuer=_kc_base(),
                       options={"verify_aud": False})
    except jwt.PyJWTError as e:
        raise AuthError(f"Keycloak token rejected: {e}") from e
    known = set(_registry()["roles"])
    sub = c.get("preferred_username", c["sub"])
    status = directory_status(sub)
    if status != "active":
        raise AuthError(f"account '{sub}' is {status} in the directory")
    return {"sub": sub, "name": c.get("name", ""),
            "roles": [r for r in c.get("realm_access", {}).get("roles", []) if r in known],
            "status": status, "typ": "human", "iss": c["iss"], "exp": c["exp"]}


def keycloak_healthy() -> bool:
    try:
        return httpx.get(f"{_kc_base()}/.well-known/openid-configuration", timeout=3).status_code == 200
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------- agent tokens
def _registry() -> dict:
    return json.loads(AGENT_REGISTRY.read_text())["govsys"]


def spiffe_id(agent: str) -> str:
    return f"spiffe://{settings.trust_domain}/agent/{agent}"


def issue_agent_token(agent: str, user_claims: dict, chain: list[str]) -> str:
    """Mint a short-lived workload token for `agent`, bound to the human principal."""
    reg = _registry()["agents"]
    if agent not in reg:
        raise AuthError(f"agent '{agent}' is not registered with the workload issuer")
    now = int(time.time())
    claims = {"iss": WORKLOAD_ISSUER, "aud": AUDIENCE, "sub": reg[agent]["spiffe_id"],
              "agent": agent, "act": {"sub": user_claims["sub"]}, "chain": chain + [agent],
              "typ": "agent", "iat": now, "exp": now + settings.agent_token_ttl_s,
              "jti": str(uuid.uuid4())}
    return jwt.encode(claims, _workload_key(), algorithm="RS256", headers={"kid": "workload-1"})


def verify_agent_token(token: str, expected_agent: str) -> dict:
    try:
        c = jwt.decode(token, _workload_key().public_key(), algorithms=["RS256"],
                       audience=AUDIENCE, issuer=WORKLOAD_ISSUER)
    except jwt.PyJWTError as e:
        raise AuthError(f"agent token rejected: {e}") from e
    if c.get("agent") != expected_agent:
        raise AuthError(f"token belongs to '{c.get('agent')}', not '{expected_agent}'")
    reg = _registry()["agents"].get(expected_agent)
    if not reg or reg["spiffe_id"] != c["sub"]:
        raise AuthError(f"SPIFFE ID {c['sub']} not registered for '{expected_agent}'")
    return c


def forge_agent_token(agent: str, user: str) -> str:
    """Red-team helper: a token for `agent` signed by an attacker-controlled key."""
    rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    return jwt.encode({"iss": WORKLOAD_ISSUER, "aud": AUDIENCE, "sub": spiffe_id(agent), "agent": agent,
                       "act": {"sub": user}, "chain": [agent], "typ": "agent",
                       "iat": now, "exp": now + 60}, rogue, algorithm="RS256")
