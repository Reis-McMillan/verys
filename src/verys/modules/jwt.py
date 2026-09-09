import base64
import hashlib
import json
import jwt
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.serialization import load_pem_private_key, Encoding, PublicFormat

from verys.config import config

_private_key = None
_kid = None


def _get_private_key():
    global _private_key
    if _private_key is None:
        jwt_private_key = getattr(config, 'JWT_PRIVATE_KEY', None)
        if jwt_private_key:
            pem_bytes = jwt_private_key.encode('utf-8')
            _private_key = load_pem_private_key(pem_bytes, password=None)
        else:
            raise ValueError('JWT_PRIVATE_KEY is not set.')
    return _private_key


def _get_kid() -> str:
    """Compute a deterministic key ID from the JWK thumbprint (RFC 7638)."""
    global _kid
    if _kid is None:
        public_key = _get_private_key().public_key()
        raw = public_key.public_bytes_raw()
        x = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        # RFC 7638: canonical JSON of required JWK members, sorted
        thumbprint_input = json.dumps(
            {"crv": "Ed25519", "kty": "OKP", "x": x},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        digest = hashlib.sha256(thumbprint_input).digest()
        _kid = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return _kid


def get_public_key_pem() -> str:
    return _get_private_key().public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _compute_at_hash(access_token: str) -> str:
    """Compute at_hash: left half of SHA-256 of the access token, base64url-encoded."""
    digest = hashlib.sha512(access_token.encode("ascii")).digest()
    left_half = digest[: len(digest) // 2]
    return base64.urlsafe_b64encode(left_half).rstrip(b"=").decode()


def create_signed_jwt(
    identity: dict,
    scopes: list[str],
    audience: str = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.ISSUER,
        "sub": str(identity["id"]),
        "aud": config.ISSUER if not audience else audience,
        "roles": [r["name"] for r in identity["roles"]],
        "iat": now,
        "exp": now + timedelta(seconds=config.JWT_EXPIRY),
        "scopes": scopes,
    }
    return jwt.encode(
        payload,
        _get_private_key(),
        algorithm="EdDSA",
        headers={"kid": _get_kid()},
    )


def create_id_token(
    identity: dict,
    client_id: str,
    client_scopes: list[str],
    nonce: str | None,
    auth_time: datetime,
    access_token: str | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "iss": config.ISSUER,
        "sub": str(identity["id"]),
        "aud": client_id,
        "exp": now + timedelta(seconds=config.ID_TOKEN_EXPIRY),
        "iat": now,
        "auth_time": int(auth_time.timestamp()),
    }

    scope_set = set(client_scopes)

    if "email" in scope_set:
        payload["email"] = identity["email"]
        payload["email_verified"] = identity["email_verified"]

    if "profile" in scope_set:
        payload["given_name"] = identity["first_name"]
        payload["family_name"] = identity["last_name"]
        payload["name"] = f"{identity['first_name']} {identity['last_name']}"
        origination = identity.get("origination")
        payload["origination"] = origination.isoformat() if origination else None

    if nonce:
        payload["nonce"] = nonce
    if access_token:
        payload["at_hash"] = _compute_at_hash(access_token)
    if identity["roles"]:
        payload["roles"] = [r["name"] for r in identity["roles"]]

    return jwt.encode(
        payload,
        _get_private_key(),
        algorithm="EdDSA",
        headers={"kid": _get_kid()},
    )
