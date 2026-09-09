import logging
import uuid

import jwt
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse

from verys.config import config
from verys.models.identity import Identity
from verys.modules.jwt import get_public_key_pem

logger = logging.getLogger("verys.auth")


class User(SimpleUser):
    """Authenticated principal attached to ``request.user``."""

    def __init__(self, *, id: str, email: str, roles: set[str], token_scopes: list[str]):
        super().__init__(email)
        self.id = id
        self.email = email
        self.roles = set(roles)
        self.token_scopes = token_scopes

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles


_PUBLIC_FEDERATION_PREFIXES = ("/federation/initiate", "/federation/callback")


def _requires_auth(method: str, path: str) -> bool:
    """Whether the Bearer backend must enforce a valid token for this request.

    Routes that manage their own credentials (client auth on /token, browser
    cookies, self-validated Bearer on /userinfo) or are public return False;
    their handlers control their own auth responses.
    """
    if method == "OPTIONS":
        return False
    if path.startswith(("/identity", "/clients", "/scopes", "/roles")):
        return True
    if path.startswith("/providers"):
        # Reads are public; writes require admin (enforced in-handler).
        return method not in ("GET", "HEAD")
    if path.startswith("/federation"):
        if path.startswith(_PUBLIC_FEDERATION_PREFIXES):
            return False
        # /federation/tokens, /federation/{id}/tokens, /federation/{token_id}
        return True
    return False


def parse_subject(sub) -> str | None:
    """Return the identity id encoded in a JWT ``sub`` claim, or ``None``."""
    try:
        return str(uuid.UUID(str(sub)))
    except (TypeError, ValueError):
        return None


class BearerToken(AuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection):
        if not _requires_auth(conn.scope["method"], conn.url.path):
            return None

        auth = conn.headers.get("Authorization")
        if not auth:
            raise AuthenticationError("Authorization header required.")

        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise AuthenticationError("Bad authorization header.")

        token = parts[1]
        try:
            decoded = jwt.decode(
                token,
                get_public_key_pem(),
                algorithms=["EdDSA"],
                audience=config.ISSUER,
            )
        except jwt.InvalidTokenError as e:
            logger.warning("Auth failed: invalid JWT token - %s", e)
            raise AuthenticationError("Not authenticated")

        sub = decoded.get("sub")
        if not sub:
            logger.warning("Auth failed: JWT missing 'sub' claim")
            raise AuthenticationError("Not authenticated")

        identity_id = parse_subject(sub)
        if identity_id is None:
            logger.warning("Auth failed: 'sub' claim is not a valid identity id: %s", sub)
            raise AuthenticationError("Not authenticated")

        identity = await Identity.get(id=identity_id, closed=False)
        if not identity:
            logger.warning("Auth failed: no identity for id %s", identity_id)
            raise AuthenticationError("Not authenticated")

        user = User(
            id=identity["id"],
            email=identity["email"],
            roles={r["name"] for r in identity["roles"]},
            token_scopes=decoded.get("scopes", []),
        )

        logger.info("Authenticated %s via JWT", user.email)
        return AuthCredentials(["authenticated"]), user


def on_auth_error(conn: HTTPConnection, exc: AuthenticationError) -> JSONResponse:
    return JSONResponse(status_code=401, content={"error": str(exc)})
