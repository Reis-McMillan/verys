import base64
import logging

import bcrypt
from starlette.requests import Request

from verys.models.oauth2_client import OAuthClient

logger = logging.getLogger("verys.client_auth")


def hash_client_secret(secret: str) -> str:
    return bcrypt.hashpw(secret.encode(), bcrypt.gensalt()).decode()


def verify_client_secret(secret: str, hashed: str) -> bool:
    return bcrypt.checkpw(secret.encode(), hashed.encode())


async def authenticate_client(
    request: Request,
    form_client_id: str | None = None,
    form_client_secret: str | None = None,
) -> dict | None:
    """
    Authenticate an OAuth2 client using Basic auth or POST body credentials.
    Returns the client document if authenticated, None otherwise.
    """
    client_id = None
    client_secret = None

    # Try HTTP Basic auth first
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode()
            client_id, client_secret = decoded.split(":", 1)
        except Exception:
            logger.warning("Failed to decode Basic auth header")
            return None
    else:
        # Fall back to POST body
        client_id = form_client_id
        client_secret = form_client_secret

    if not client_id:
        return None

    client = await OAuthClient.get(client_id=client_id)
    if not client:
        logger.warning("Client not found: %s", client_id)
        return None

    # Public clients (PKCE-only) don't need a secret
    if client["is_public"] or client["token_endpoint_auth_method"] == "none":
        return client

    # Confidential clients must provide a valid secret
    if not client_secret or not client["client_secret_hash"]:
        logger.warning("Missing client secret for: %s", client_id)
        return None

    if not verify_client_secret(client_secret, client["client_secret_hash"]):
        logger.warning("Invalid client secret for: %s", client_id)
        return None

    return client
