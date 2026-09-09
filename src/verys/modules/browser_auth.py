from datetime import datetime, timezone

from starlette.requests import Request

from verys.config import config
from verys.models.identity import Identity
from verys.modules.cookie import decrypt_cookie
from verys.modules.email import normalize_email


async def get_browser_identity(request: Request) -> dict | None:
    """Identify user from token/token_iv cookies during the authorize flow."""
    token = request.cookies.get(config.ENCRYPT_COOKIE_NAME)
    token_iv = request.cookies.get(f"{config.ENCRYPT_COOKIE_NAME}_iv")
    if not token or not token_iv:
        return None

    try:
        decrypted = decrypt_cookie(token, token_iv)
    except Exception:
        return None

    identity = await Identity.get(email=normalize_email(decrypted["email"]), closed=False)
    if (
        not identity
        or identity["auth_key"] != decrypted["auth_key"]
        or datetime.now(timezone.utc) > identity["expires"]
    ):
        return None

    return identity
