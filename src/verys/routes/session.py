import logging
from pathlib import Path

import jwt as pyjwt
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from verys.config import config
from verys.middleware.authenticated import parse_subject
from verys.models.oauth2_client import OAuthClient
from verys.models.refresh_token import RefreshToken
from verys.modules.http import json_message
from verys.modules.jwt import get_public_key_pem

logger = logging.getLogger("verys.session")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


async def revoke_refresh_tokens(identity_id: str, client_id: str) -> int:
    """Revoke every live refresh token issued to ``client_id`` for the identity."""
    tokens = await RefreshToken.all(identity_id=identity_id, client_id=client_id, revoked=False)
    for rt in tokens:
        rt["revoked"] = True
        await RefreshToken.upsert(rt)
    return len(tokens)


async def end_session(request: Request):
    id_token_hint = request.query_params.get("id_token_hint")
    post_logout_redirect_uri = request.query_params.get("post_logout_redirect_uri")
    state = request.query_params.get("state")

    # Try to identify user from id_token_hint
    identity_id = None
    client_id = None
    if id_token_hint:
        try:
            public_key_pem = get_public_key_pem()
            decoded = pyjwt.decode(
                id_token_hint,
                public_key_pem,
                algorithms=["EdDSA"],
                options={"verify_aud": False, "verify_exp": False},
            )
            identity_id = parse_subject(decoded.get("sub"))
            client_id = decoded.get("aud")
        except pyjwt.InvalidTokenError:
            pass

    # Revoke refresh tokens if we identified the user
    if identity_id and client_id:
        await revoke_refresh_tokens(identity_id, client_id)
        logger.info("Revoked refresh tokens for identity %s (client: %s)", identity_id, client_id)

    response = None
    if post_logout_redirect_uri and client_id:
        client = await OAuthClient.get(client_id=client_id)
        if client and post_logout_redirect_uri in client["redirect_uris"]:
            url = post_logout_redirect_uri
            if state:
                url = f"{url}?state={state}"
            response = RedirectResponse(url=url, status_code=302)

    if response is None:
        response = templates.TemplateResponse(request, "logout.html", {})

    # Clear cookies
    response.delete_cookie(key=config.ENCRYPT_COOKIE_NAME, path="/")
    response.delete_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", path="/")

    logger.info("Session ended for identity %s", identity_id or "unknown")
    return response


async def revoke_token(request: Request):
    form = await request.form()
    token_value = form.get("token")
    if token_value:
        rt = await RefreshToken.get(token=token_value)
        if rt:
            rt["revoked"] = True
            await RefreshToken.upsert(rt)
            logger.info("Token revoked for identity %s", rt["identity_id"])

    # Per RFC 7009, always return 200 even if token not found
    return json_message("Token revoked.")


routes = [
    Route("/end-session", end_session, methods=["GET"]),
    Route("/token/revoke", revoke_token, methods=["POST"]),
]
