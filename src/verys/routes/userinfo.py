import logging

import jwt as pyjwt
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from verys.config import config
from verys.middleware.authenticated import parse_subject
from verys.models.identity import Identity
from verys.modules.http import json_error
from verys.modules.jwt import get_public_key_pem

logger = logging.getLogger("verys.userinfo")


async def userinfo(request: Request):
    # Accept token from Authorization header or POST body (access_token field)
    token = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(None, 1)[1]
    elif request.method == "POST":
        form = await request.form()
        token = form.get("access_token")

    if not token:
        return json_error("Missing access token", status_code=401)

    try:
        decoded = pyjwt.decode(
            token,
            get_public_key_pem(),
            algorithms=["EdDSA"],
            audience=config.ISSUER,
        )
    except pyjwt.ExpiredSignatureError as e:
        logger.warning("Expired token getting user info: %s", e)
        return json_error("Token expired", status_code=401)
    except pyjwt.InvalidTokenError as e:
        logger.warning("Invalid token getting user info: %s", e, exc_info=True)
        return json_error("Invalid token", status_code=401)

    sub = decoded.get("sub")
    if not sub:
        logger.warning("Subject missing while getting user info", exc_info=True)
        return json_error("Invalid token: missing subject", status_code=401)

    identity_id = parse_subject(sub)
    if identity_id is None:
        logger.warning("Invalid subject data type while getting user info: %s", sub)
        return json_error("Invalid token: bad subject", status_code=401)

    identity = await Identity.get(id=identity_id, closed=False)
    if not identity:
        return json_error("Identity not found", status_code=401)

    token_scopes = set(decoded.get("scopes") or [])

    claims = {"sub": identity["id"]}

    if "email" in token_scopes:
        claims["email"] = identity["email"]
        claims["email_verified"] = identity["email_verified"]

    if "profile" in token_scopes:
        claims["given_name"] = identity["first_name"]
        claims["family_name"] = identity["last_name"]
        claims["name"] = f"{identity['first_name']} {identity['last_name']}"
        origination = identity.get("origination")
        claims["origination"] = origination.isoformat() if origination else None

    roles = decoded.get("roles")
    if roles:
        claims["roles"] = roles

    return JSONResponse(claims)


routes = [
    Route("/userinfo", userinfo, methods=["GET", "POST"]),
]
