import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from pydantic import BaseModel, EmailStr
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from verys.models.identity import Identity
from verys.models.oauth2_session import OAuth2Session
from verys.models.oauth2_client import OAuthClient
from verys.config import config
from verys.modules.http import json_error, json_message, check_body
from verys.routes.verification import send_verification_email

logger = logging.getLogger("verys.registration")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


class RegistrationBody(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    oauth2_session_id: str | None = None


async def show_registration(request: Request):
    email = request.query_params.get("email")
    oauth2_session = request.query_params.get("oauth2_session")

    client_name = ""
    if oauth2_session:
        oauth2_sess = await OAuth2Session.get(session_id=oauth2_session)
        if oauth2_sess and not OAuth2Session.is_expired(oauth2_sess):
            client = await OAuthClient.get(client_id=oauth2_sess["client_id"])
            if client:
                client_name = client["client_name"]

    return templates.TemplateResponse(request, "registration.html", {
        "client_name": client_name,
        "issuer": config.ISSUER,
        "oauth2_session_id": oauth2_session or "",
        "email": email or "",
    })


async def register(request: Request):
    body, err = await check_body(request, RegistrationBody)
    if err:
        return err

    # If an OAuth2 session was passed through, validate it up-front so the
    # caller learns immediately if the flow has expired and can restart cleanly.
    if body.oauth2_session_id:
        oauth2_sess = await OAuth2Session.get(session_id=body.oauth2_session_id)
        if not oauth2_sess or OAuth2Session.is_expired(oauth2_sess):
            return json_error(
                "OAuth2 session is invalid or expired. Restart the sign-in flow."
            )

    try:
        expiry_dt = datetime.now(tz=timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)
        identity = await Identity.upsert({
            "first_name": body.first_name,
            "last_name": body.last_name,
            "email": body.email,
            "auth_key": Identity.make_auth_key(),
            "expires": expiry_dt,
        })
    except DuplicateKeyError:
        logger.warning("Failed to create identity for %s... identity already exists", body.email)
        return json_error("An account already exists for this email.")

    if email_err := await send_verification_email(identity["email"]):
        return email_err

    payload = {"email": identity["email"]}
    if body.oauth2_session_id:
        payload["oauth2_session_id"] = body.oauth2_session_id

    return json_message(
        "Registration complete. Check your email for a verification code.",
        status_code=201,
        **payload,
    )


routes = [
    Route("/register/", show_registration, methods=["GET"]),
    Route("/register/", register, methods=["POST"]),
]
