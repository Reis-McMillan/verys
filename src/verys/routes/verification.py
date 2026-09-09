# routes/verification.py
import logging
from pathlib import Path
from urllib.parse import urlencode

import aiosmtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import humanize
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route

from verys.config import config
from verys.models.verification import Verification
from verys.models.identity import Identity
from verys.models.oauth2_session import OAuth2Session
from verys.modules.cookie import encrypt_cookie
from verys.modules.email import normalize_email
from verys.modules.http import json_error, json_message, require_query

logger = logging.getLogger("verys.verification")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def _cookie_opts() -> dict:
    opts = {
        "httponly": True,
        "secure": True,
        "samesite": "lax",
        "max_age": int(config.AUTHENTICATION_TTL),
        "path": "/",
    }
    if config.COOKIE_DOMAIN:
        opts["domain"] = config.COOKIE_DOMAIN
    return opts


async def _consume_code(email: str, code: int, ttl: int) -> dict | None:
    """Consume the pending verification entry. Returns it on success, or
    ``None`` if it is missing, wrong, or older than ``ttl`` seconds."""
    entry = await Verification.get(email=email, code=code)
    if entry is None:
        return None
    await Verification.delete(email=email)
    if entry["when"] < datetime.now(timezone.utc) - timedelta(seconds=ttl):
        return None
    return entry


async def verify_code(request: Request):
    if err := require_query(request, "email", "code"):
        return err
    email = normalize_email(request.query_params.get("email"))
    code = request.query_params.get("code")
    oauth2_session = request.query_params.get("oauth2_session")

    try:
        code_int = int(code)
    except ValueError as e:
        logger.warning("Verification failed: value error for %s - %s", email, e)
        return json_error(str(e), status_code=404)

    if not await _consume_code(email, code_int, config.VERIFY_TTL):
        logger.warning("Verification failed: invalid or expired code for %s", email)
        return json_error("Invalid or expired code", status_code=404)

    r = await Identity.get(email=email, closed=False)
    if not r:
        logger.warning("Verification failed: no identity for %s", email)
        return json_error("No account exists for this email", status_code=404)

    now = datetime.now(timezone.utc)
    # If the identity has expired, refresh the session key & expiry. Verification
    # renews browser sessions; email_verified, once set, stays set.
    if r["expires"] < now:
        r["auth_key"] = Identity.make_auth_key()
        r["expires"] = now + timedelta(seconds=config.AUTHENTICATION_TTL)

    r["last_auth_time"] = now
    r["email_verified"] = True
    r = await Identity.upsert(r)

    logger.info("Verification successful: %s", email)
    value, iv = encrypt_cookie(r["email"], r["auth_key"])
    cookie_opts = _cookie_opts()

    # If this verification was part of an OAuth2 flow, redirect back to /authorize
    if oauth2_session:
        oauth2_sess = await OAuth2Session.get(session_id=oauth2_session)
        if oauth2_sess and not OAuth2Session.is_expired(oauth2_sess):
            params = {
                "response_type": oauth2_sess["response_type"],
                "client_id": oauth2_sess["client_id"],
                "redirect_uri": oauth2_sess["redirect_uri"],
                "scope": oauth2_sess["scope"],
            }
            for key in ("state", "nonce", "code_challenge", "code_challenge_method"):
                if oauth2_sess.get(key):
                    params[key] = oauth2_sess[key]

            await OAuth2Session.delete(session_id=oauth2_session)

            response = RedirectResponse(url=f"/authorize?{urlencode(params)}", status_code=302)
            response.set_cookie(key=config.ENCRYPT_COOKIE_NAME, value=value, **cookie_opts)
            response.set_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", value=iv, **cookie_opts)
            logger.info("OAuth2 flow: redirecting %s back to /authorize", r["email"])
            return response

    response = json_message("Email verified.")
    response.set_cookie(key=config.ENCRYPT_COOKIE_NAME, value=value, **cookie_opts)
    response.set_cookie(key=f"{config.ENCRYPT_COOKIE_NAME}_iv", value=iv, **cookie_opts)
    logger.info("Cookie issued for %s", r["email"])
    return response


async def send_verification_email(email: str):
    """Generate a verification code for the given email and send it.

    Returns a ``JSONResponse`` (500) if the email send fails, otherwise ``None``.
    """
    email = normalize_email(email)
    vcode = Verification.make_code()

    entry = await Verification.get(email=email) or {"email": email}
    entry["code"] = vcode
    entry["when"] = datetime.now(timezone.utc)
    await Verification.upsert(entry)

    ttl_delta = timedelta(seconds=config.VERIFY_TTL)
    identity_ttl_str = humanize.precisedelta(ttl_delta, minimum_unit="minutes")

    text_template = (TEMPLATE_DIR / "verification.txt").read_text()
    html_template = (TEMPLATE_DIR / "verification.html").read_text()

    replacements = {
        "${code}": str(vcode),
        "${identity_ttl}": identity_ttl_str,
    }

    final_text = text_template
    final_html = html_template
    for placeholder, value in replacements.items():
        final_text = final_text.replace(placeholder, value)
        final_html = final_html.replace(placeholder, value)

    message = EmailMessage()
    message["Subject"] = "Verify your email address"
    message["From"] = config.VERIFY_FROM_ADDR
    message["To"] = email
    message.add_alternative(final_text, subtype="text")
    message.add_alternative(final_html, subtype="html")

    debug_addr = getattr(config, "VERIFY_DEBUG_ADDR", None)
    if debug_addr:
        message["Bcc"] = debug_addr
        recipients = [email, debug_addr]
    else:
        recipients = email

    try:
        await aiosmtplib.send(
            message,
            hostname=config.SMTP_ENDPOINT,
            port=config.SMTP_PORT,
            username=config.USERNAME_SMTP,
            password=config.PASSWORD_SMTP,
            start_tls=True,
            recipients=recipients,
        )
        entry = await Verification.get(email=email)
        if entry:
            entry["email_sent"] = datetime.now(timezone.utc)
            await Verification.upsert(entry)
        logger.info("Verification email sent to %s", email)
    except Exception as e:
        logger.error("Email send failed for %s: %s", email, e, exc_info=True)
        return json_error("Email service failed.", status_code=500)
    return None


async def handle_verification(request: Request):
    if err := require_query(request, "email"):
        return err
    email = normalize_email(request.query_params.get("email"))
    oauth2_session = request.query_params.get("oauth2_session")

    identity = await Identity.get(email=email, closed=False)
    if not identity:
        params = {"email": email}
        if oauth2_session:
            params["oauth2_session"] = oauth2_session
        logger.info("POST /verification: no identity for %s — redirecting to /register/", email)
        return RedirectResponse(url=f"/register/?{urlencode(params)}", status_code=302)

    if err := await send_verification_email(identity["email"]):
        return err
    return json_message("Verification code sent.", status_code=201)


routes = [
    Route("/verification", verify_code, methods=["GET"]),
    Route("/verification", handle_verification, methods=["POST"]),
]
