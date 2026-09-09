import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote

from pydantic import BaseModel, ValidationError
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request
from starlette.routing import Route

from verys.config import config
from verys.models.identity import Identity
from verys.modules.email import normalize_email
from verys.modules.http import json_error, json_message, check_body, require_query

logger = logging.getLogger("verys.identity")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _serialize(identity: dict) -> dict:
    return {
        "id": identity["id"],
        "first_name": identity["first_name"],
        "last_name": identity["last_name"],
        "email": identity["email"],
        "email_verified": identity["email_verified"],
        "expires": _iso(identity.get("expires")),
        "origination": _iso(identity.get("origination")),
        "closed": identity["closed"],
        "last_auth_time": _iso(identity.get("last_auth_time")),
    }


def _forbidden(request: Request, action: str):
    logger.warning("Forbidden: %s tried to %s", request.user.email, action)
    return json_error("Not authorized to perform this action.", status_code=403)


async def get_all_identities(request: Request):
    if not request.user.is_admin:
        return _forbidden(request, "list all identities")
    identities = [_serialize(i) for i in await Identity.all()]
    return json_message("Identities retrieved.", identities=identities)


async def create_identity(request: Request):
    if not request.user.is_admin:
        return _forbidden(request, "create identity")
    if err := require_query(request, "email"):
        return err

    email = request.query_params.get("email")
    first_name = request.query_params.get("first_name", "")
    last_name = request.query_params.get("last_name", "")
    expires_raw = request.query_params.get("expires")
    if expires_raw:
        try:
            expires = datetime.fromisoformat(expires_raw)
        except ValueError:
            return json_error("Invalid 'expires' datetime.")
    else:
        expires = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)

    try:
        new_id = await Identity.upsert({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "auth_key": Identity.make_auth_key(),
            "expires": expires,
        })
    except DuplicateKeyError:
        logger.warning("Identity creation failed: duplicate email %s", email)
        return json_error("An account already exists for this email.", status_code=400)
    except ValidationError as e:
        logger.warning("Identity creation failed: validation error for %s - %s", email, e)
        return json_error(str(e), status_code=400)

    url_safe_email = quote(new_id["email"])
    logger.info("Identity created: %s by %s", email, request.user.email)
    return json_message(
        "Identity created.",
        status_code=201,
        headers={"Location": f"/identity/{url_safe_email}"},
        email=new_id["email"],
    )


async def get_identity(request: Request):
    if not request.user.is_admin:
        return _forbidden(request, f"get identity {request.path_params['email']}")
    email = request.path_params["email"]
    r = await Identity.get(email=normalize_email(email), closed=False)
    if not r:
        logger.warning("Identity not found: %s (admin lookup)", email)
        return json_error("Identity not found", status_code=404)
    return json_message("Identity retrieved.", **_serialize(r))


class IdentityUpdate(BaseModel):
    new_email: Optional[str] = None
    new_key: Optional[str] = None
    new_expires: Optional[datetime] = None


async def update_identity(request: Request):
    if not request.user.is_admin:
        return _forbidden(request, f"update identity {request.path_params['email']}")
    update, err = await check_body(request, IdentityUpdate)
    if err:
        return err

    email = request.path_params["email"]
    identity = await Identity.get(email=normalize_email(email), closed=False)
    if not identity:
        logger.warning("Identity update failed: %s not found", email)
        return json_error("No Identity found.", status_code=404)

    if update.new_email:
        identity["email"] = update.new_email
    if update.new_key:
        identity["auth_key"] = update.new_key
    if update.new_expires:
        identity["expires"] = update.new_expires

    try:
        await Identity.upsert(identity)
    except ValidationError as e:
        logger.warning("Identity update failed: validation error for %s - %s", email, e)
        return json_error(str(e), status_code=400)
    except DuplicateKeyError:
        logger.warning("Identity update failed: duplicate email %s", update.new_email)
        return json_error("An account already exists for this email.", status_code=400)

    url_safe_email = quote(email)
    logger.info("Identity updated: %s by %s", email, request.user.email)
    return json_message(
        "Identity updated.",
        status_code=201,
        headers={"Location": f"/identity/{url_safe_email}"},
    )


async def delete_identity(request: Request):
    if not request.user.is_admin:
        return _forbidden(request, f"delete identity {request.path_params['email']}")
    email = request.path_params["email"]
    identity = await Identity.get(email=normalize_email(email), closed=False)
    if not identity:
        logger.warning("Identity delete failed: %s not found", email)
        return json_error("Identity not found", status_code=404)

    identity["closed"] = True
    await Identity.upsert(identity)

    logger.info("Identity deleted: %s by %s", email, request.user.email)
    return json_message("Identity deleted.")


async def _rotate_auth_key(identity: dict) -> None:
    """Invalidate the identity's browser session by issuing a new auth key."""
    identity["auth_key"] = Identity.make_auth_key()
    await Identity.upsert(identity)


async def logout(request: Request):
    logout_target = request.user.email
    existing = await Identity.get(email=logout_target, closed=False)
    if existing:
        await _rotate_auth_key(existing)
    logger.info("Logout: %s", logout_target)
    return json_message("Logged out.", status_code=201)


async def logout_identity(request: Request):
    if not request.user.is_admin:
        return _forbidden(request, f"logout identity {request.path_params['id']}")
    id = request.path_params["id"]
    existing = await Identity.get(id=id, closed=False)
    if not existing:
        logger.warning("Admin logout failed: identity %s not found", id)
        return json_error("Identity not found", status_code=404)

    await _rotate_auth_key(existing)
    logger.info("Admin logout: %s by %s", id, request.user.email)
    return json_message("Logged out.", status_code=201)


routes = [
    Route("/identity", get_all_identities, methods=["GET"]),
    Route("/identity", create_identity, methods=["POST"]),
    Route("/identity/logout", logout, methods=["POST"]),
    Route("/identity/{id}/logout", logout_identity, methods=["POST"]),
    Route("/identity/{email}", get_identity, methods=["GET"]),
    Route("/identity/{email}", update_identity, methods=["PUT"]),
    Route("/identity/{email}", delete_identity, methods=["DELETE"]),
]
