"""Link an identity to an external provider and serve the resulting tokens.

Linking is driven by the client: when a client holds a scope fulfilled by an
external provider and Verys has no usable token for it (no token listed by
``GET /federation/tokens``, or ``reauthorization_required`` from
``GET /federation/{token_id}``), the client sends the user's browser to
``GET /federation/initiate``. The OAuth2 authorize endpoint never starts
federation on the client's behalf.
"""
import logging
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route

from verys.config import config
from verys.models.external_provider import ExternalProvider
from verys.models.external_token import ExternalToken
from verys.models.federation_session import FederationSession
from verys.models.oauth2_client import OAuthClient
from verys.models.scope import Scope
from verys.modules.browser_auth import get_browser_identity
from verys.modules.http import json_error, json_message, require_query

logger = logging.getLogger("verys.federation")


async def _scoped_providers(scopes: list[str]) -> set[str]:
    provider_ids = set()
    for s_name in scopes:
        scope = await Scope.get(name=s_name)
        if scope and scope["provider_id"]:
            provider_ids.add(scope["provider_id"])
    return provider_ids


def _serialize_token(t: dict) -> dict:
    expires_at = t.get("expires_at")
    return {
        "token_id": t["id"],
        "provider_id": t["provider_id"],
        "subject": t["subject"],
        "access_token": t["access_token"],
        "token_type": t["token_type"],
        "expires_at": expires_at.isoformat() if expires_at else None,
        "email": t["email"],
    }


def _with_params(url: str, params: dict) -> str:
    """Append query params to ``url``, preserving any existing query string."""
    parts = urlparse(url)
    query = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunparse(parts._replace(query=urlencode(query)))


async def initiate_federation(request: Request):
    """Start the upstream OAuth2 flow with an external provider.

    Requires the user's browser session. ``client_id`` and ``redirect_uri``
    are optional but must be given together; the redirect URI must be one the
    client has registered, and the browser is sent back there when the
    upstream flow completes (with ``provider_id``, plus ``error`` and
    ``error_description`` on failure). Without them the callback ends in a
    JSON response.
    """
    if err := require_query(request, "provider_id"):
        return err
    provider_id = request.query_params.get("provider_id")
    client_id = request.query_params.get("client_id")
    redirect_uri = request.query_params.get("redirect_uri")

    identity = await get_browser_identity(request)
    if not identity:
        return json_error("Not authenticated", status_code=401)
    identity_id = identity["id"]

    if bool(client_id) != bool(redirect_uri):
        return json_error("client_id and redirect_uri must be provided together")
    if redirect_uri:
        client = await OAuthClient.get(client_id=client_id)
        if not client:
            return json_error("Invalid client_id")
        if redirect_uri not in client["redirect_uris"]:
            return json_error("Invalid redirect_uri")

    provider = await ExternalProvider.get(provider_id=provider_id)
    if not provider or not provider["enabled"]:
        return json_error("Provider not found or disabled", status_code=404)

    provider_scopes = set(provider["scopes"] or [])
    if not provider_scopes:
        return json_error("No scopes configured for this provider")

    fed_session = await FederationSession.upsert({
        "identity_id": identity_id,
        "provider_id": provider_id,
        "redirect_uri": redirect_uri,
    })

    callback_uri = f"{config.ISSUER}/federation/callback/{provider_id}"
    params = {
        "client_id": provider["client_id"],
        "redirect_uri": callback_uri,
        "response_type": "code",
        "scope": " ".join(sorted(provider_scopes)),
        "state": fed_session["session_id"],
        "access_type": "offline",
        "prompt": "consent",
    }

    redirect_url = f"{provider['authorization_endpoint']}?{urlencode(params)}"
    logger.info("Federation initiated: identity %s -> %s", identity_id, provider_id)
    return RedirectResponse(url=redirect_url, status_code=302)


async def federation_callback(request: Request):
    """Receive callback from upstream provider and exchange code for tokens."""
    if err := require_query(request, "state"):
        return err
    provider_id = request.path_params["provider_id"]
    code = request.query_params.get("code")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")
    state = request.query_params.get("state")

    fed_session = await FederationSession.get(session_id=state)
    if not fed_session or FederationSession.is_expired(fed_session):
        return json_error("Invalid or expired federation session")

    if fed_session["provider_id"] != provider_id:
        return json_error("Provider mismatch")

    identity_id = fed_session["identity_id"]
    client_redirect_uri = fed_session["redirect_uri"]

    # Handle error from upstream provider (user cancelled, no account, etc.)
    if error is not None:
        logger.warning(
            "Federation error from %s for identity %s: %s - %s",
            provider_id, identity_id, error, error_description,
        )
        await FederationSession.delete(session_id=state)

        description = error_description or f"Upstream provider {provider_id} returned: {error}"
        if client_redirect_uri:
            return RedirectResponse(
                url=_with_params(client_redirect_uri, {
                    "error": "federation_failed",
                    "error_description": description,
                    "provider_id": provider_id,
                }),
                status_code=302,
            )

        return json_error(
            "federation_failed",
            error_description=description,
            provider_id=provider_id,
        )

    if not code:
        return json_error("Missing authorization code from provider")

    provider = await ExternalProvider.get(provider_id=provider_id)
    if not provider:
        return json_error("Provider not found", status_code=404)

    callback_uri = f"{config.ISSUER}/federation/callback/{provider_id}"
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            provider["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback_uri,
                "client_id": provider["client_id"],
                "client_secret": provider["client_secret"],
            },
            headers={"Accept": "application/json"},
        )

    if token_response.status_code != 200:
        logger.error(
            "Token exchange failed for identity %s with %s: %s",
            identity_id, provider_id, token_response.text,
        )
        return json_error("Failed to exchange code with upstream provider", status_code=502)

    token_data = token_response.json()
    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    expires_in = token_data.get("expires_in")
    token_type = token_data.get("token_type", "Bearer")
    scope_str = token_data.get("scope", "")

    if not access_token:
        return json_error("No access token in upstream response", status_code=502)

    if not provider["userinfo_endpoint"]:
        return json_error("Provider has no userinfo endpoint configured", status_code=502)

    async with httpx.AsyncClient() as userinfo_client:
        userinfo_response = await userinfo_client.get(
            provider["userinfo_endpoint"],
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if userinfo_response.status_code != 200:
        logger.error(
            "Userinfo request failed for identity %s from %s: %s",
            identity_id, provider_id, userinfo_response.text,
        )
        return json_error("Failed to fetch userinfo from upstream provider", status_code=502)

    userinfo = userinfo_response.json()
    logger.info(
        "Successfully retrieved userinfo from provider %s for %s.",
        provider_id, identity_id,
    )

    subject = userinfo.get("sub")
    if not subject:
        return json_error("Userinfo response missing sub claim", status_code=502)

    email = userinfo.get("email")
    if not email:
        return json_error("Userinfo response missing email claim", status_code=502)

    expires_at = None
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    # Merge onto any existing token for (identity, provider, subject) so the
    # token id and created_at survive re-linking.
    existing = await ExternalToken.get(
        identity_id=identity_id, provider_id=provider_id, subject=subject
    )
    await ExternalToken.upsert({
        **(existing or {}),
        "identity_id": identity_id,
        "provider_id": provider_id,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": token_type,
        "expires_at": expires_at,
        "scopes_granted": scope_str.split() if scope_str else [],
        "subject": subject,
        "email": email,
        "updated_at": datetime.now(timezone.utc),
    })

    logger.info(
        "External tokens stored for identity %s from %s",
        identity_id, provider_id,
    )

    await FederationSession.delete(session_id=state)

    if client_redirect_uri:
        return RedirectResponse(
            url=_with_params(client_redirect_uri, {"provider_id": provider_id}),
            status_code=302,
        )

    return json_message("Federation complete", provider=provider_id)


async def get_external_tokens(request: Request):
    """List external providers the user has linked tokens for."""
    identity_id = request.user.id
    tokens: list[dict] = []
    provider_ids = await _scoped_providers(request.user.token_scopes)
    for pid in provider_ids:
        tokens.extend(await ExternalToken.all(identity_id=identity_id, provider_id=pid))
    refreshed = []
    for t in tokens:
        checked = await _token_check(t)
        if checked:
            refreshed.append(checked)
    return json_message(
        "External tokens retrieved.",
        tokens=[_serialize_token(t) for t in refreshed if t],
    )


async def get_user_external_tokens(request: Request):
    if not request.user.is_admin:
        return json_error("Not authorized to perform this action.", status_code=403)
    identity_id = str(request.path_params["identity_id"])
    tokens = await ExternalToken.all(identity_id=identity_id)
    refreshed = []
    for t in tokens:
        checked = await _token_check(t)
        if checked:
            refreshed.append(checked)
    return json_message(
        "External tokens retrieved.",
        tokens=[_serialize_token(t) for t in refreshed if t],
    )


async def get_external_token(request: Request):
    """Serve external access tokens to downstream clients.

    Requires a valid Bearer JWT. Returns only the access token, never the refresh token.
    Automatically refreshes expired tokens if a refresh token is available.
    """
    token_id = str(request.path_params["token_id"])
    identity_id = request.user.id
    scoped_providers = await _scoped_providers(request.user.token_scopes)

    ext_token = await ExternalToken.get(id=token_id)
    if not ext_token:
        return json_error("External token not found", status_code=404)
    if ext_token["identity_id"] != identity_id and not request.user.is_admin:
        return json_error("Unauthorized to perform this action.", status_code=403)
    if ext_token["provider_id"] not in scoped_providers and not request.user.is_admin:
        return json_error("Access not granted for this token.", status_code=403)

    ext_token_pid = ext_token["provider_id"]
    ext_token = await _token_check(ext_token)
    if not ext_token:
        return json_error(
            "reauthorization_required",
            status_code=401,
            headers={"Cache-Control": "no-store"},
            error_description="External token refresh failed. User must re-authorize with the provider.",
            provider_id=ext_token_pid,
        )

    return json_message(
        "External token retrieved.",
        headers={"Cache-Control": "no-store"},
        **_serialize_token(ext_token),
    )


async def _token_check(ext_token: dict) -> dict | None:
    if ExternalToken.is_expired(ext_token) and ext_token["refresh_token"]:
        refreshed = await _refresh_external_token(ext_token)
        if not refreshed:
            # Upstream rejected the refresh token — delete stale record
            await ExternalToken.delete(id=ext_token["id"])
            return None
        return refreshed
    return ext_token


async def _refresh_external_token(ext_token: dict) -> dict | None:
    """Refresh an expired external access token using the stored refresh token."""
    provider = await ExternalProvider.get(provider_id=ext_token["provider_id"])
    if not provider:
        return None

    refresh_token = ext_token["refresh_token"]
    if not refresh_token:
        return None

    async with httpx.AsyncClient() as client:
        response = await client.post(
            provider["token_endpoint"],
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": provider["client_id"],
                "client_secret": provider["client_secret"],
            },
            headers={"Accept": "application/json"},
        )

    if response.status_code != 200:
        logger.error(
            "External token refresh failed for identity %s from %s: %s",
            ext_token["identity_id"], ext_token["provider_id"], response.text,
        )
        return None

    token_data = response.json()
    new_access_token = token_data.get("access_token")
    if not new_access_token:
        return None

    expires_at = None
    expires_in = token_data.get("expires_in")
    if expires_in:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=int(expires_in))

    ext_token["access_token"] = new_access_token
    ext_token["refresh_token"] = token_data.get("refresh_token", refresh_token)
    ext_token["token_type"] = token_data.get("token_type", "Bearer")
    ext_token["expires_at"] = expires_at
    ext_token["updated_at"] = datetime.now(timezone.utc)
    return await ExternalToken.upsert(ext_token)


async def delete_external_token(request: Request):
    token_id = str(request.path_params["token_id"])
    identity_id = request.user.id
    scoped_providers = await _scoped_providers(request.user.token_scopes)
    ext_token = await ExternalToken.get(id=token_id)

    if not ext_token:
        return json_error("External token not found.", status_code=404)
    if ext_token["identity_id"] != identity_id and not request.user.is_admin:
        return json_error("Unauthorized to perform this action.", status_code=403)
    if ext_token["provider_id"] not in scoped_providers and not request.user.is_admin:
        return json_error("Access not granted for this token.", status_code=403)

    await ExternalToken.delete(id=token_id)

    return json_message("External token deleted.")


routes = [
    Route("/federation/initiate", initiate_federation, methods=["GET"]),
    Route("/federation/callback/{provider_id}", federation_callback, methods=["GET"]),
    Route("/federation/tokens", get_external_tokens, methods=["GET"]),
    Route("/federation/{identity_id:uuid}/tokens", get_user_external_tokens, methods=["GET"]),
    Route("/federation/{token_id:uuid}", get_external_token, methods=["GET"]),
    Route("/federation/{token_id:uuid}", delete_external_token, methods=["DELETE"]),
]
