import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import jwt
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

from verys.config import config
from verys.middleware.authenticated import parse_subject
from verys.models.authorization_code import AuthorizationCode
from verys.models.consent import Consent
from verys.models.external_token import ExternalToken
from verys.models.identity import Identity
from verys.models.oauth2_client import OAuthClient
from verys.models.oauth2_session import OAuth2Session
from verys.models.refresh_token import RefreshToken
from verys.models.scope import Scope
from verys.modules.browser_auth import get_browser_identity
from verys.modules.client_auth import authenticate_client
from verys.modules.http import json_error, require_query
from verys.modules.jwt import create_id_token, create_signed_jwt, get_public_key_pem
from verys.modules.pkce import verify_code_challenge
from verys.routes.session import revoke_refresh_tokens

logger = logging.getLogger("verys.oauth2")

TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _covers_scopes(consent: dict, requested_scopes: list[str]) -> bool:
    granted = consent.get("scopes") or []
    return all(s in granted for s in requested_scopes)


def _build_error_redirect(redirect_uri: str, error: str, description: str, state: str | None = None):
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


async def _federation_scopes(scope_names: list[str]) -> dict[str, list[str]]:
    """Map provider_id -> requested scope names fulfilled by that provider."""
    federation_scopes: dict[str, list[str]] = {}
    for s in scope_names:
        scope_record = await Scope.get(name=s)
        if scope_record and scope_record["provider_id"]:
            federation_scopes.setdefault(scope_record["provider_id"], []).append(s)
    return federation_scopes


async def _find_missing_federation_provider(
    identity_id: str, federation_scopes: dict[str, list[str]]
) -> str | None:
    """Return the first federation provider missing a usable token, else None."""
    for provider_id in federation_scopes:
        tokens = await ExternalToken.all(identity_id=identity_id, provider_id=provider_id)
        if not tokens or not any(t["refresh_token"] for t in tokens):
            return provider_id
    return None


async def _redirect_to_federation(
    provider_id: str,
    scope_names: list[str],
    client_id: str,
    redirect_uri: str,
    response_type: str,
    scope: str,
    state: str | None,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> RedirectResponse:
    """Store OAuth2 session and redirect to federation initiate."""
    oauth2_session = await OAuth2Session.upsert({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    })

    params = {
        "provider_id": provider_id,
        "scope_names": " ".join(scope_names),
        "oauth2_session_id": oauth2_session["session_id"],
    }
    return RedirectResponse(url=f"/federation/initiate?{urlencode(params)}", status_code=302)


async def authorize(request: Request):
    if err := require_query(request, "response_type", "client_id", "redirect_uri", "scope"):
        return err

    q = request.query_params
    response_type = q.get("response_type")
    client_id = q.get("client_id")
    redirect_uri = q.get("redirect_uri")
    scope = q.get("scope")
    state = q.get("state")
    nonce = q.get("nonce")
    code_challenge = q.get("code_challenge")
    code_challenge_method = q.get("code_challenge_method")
    prompt = q.get("prompt")
    request_obj = q.get("request")
    request_uri = q.get("request_uri")
    max_age = None
    if q.get("max_age") is not None:
        try:
            max_age = int(q.get("max_age"))
        except ValueError:
            return json_error("Invalid max_age")

    # Validate client
    client = await OAuthClient.get(client_id=client_id)
    if not client:
        return json_error("Invalid client_id", status_code=400)

    # Validate redirect_uri (exact match required)
    if redirect_uri not in client["redirect_uris"]:
        return json_error("Invalid redirect_uri", status_code=400)

    # Reject request objects — not supported (OIDCC-3.1.2.6)
    if request_obj is not None:
        return _build_error_redirect(
            redirect_uri, "request_not_supported",
            "Request objects are not supported", state
        )
    if request_uri is not None:
        return _build_error_redirect(
            redirect_uri, "request_uri_not_supported",
            "Request URI is not supported", state
        )

    # Validate response_type
    if response_type != "code":
        return _build_error_redirect(
            redirect_uri, "unsupported_response_type",
            "Only 'code' response type is supported", state
        )

    # Parse and validate scopes
    requested_scopes = scope.split()
    if "openid" not in requested_scopes:
        return _build_error_redirect(
            redirect_uri, "invalid_scope",
            "The 'openid' scope is required", state
        )
    for s in requested_scopes:
        if s not in client["allowed_scopes"]:
            return _build_error_redirect(
                redirect_uri, "invalid_scope",
                f"Scope '{s}' is not allowed for this client", state
            )

    # Validate scopes exist in the database and partition into OIDC vs federation
    federation_scopes = {}  # provider_id -> [scope_name, ...]
    for s in requested_scopes:
        scope_record = await Scope.get(name=s)
        if not scope_record:
            return _build_error_redirect(
                redirect_uri, "invalid_scope",
                f"Unknown scope '{s}'", state
            )
        if scope_record["provider_id"]:
            federation_scopes.setdefault(scope_record["provider_id"], []).append(s)

    # Validate PKCE
    if code_challenge and code_challenge_method != "S256":
        return _build_error_redirect(
            redirect_uri, "invalid_request",
            "Only S256 code_challenge_method is supported", state
        )

    # Public clients must use PKCE
    if client["is_public"] and not code_challenge:
        return _build_error_redirect(
            redirect_uri, "invalid_request",
            "Public clients must use PKCE", state
        )

    # Parse prompt parameter
    prompt_values = set(prompt.split()) if prompt else set()

    # "none" must not be combined with other values
    if "none" in prompt_values and len(prompt_values) > 1:
        return _build_error_redirect(
            redirect_uri, "invalid_request",
            "prompt=none cannot be combined with other values", state
        )

    # Check if user is authenticated
    # prompt=login forces re-authentication — ignore existing session
    if "login" in prompt_values:
        identity = None
    else:
        identity = await get_browser_identity(request)

    # max_age: if the user's last authentication is older than max_age seconds,
    # force re-authentication (treat as if not authenticated)
    if identity and max_age is not None:
        auth_time = identity["last_auth_time"] or datetime.min.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - auth_time).total_seconds()
        if elapsed > max_age:
            identity = None

    # Unverified users must complete email verification before proceeding.
    if identity and not identity["email_verified"]:
        identity = None

    if not identity:
        if "none" in prompt_values:
            return _build_error_redirect(
                redirect_uri, "login_required",
                "User is not authenticated and prompt=none was requested", state
            )

        # Store authorize params and redirect to login
        oauth2_session = await OAuth2Session.upsert({
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": response_type,
            "scope": scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        })

        return templates.TemplateResponse(request, "login.html", {
            "oauth2_session_id": oauth2_session["session_id"],
            "client_name": client["client_name"],
            "issuer": config.ISSUER,
            "registration_uri": config.VERYS_CLIENT_REGISTRATION_URI,
        })

    # Check consent
    consent = await Consent.get(identity_id=identity["id"], client_id=client_id)
    has_consent = consent and _covers_scopes(consent, requested_scopes)

    # prompt=consent forces the consent screen even if already granted
    if has_consent and "consent" not in prompt_values:
        # Check if federation scopes need external tokens before issuing code
        missing_provider = await _find_missing_federation_provider(
            identity["id"], federation_scopes
        )
        if missing_provider:
            return await _redirect_to_federation(
                missing_provider, federation_scopes[missing_provider],
                client_id, redirect_uri, response_type, scope, state, nonce,
                code_challenge, code_challenge_method,
            )

        # Consent already granted and all external tokens present, issue code
        return await _issue_authorization_code(
            identity, client, redirect_uri,
            requested_scopes, state, nonce,
            code_challenge, code_challenge_method,
        )

    if "none" in prompt_values:
        return _build_error_redirect(
            redirect_uri, "consent_required",
            "User has not consented and prompt=none was requested", state
        )

    # Generate CSRF token for consent form
    csrf_token = secrets.token_urlsafe(32)
    # Store in an oauth2 session for validation
    oauth2_session = await OAuth2Session.upsert({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": response_type,
        "scope": scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "csrf_token": csrf_token,
    })

    # Build scope details for the consent template
    scope_details = []
    for s in requested_scopes:
        scope_record = await Scope.get(name=s)
        if scope_record:
            scope_details.append({
                "name": s,
                "description": scope_record["description"],
                "provider_id": scope_record["provider_id"],
            })
        else:
            scope_details.append({"name": s, "description": s, "provider_id": None})

    return templates.TemplateResponse(request, "consent.html", {
        "client_name": client["client_name"],
        "scopes": requested_scopes,
        "scope_details": scope_details,
        "oauth2_session_id": oauth2_session["session_id"],
        "csrf_token": csrf_token,
        "issuer": config.ISSUER,
    })


async def authorize_consent(request: Request):
    form = await request.form()
    oauth2_session_id = form.get("oauth2_session_id")
    consent_action = form.get("consent_action")
    csrf_token = form.get("csrf_token")

    # Look up session
    oauth2_session = await OAuth2Session.get(session_id=oauth2_session_id)
    if not oauth2_session or OAuth2Session.is_expired(oauth2_session):
        return json_error("Invalid or expired session", status_code=400)

    # Verify CSRF token
    if not oauth2_session["csrf_token"] or not secrets.compare_digest(
        csrf_token or "", oauth2_session["csrf_token"]
    ):
        return json_error("Invalid CSRF token", status_code=403)

    # Verify user is authenticated
    identity = await get_browser_identity(request)
    if not identity:
        return json_error("Not authenticated", status_code=401)

    redirect_uri = oauth2_session["redirect_uri"]
    state = oauth2_session["state"]

    if consent_action != "approve":
        await OAuth2Session.delete(session_id=oauth2_session_id)
        return _build_error_redirect(
            redirect_uri, "access_denied",
            "The user denied the authorization request", state
        )

    # Look up client
    client = await OAuthClient.get(client_id=oauth2_session["client_id"])
    if not client:
        return json_error("Client not found", status_code=400)

    requested_scopes = oauth2_session["scope"].split()

    # Store consent
    await Consent.upsert({
        "identity_id": identity["id"],
        "client_id": client["client_id"],
        "scopes": requested_scopes,
    })

    # Check if federation scopes need external tokens
    federation_scopes = await _federation_scopes(requested_scopes)

    missing_provider = await _find_missing_federation_provider(
        identity["id"], federation_scopes
    )
    if missing_provider:
        # Keep the session alive for the federation callback to resume
        return await _redirect_to_federation(
            missing_provider, federation_scopes[missing_provider],
            oauth2_session["client_id"], redirect_uri,
            oauth2_session["response_type"], oauth2_session["scope"], state,
            oauth2_session["nonce"], oauth2_session["code_challenge"],
            oauth2_session["code_challenge_method"],
        )

    # Clean up session
    nonce = oauth2_session["nonce"]
    code_challenge = oauth2_session["code_challenge"]
    code_challenge_method = oauth2_session["code_challenge_method"]
    await OAuth2Session.delete(session_id=oauth2_session_id)

    return await _issue_authorization_code(
        identity, client, redirect_uri,
        requested_scopes, state, nonce,
        code_challenge, code_challenge_method,
    )


async def _issue_authorization_code(
    identity: dict,
    client: dict,
    redirect_uri: str,
    scopes: list[str],
    state: str | None,
    nonce: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> RedirectResponse:
    auth_time = identity["last_auth_time"] or datetime.now(timezone.utc)

    auth_code = await AuthorizationCode.upsert({
        "client_id": client["client_id"],
        "identity_email": identity["email"],
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "auth_time": auth_time,
        "expires_at": datetime.now(timezone.utc)
        + timedelta(seconds=config.AUTHORIZATION_CODE_TTL),
    })

    params = {"code": auth_code["code"]}
    if state:
        params["state"] = state

    logger.info(
        "Authorization code issued for %s (client: %s)",
        identity["email"],
        client["client_id"],
    )
    return RedirectResponse(url=f"{redirect_uri}?{urlencode(params)}", status_code=302)


async def token_endpoint(request: Request):
    form = await request.form()
    grant_type = form.get("grant_type")
    code = form.get("code")
    redirect_uri = form.get("redirect_uri")
    client_id = form.get("client_id")
    client_secret = form.get("client_secret")
    code_verifier = form.get("code_verifier")
    refresh_token = form.get("refresh_token")
    subject_token = form.get("subject_token")
    subject_token_type = form.get("subject_token_type")
    audience = form.get("audience")

    # Authenticate client
    client = await authenticate_client(request, client_id, client_secret)
    if not client:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_client", "error_description": "Client authentication failed"},
            headers={"WWW-Authenticate": "Basic"},
        )

    if grant_type == "authorization_code":
        return await _handle_authorization_code_grant(
            client, code, redirect_uri, code_verifier
        )
    elif grant_type == "refresh_token":
        return await _handle_refresh_token_grant(client, refresh_token)
    elif grant_type == "urn:ietf:params:oauth:grant-type:token-exchange":
        return await _handle_token_exchange_grant(
            client, subject_token, subject_token_type, audience
        )
    else:
        return JSONResponse(
            status_code=400,
            content={"error": "unsupported_grant_type", "error_description": "Supported grant types: authorization_code, refresh_token, urn:ietf:params:oauth:grant-type:token-exchange"},
        )


async def _handle_authorization_code_grant(
    client: dict,
    code: str | None,
    redirect_uri: str | None,
    code_verifier: str | None,
) -> JSONResponse:
    if not code:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Code is required"},
        )

    auth_code = await AuthorizationCode.get(code=code)
    if not auth_code:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Authorization code not found"},
        )

    # Look up identity early (needed for replay handling and token issuance)
    identity = await Identity.get(email=auth_code["identity_email"], closed=False)
    if not identity:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Identity not found"},
        )

    if auth_code["used"]:
        # Potential replay attack — revoke all tokens for this authorization (RFC 6749 §4.1.2)
        logger.warning("Authorization code replay detected: %s", code)
        await revoke_refresh_tokens(identity["id"], auth_code["client_id"])
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Authorization code has already been used"},
        )

    if AuthorizationCode.is_expired(auth_code):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Authorization code has expired"},
        )

    if auth_code["client_id"] != client["client_id"]:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Client mismatch"},
        )

    if auth_code["redirect_uri"] != redirect_uri:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Redirect URI mismatch"},
        )

    # Verify PKCE
    if auth_code["code_challenge"]:
        if not code_verifier:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "error_description": "Code verifier is required"},
            )
        if not verify_code_challenge(
            code_verifier, auth_code["code_challenge"], auth_code["code_challenge_method"]
        ):
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_grant", "error_description": "Invalid code verifier"},
            )

    # Mark code as used
    auth_code["used"] = True
    await AuthorizationCode.upsert(auth_code)

    # Generate access token
    access_token = create_signed_jwt(identity, client["allowed_scopes"])

    # Generate ID token
    id_token = create_id_token(
        identity=identity,
        client_id=client["client_id"],
        client_scopes=client["allowed_scopes"],
        nonce=auth_code["nonce"],
        auth_time=auth_code["auth_time"],
        access_token=access_token,
    )

    # Generate refresh token
    rt = await RefreshToken.upsert({
        "client_id": client["client_id"],
        "identity_id": identity["id"],
        "scopes": auth_code["scopes"],
        "expires_at": identity["expires"],
    })

    logger.info("Tokens issued for %s (client: %s)", identity["email"], client["client_id"])

    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": config.JWT_EXPIRY,
            "id_token": id_token,
            "refresh_token": rt["token"],
            "scope": " ".join(auth_code["scopes"]),
        },
        headers={"Cache-Control": "no-store"},
    )


async def _handle_refresh_token_grant(
    client: dict,
    refresh_token_value: str | None,
) -> JSONResponse:
    if not refresh_token_value:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Refresh token is required"},
        )

    rt = await RefreshToken.get(token=refresh_token_value)
    if not rt:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Refresh token not found"},
        )

    if rt["revoked"] or RefreshToken.is_expired(rt):
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Refresh token is revoked or expired"},
        )

    if rt["client_id"] != client["client_id"]:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Client mismatch"},
        )

    # Look up identity
    identity = await Identity.get(id=rt["identity_id"], closed=False)
    if not identity:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Identity not found"},
        )

    # Generate new access token
    access_token = create_signed_jwt(identity, client["allowed_scopes"])

    # Generate new ID token
    auth_time = identity["last_auth_time"] or datetime.now(timezone.utc)
    id_token = create_id_token(
        identity=identity,
        client_id=client["client_id"],
        client_scopes=client["allowed_scopes"],
        nonce=None,
        auth_time=auth_time,
        access_token=access_token,
    )

    # Rotate refresh token
    new_rt = await RefreshToken.upsert({
        "client_id": client["client_id"],
        "identity_id": identity["id"],
        "scopes": rt["scopes"],
        "expires_at": identity["expires"],
    })

    rt["revoked"] = True
    rt["replaced_by"] = new_rt["token"]
    await RefreshToken.upsert(rt)

    logger.info("Tokens refreshed for %s (client: %s)", identity["email"], client["client_id"])

    return JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": config.JWT_EXPIRY,
            "id_token": id_token,
            "refresh_token": new_rt["token"],
            "scope": " ".join(rt["scopes"]),
        },
        headers={"Cache-Control": "no-store"},
    )


async def _handle_token_exchange_grant(
    client: dict,
    subject_token: str | None,
    subject_token_type: str | None,
    audience: str | None,
):
    if not subject_token:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "subject_token is required"},
        )

    if subject_token_type and subject_token_type != "urn:ietf:params:oauth:token-type:access_token":
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "Only access_token subject_token_type is supported"},
        )

    if not audience:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_request", "error_description": "audience is required"},
        )

    # Validate the subject token
    try:
        decoded = jwt.decode(
            subject_token,
            key=get_public_key_pem(),
            algorithms=["EdDSA"],
            audience=config.ISSUER,
        )
    except jwt.InvalidTokenError as e:
        logger.warning("Invalid subject token during token exchange: %s", e, exc_info=True)
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Invalid or expired subject token"},
        )

    # Verify target audience is a registered client
    target_client = await OAuthClient.get(client_id=audience)
    if not target_client:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_target", "error_description": "Audience is not a registered OAuth client"},
        )

    # Requesting client must be allowed every scope the target requires.
    required_scopes = list(target_client["required_scopes"] or [])
    missing_scopes = [
        s for s in required_scopes if s not in (client["allowed_scopes"] or [])
    ]
    if missing_scopes:
        return JSONResponse(
            status_code=403,
            content={
                "error": "insufficient_scope",
                "error_description": (
                    f"Client is not allowed scopes required by target: {' '.join(missing_scopes)}"
                ),
            },
        )

    # Look up identity from sub claim (an identity id)
    identity_id = parse_subject(decoded.get("sub", ""))
    if identity_id is None:
        logger.warning("Invalid subject during token exchange: %s", decoded.get("sub"))
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Invalid subject in token"},
        )
    identity = await Identity.get(id=identity_id, closed=False)
    if not identity:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_grant", "error_description": "Identity not found"},
        )

    target_consent = await Consent.get(
        identity_id=identity["id"], client_id=target_client["client_id"]
    )
    if not target_consent:
        return JSONResponse(
            status_code=403,
            content={
                "error": "access_denied",
                "error_description": "User has not consented to target client.",
            },
        )

    # Issue new access token scoped to the target audience with the target's
    # required scopes.
    access_token = create_signed_jwt(identity, required_scopes, audience=audience)

    logger.info(
        "Token exchange: %s exchanged token for audience %s (via client: %s)",
        identity["email"], audience, client["client_id"],
    )

    return JSONResponse(
        content={
            "access_token": access_token,
            "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "token_type": "Bearer",
            "expires_in": config.JWT_EXPIRY,
        },
        headers={"Cache-Control": "no-store"},
    )


routes = [
    Route("/authorize", authorize, methods=["GET", "POST"]),
    Route("/authorize/consent", authorize_consent, methods=["POST"]),
    Route("/token", token_endpoint, methods=["POST"]),
]
