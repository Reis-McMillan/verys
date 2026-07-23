import logging
import secrets

import httpx
from pydantic import BaseModel
from sqlmodel import Session
from starlette.requests import Request
from starlette.routing import Route

from verys.config import config
from verys.models.oauth2_client import OAuthClient
from verys.models.scope import Scope
from verys.modules.client_auth import hash_client_secret
from verys.modules.http import json_error, json_message, check_body

logger = logging.getLogger("verys.clients")


class ClientCreateRequest(BaseModel):
    client_name: str
    redirect_uris: list[str]
    allowed_scopes: list[str] = ["openid"]
    prm_uri: str | None = None
    grant_types: list[str] = ["authorization_code", "refresh_token"]
    token_endpoint_auth_method: str = "client_secret_basic"
    is_public: bool = False


class ClientUpdateRequest(BaseModel):
    client_name: str | None = None
    redirect_uris: list[str] | None = None
    allowed_scopes: list[str] | None = None
    prm_uri: str | None = None
    grant_types: list[str] | None = None
    token_endpoint_auth_method: str | None = None
    is_public: bool | None = None


async def _get_prm_uri(prm_uri: str, client_name: str, session: Session):
    """Returns ``(required_scopes, None)`` or ``(None, JSONResponse error)``."""
    async with httpx.AsyncClient() as client:
        response = await client.get(prm_uri)
        if response.status_code != 200:
            return None, json_error("Failed to retrieve OAuth metadata for client.")

        result: dict = response.json()
        if config.ISSUER not in result.get("authorization_servers", []):
            return None, json_error(
                f"Client must list {config.ISSUER} as authorization server."
            )

        if result.get("resource_name") != client_name:
            return None, json_error("Client name must match OAuth resource name.")

        required_scopes = result.get("scopes_supported", [])
        for s in required_scopes:
            if not Scope.get_by_name(session, s):
                return None, json_error(f"Unknown scope '{s}'")
        return required_scopes, None


async def create_client(request: Request):
    if not request.user.is_admin:
        return json_error("Unauthorized to perform this action", status_code=403)
    body, err = await check_body(request, ClientCreateRequest)
    if err:
        return err

    session = request.state.session
    for s in body.allowed_scopes:
        if not Scope.get_by_name(session, s):
            return json_error(f"Unknown scope '{s}'")

    required_scopes = []
    if body.prm_uri:
        required_scopes, prm_err = await _get_prm_uri(body.prm_uri, body.client_name, session)
        if prm_err:
            return prm_err

    plain_secret = secrets.token_urlsafe(48) if not body.is_public else None

    client = OAuthClient(
        client_name=body.client_name,
        redirect_uris=body.redirect_uris,
        allowed_scopes=body.allowed_scopes,
        prm_uri=body.prm_uri,
        required_scopes=required_scopes,
        grant_types=body.grant_types,
        token_endpoint_auth_method=body.token_endpoint_auth_method,
        is_public=body.is_public,
        client_secret_hash=hash_client_secret(plain_secret) if plain_secret else None,
        owner_email=request.user.email,
    )
    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Client created: %s (%s)", client.client_id, client.client_name)

    payload = {
        "client_id": client.client_id,
        "client_name": client.client_name,
        "redirect_uris": client.redirect_uris,
        "allowed_scopes": client.allowed_scopes,
        "grant_types": client.grant_types,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "is_public": client.is_public,
    }
    if plain_secret:
        payload["client_secret"] = plain_secret
    return json_message("Client created.", status_code=201, **payload)


async def list_clients(request: Request):
    if not request.user.is_admin:
        return json_error("Unauthorized to perform this action", status_code=403)

    session = request.state.session
    clients = OAuthClient.all(session)
    return json_message(
        "Clients retrieved.",
        clients=[
            {
                "client_id": c.client_id,
                "client_name": c.client_name,
                "redirect_uris": c.redirect_uris,
                "allowed_scopes": c.allowed_scopes,
                "required_scopes": c.required_scopes,
                "is_public": c.is_public,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in clients
        ],
    )


async def get_client(request: Request):
    if not request.user.is_admin:
        return json_error("Unauthorized to perform this action", status_code=403)

    session = request.state.session
    client_id = request.path_params["client_id"]
    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        return json_error("Client not found", status_code=404)

    return json_message(
        "Client retrieved.",
        client_id=client.client_id,
        client_name=client.client_name,
        redirect_uris=client.redirect_uris,
        allowed_scopes=client.allowed_scopes,
        required_scopes=client.required_scopes,
        grant_types=client.grant_types,
        token_endpoint_auth_method=client.token_endpoint_auth_method,
        is_public=client.is_public,
        created_at=client.created_at.isoformat() if client.created_at else None,
        owner_email=client.owner_email,
    )


async def update_client(request: Request):
    if not request.user.is_admin:
        return json_error("Unauthorized to perform this action", status_code=403)
    body, err = await check_body(request, ClientUpdateRequest)
    if err:
        return err

    session = request.state.session
    client_id = request.path_params["client_id"]
    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        return json_error("Client not found", status_code=404)

    if body.client_name is not None:
        client.client_name = body.client_name
    if body.redirect_uris is not None:
        client.redirect_uris = body.redirect_uris
    if body.allowed_scopes is not None:
        for s in body.allowed_scopes:
            if not Scope.get_by_name(session, s):
                return json_error(f"Unknown scope '{s}'")
        client.allowed_scopes = body.allowed_scopes
    if body.prm_uri is not None:
        client_name = body.client_name if body.client_name else client.client_name
        required_scopes, prm_err = await _get_prm_uri(body.prm_uri, client_name, session)
        if prm_err:
            return prm_err
        client.prm_uri = body.prm_uri
        client.required_scopes = required_scopes
    if body.grant_types is not None:
        client.grant_types = body.grant_types
    if body.token_endpoint_auth_method is not None:
        client.token_endpoint_auth_method = body.token_endpoint_auth_method
    if body.is_public is not None:
        client.is_public = body.is_public

    session.add(client)
    session.commit()
    session.refresh(client)

    logger.info("Client updated: %s", client.client_id)
    return json_message("Client updated.")


async def delete_client(request: Request):
    if not request.user.is_admin:
        return json_error("Unauthorized to perform this action", status_code=403)

    session = request.state.session
    client_id = request.path_params["client_id"]
    client = OAuthClient.get_by_client_id(session, client_id)
    if not client:
        return json_error("Client not found", status_code=404)

    session.delete(client)
    session.commit()

    logger.info("Client deleted: %s", client_id)
    return json_message("Client deleted.")


routes = [
    Route("/clients/", create_client, methods=["POST"]),
    Route("/clients/", list_clients, methods=["GET"]),
    Route("/clients/{client_id}", get_client, methods=["GET"]),
    Route("/clients/{client_id}", update_client, methods=["PUT"]),
    Route("/clients/{client_id}", delete_client, methods=["DELETE"]),
]
