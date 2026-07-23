import logging

import httpx
from pydantic import BaseModel
from starlette.requests import Request
from starlette.routing import Route

from verys.models.external_provider import ExternalProvider
from verys.models.external_token import ExternalToken
from verys.models.scope import Scope
from verys.modules.encryption import encrypt_field
from verys.modules.http import json_error, json_message, check_body

logger = logging.getLogger("verys.providers")


class ProviderCreateRequest(BaseModel):
    provider_id: str
    display_name: str
    client_id: str
    client_secret: str
    authorization_endpoint: str
    token_endpoint: str
    discovery_url: str
    scopes: list[str] = []


class ProviderUpdateRequest(BaseModel):
    display_name: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None
    enabled: bool | None = None
    scopes: list[str] | None = None


def _serialize(provider: ExternalProvider) -> dict:
    return {
        "provider_id": provider.provider_id,
        "display_name": provider.display_name,
        "client_id": provider.client_id,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "jwks_uri": provider.jwks_uri,
        "userinfo_endpoint": provider.userinfo_endpoint,
        "scopes": provider.scopes,
        "enabled": provider.enabled,
        "created_at": provider.created_at.isoformat() if provider.created_at else None,
    }


async def create_provider(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)
    body, err = await check_body(request, ProviderCreateRequest)
    if err:
        return err

    session = request.state.session
    if ExternalProvider.get_by_provider_id(session, body.provider_id):
        return json_error("Provider already exists", status_code=409)

    # Fetch OIDC discovery to get jwks_uri
    try:
        async with httpx.AsyncClient() as client:
            discovery_response = await client.get(
                body.discovery_url, headers={"Accept": "application/json"}
            )
        if discovery_response.status_code != 200:
            return json_error("Failed to fetch OIDC discovery document")
        discovery = discovery_response.json()
        jwks_uri = discovery.get("jwks_uri")
        if not jwks_uri:
            return json_error("OIDC discovery document missing jwks_uri")
        userinfo_endpoint = discovery.get("userinfo_endpoint")
    except httpx.RequestError as e:
        logger.error("Failed to fetch discovery URL %s: %s", body.discovery_url, e, exc_info=True)
        return json_error(f"Failed to reach discovery URL: {e}")

    provider = ExternalProvider(
        provider_id=body.provider_id,
        display_name=body.display_name,
        client_id=body.client_id,
        client_secret_encrypted=encrypt_field(body.client_secret),
        authorization_endpoint=body.authorization_endpoint,
        token_endpoint=body.token_endpoint,
        jwks_uri=jwks_uri,
        userinfo_endpoint=userinfo_endpoint,
        scopes=body.scopes,
    )
    session.add(provider)
    session.commit()
    session.refresh(provider)

    logger.info("Provider created: %s", provider.provider_id)
    return json_message("Provider created.", status_code=201, **_serialize(provider))


async def list_providers(request: Request):
    session = request.state.session
    return json_message(
        "Providers retrieved.",
        providers=[_serialize(p) for p in ExternalProvider.all(session)],
    )


async def get_provider(request: Request):
    session = request.state.session
    provider = ExternalProvider.get_by_provider_id(session, request.path_params["provider_id"])
    if not provider:
        return json_error("Provider not found", status_code=404)
    return json_message("Provider retrieved.", **_serialize(provider))


async def update_provider(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)
    body, err = await check_body(request, ProviderUpdateRequest)
    if err:
        return err

    session = request.state.session
    provider = ExternalProvider.get_by_provider_id(session, request.path_params["provider_id"])
    if not provider:
        return json_error("Provider not found", status_code=404)

    if body.display_name is not None:
        provider.display_name = body.display_name
    if body.client_id is not None:
        provider.client_id = body.client_id
    if body.client_secret is not None:
        provider.client_secret_encrypted = encrypt_field(body.client_secret)
    if body.authorization_endpoint is not None:
        provider.authorization_endpoint = body.authorization_endpoint
    if body.token_endpoint is not None:
        provider.token_endpoint = body.token_endpoint
    if body.enabled is not None:
        provider.enabled = body.enabled
    if body.scopes is not None:
        provider.scopes = body.scopes

    session.add(provider)
    session.commit()
    session.refresh(provider)

    logger.info("Provider updated: %s", provider.provider_id)
    return json_message("Provider updated.")


async def delete_provider(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)

    session = request.state.session
    provider_id = request.path_params["provider_id"]
    provider = ExternalProvider.get_by_provider_id(session, provider_id)
    if not provider:
        return json_error("Provider not found", status_code=404)

    scope = Scope.get_by_provider(session, provider_id)
    if scope:
        session.delete(scope)

    tokens = ExternalToken.get_all_for_provider(session, provider_id)
    for t in tokens:
        session.delete(t)

    session.delete(provider)
    session.commit()

    logger.info("Provider deleted: %s (with %d tokens)", provider_id, len(tokens))
    return json_message("Provider deleted.")


routes = [
    Route("/providers/", create_provider, methods=["POST"]),
    Route("/providers/", list_providers, methods=["GET"]),
    Route("/providers/{provider_id}", get_provider, methods=["GET"]),
    Route("/providers/{provider_id}", update_provider, methods=["PUT"]),
    Route("/providers/{provider_id}", delete_provider, methods=["DELETE"]),
]
