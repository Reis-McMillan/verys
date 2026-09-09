import logging

import httpx
from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.routing import Route

from verys.models.external_provider import ExternalProvider
from verys.models.external_token import ExternalToken
from verys.models.scope import Scope
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


def _serialize(provider: dict) -> dict:
    created_at = provider.get("created_at")
    return {
        "provider_id": provider["provider_id"],
        "display_name": provider["display_name"],
        "client_id": provider["client_id"],
        "authorization_endpoint": provider["authorization_endpoint"],
        "token_endpoint": provider["token_endpoint"],
        "jwks_uri": provider["jwks_uri"],
        "userinfo_endpoint": provider["userinfo_endpoint"],
        "scopes": provider["scopes"],
        "enabled": provider["enabled"],
        "created_at": created_at.isoformat() if created_at else None,
    }


async def create_provider(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)
    body, err = await check_body(request, ProviderCreateRequest)
    if err:
        return err

    if await ExternalProvider.get(provider_id=body.provider_id):
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

    try:
        provider = await ExternalProvider.upsert({
            "provider_id": body.provider_id,
            "display_name": body.display_name,
            "client_id": body.client_id,
            "client_secret": body.client_secret,
            "authorization_endpoint": body.authorization_endpoint,
            "token_endpoint": body.token_endpoint,
            "jwks_uri": jwks_uri,
            "userinfo_endpoint": userinfo_endpoint,
            "scopes": body.scopes,
        })
    except ValidationError as e:
        return json_error(str(e), status_code=400)

    logger.info("Provider created: %s", provider["provider_id"])
    return json_message("Provider created.", status_code=201, **_serialize(provider))


async def list_providers(request: Request):
    return json_message(
        "Providers retrieved.",
        providers=[_serialize(p) for p in await ExternalProvider.all()],
    )


async def get_provider(request: Request):
    provider = await ExternalProvider.get(provider_id=request.path_params["provider_id"])
    if not provider:
        return json_error("Provider not found", status_code=404)
    return json_message("Provider retrieved.", **_serialize(provider))


async def update_provider(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)
    body, err = await check_body(request, ProviderUpdateRequest)
    if err:
        return err

    provider = await ExternalProvider.get(provider_id=request.path_params["provider_id"])
    if not provider:
        return json_error("Provider not found", status_code=404)

    for field, value in body.model_dump(exclude_none=True).items():
        provider[field] = value

    try:
        await ExternalProvider.upsert(provider)
    except ValidationError as e:
        return json_error(str(e), status_code=400)

    logger.info("Provider updated: %s", provider["provider_id"])
    return json_message("Provider updated.")


async def delete_provider(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)

    provider_id = request.path_params["provider_id"]
    if not await ExternalProvider.delete(provider_id=provider_id):
        return json_error("Provider not found", status_code=404)

    await Scope.delete(provider_id=provider_id)
    token_count = await ExternalToken.delete(provider_id=provider_id)

    logger.info("Provider deleted: %s (with %d tokens)", provider_id, token_count)
    return json_message("Provider deleted.")


routes = [
    Route("/providers/", create_provider, methods=["POST"]),
    Route("/providers/", list_providers, methods=["GET"]),
    Route("/providers/{provider_id}", get_provider, methods=["GET"]),
    Route("/providers/{provider_id}", update_provider, methods=["PUT"]),
    Route("/providers/{provider_id}", delete_provider, methods=["DELETE"]),
]
