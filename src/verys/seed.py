"""Startup seeding of default documents.

Every seed is fill-the-gap only: a document is created when it is missing and
never overwritten, so edits made later through the admin routes (rotated
secrets, disabled providers, renamed descriptions) survive restarts and the
document `log` does not grow on every boot.
"""

import logging

from verys.config import config
from verys.models import ExternalProvider, OAuthClient, Role, Scope
from verys.models.role import DEFAULT_ROLES
from verys.models.scope import OIDC_SCOPES

logger = logging.getLogger("verys.seed")


async def seed_roles() -> None:
    for name in DEFAULT_ROLES:
        if not await Role.get(name=name):
            await Role.upsert({"name": name})


async def seed_oidc_scopes() -> None:
    for name, description in OIDC_SCOPES:
        if not await Scope.get(name=name):
            await Scope.upsert({"name": name, "description": description})


async def seed_verys_client() -> None:
    verys_client = await OAuthClient.get(client_id=config.VERYS_CLIENT_ID)
    if not verys_client:
        await OAuthClient.upsert({
            "client_id": config.VERYS_CLIENT_ID,
            "client_name": "Verys Client",
            "redirect_uris": [config.VERYS_CLIENT_REDIRECT_URI],
            "allowed_scopes": ["openid", "email", "profile", "google", "microsoft"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "is_public": True,
        })
        logger.info("Seeded Verys public client: %s", config.VERYS_CLIENT_ID)
    elif verys_client["redirect_uris"] != [config.VERYS_CLIENT_REDIRECT_URI]:
        verys_client["redirect_uris"] = [config.VERYS_CLIENT_REDIRECT_URI]
        await OAuthClient.upsert(verys_client)
        logger.info("Updated Verys public client redirect_uris: %s", config.VERYS_CLIENT_ID)


async def seed_providers() -> None:
    """Create the external providers listed in ``config.SEED_PROVIDERS`` and
    the Verys-facing scope that routes into each of them.

    Each entry is an ``ExternalProvider`` document plus a ``scope`` key
    holding ``{"name", "description"}``. Entries without credentials are
    skipped with a warning so a missing env var never blocks startup.
    """
    for entry in getattr(config, "SEED_PROVIDERS", None) or []:
        provider = dict(entry)
        scope = provider.pop("scope")
        provider_id = provider["provider_id"]

        if not provider.get("client_id") or not provider.get("client_secret"):
            logger.warning(
                "Skipping seed of provider %s: client_id/client_secret not configured",
                provider_id,
            )
            continue

        if not await ExternalProvider.get(provider_id=provider_id):
            await ExternalProvider.upsert(provider)
            logger.info("Seeded external provider: %s", provider_id)

        if not await Scope.get(name=scope["name"]):
            await Scope.upsert({**scope, "provider_id": provider_id})
            logger.info("Seeded scope %s -> provider %s", scope["name"], provider_id)


async def seed_defaults() -> None:
    await seed_roles()
    await seed_oidc_scopes()
    await seed_verys_client()
    await seed_providers()
