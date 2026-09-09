"""Shared test helpers for building documents through the generic model API."""
from datetime import datetime, timedelta, timezone

from verys.models import Identity, OAuthClient
from verys.modules.client_auth import hash_client_secret


def ms(dt: datetime) -> datetime:
    """Truncate to millisecond precision, matching BSON date storage."""
    return dt.replace(microsecond=dt.microsecond // 1000 * 1000)


async def new_identity(
    email: str,
    first_name: str = 'Test',
    last_name: str = 'User',
    auth_key: str | None = None,
    expires: datetime | None = None,
    **extra,
) -> dict:
    return await Identity.upsert({
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'auth_key': auth_key or Identity.make_auth_key(),
        'expires': expires or datetime.now(timezone.utc) + timedelta(days=30),
        **extra,
    })


async def new_client(
    client_name: str,
    redirect_uris: list[str],
    secret: str | None = 'test-secret',
    **extra,
) -> dict:
    return await OAuthClient.upsert({
        'client_name': client_name,
        'redirect_uris': redirect_uris,
        'client_secret_hash': hash_client_secret(secret) if secret else None,
        **extra,
    })
