"""MongoDB connection management and index definitions.

``AsyncMongoClient`` binds to the event loop it is first used on and raises if
it is later used from a different loop. Starlette's ``TestClient`` runs the
app (and its lifespan) on a dedicated thread/loop while pytest-asyncio
fixtures run on pytest's loop, so this module keeps one client per running
loop. ``close_db()`` must be awaited on the loop that owns the client.
"""

import asyncio

from pymongo import ASCENDING
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.database import AsyncDatabase
from pymongo.asynchronous.mongo_client import AsyncMongoClient

from verys.config import config

_clients: dict[asyncio.AbstractEventLoop, AsyncMongoClient] = {}


def get_client() -> AsyncMongoClient:
    loop = asyncio.get_running_loop()
    client = _clients.get(loop)
    if client is None:
        client = AsyncMongoClient(config.MONGO_URI, tz_aware=True)
        _clients[loop] = client
    return client


def get_db() -> AsyncDatabase:
    return get_client()[config.MONGO_DB_NAME]


def get_collection(name: str) -> AsyncCollection:
    return get_db()[name]


async def close_db() -> None:
    """Close the client owned by the current event loop, if any."""
    client = _clients.pop(asyncio.get_running_loop(), None)
    if client is not None:
        await client.close()


# ---------------------------------------------------------------------------
# Indexes
# ---------------------------------------------------------------------------

LIVE = {"deleted": False}

# Soft-deleted documents have every schema field nulled, so unique indexes are
# partial on live documents only; otherwise the second soft delete in a
# collection would collide on the nulled key.
EPHEMERAL_TTL = 10 * 60  # seconds a soft-deleted ephemeral doc lingers


def _unique(*fields: str, partial: dict | None = None) -> tuple[list, dict]:
    return (
        [(f, ASCENDING) for f in fields],
        {"unique": True, "partialFilterExpression": partial or LIVE},
    )


def _index(*fields: str) -> tuple[list, dict]:
    return [(f, ASCENDING) for f in fields], {}


def _ttl(field: str, seconds: int) -> tuple[list, dict]:
    # TTL only expires documents whose field holds a BSON date, so nulled
    # fields on soft-deleted documents are ignored; ``deleted_at`` gets its
    # own TTL on ephemeral collections for that reason.
    return [(field, ASCENDING)], {"expireAfterSeconds": int(seconds)}


INDEXES: dict[str, list[tuple[list, dict]]] = {
    "identity": [
        _unique("id"),
        _unique("email"),
        _index("roles.id"),
        _index("roles.name"),
    ],
    "role": [
        _unique("id"),
        _unique("name"),
    ],
    "scope": [
        _unique("name"),
        _unique("provider_id", partial={**LIVE, "provider_id": {"$type": "string"}}),
    ],
    "oauth_client": [
        _unique("client_id"),
    ],
    "oauth2_session": [
        _unique("session_id"),
        _ttl("created_at", EPHEMERAL_TTL),
        _ttl("deleted_at", EPHEMERAL_TTL),
    ],
    "authorization_code": [
        _unique("code"),
        _ttl("expires_at", 0),
        _ttl("deleted_at", EPHEMERAL_TTL),
    ],
    "refresh_token": [
        _unique("token"),
        _index("identity_id", "client_id"),
    ],
    "consent": [
        _unique("identity_id", "client_id"),
    ],
    "verification": [
        _unique("email"),
        _ttl("when", config.VERIFY_TTL),
        _ttl("deleted_at", EPHEMERAL_TTL),
    ],
    "external_provider": [
        _unique("provider_id"),
    ],
    "external_token": [
        _unique("id"),
        _unique("identity_id", "provider_id", "subject"),
        _index("provider_id"),
    ],
    "federation_session": [
        _unique("session_id"),
        _ttl("created_at", EPHEMERAL_TTL),
        _ttl("deleted_at", EPHEMERAL_TTL),
    ],
}


async def ensure_indexes() -> None:
    """Create every index in ``INDEXES``. Safe to call repeatedly with the
    same specs; a changed spec on an existing index name raises and must be
    handled with ``collMod``/drop by hand."""
    db = get_db()
    for collection_name, specs in INDEXES.items():
        collection = db[collection_name]
        for keys, kwargs in specs:
            await collection.create_index(keys, **kwargs)
