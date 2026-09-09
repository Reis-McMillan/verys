"""Shared persistence layer for every Mongo-backed model.

Models are thin: a pydantic schema plus ``name`` (collection),
``identity_fields`` (the natural key ``upsert`` matches on) and ``schema``.
The only persistence API is the generic one here:

* ``upsert(doc)`` validates the whole document and inserts or replaces the
  live document matching ``identity_fields``.
* ``get(**filter)`` / ``all(**filter)`` read live documents by any fields.
* ``delete(**filter)`` soft-deletes every live document matching the filter:
  every schema field is nulled and the document is marked ``deleted`` with a
  ``deleted_at`` timestamp.

Every write is an update-with-aggregation-pipeline whose final stage appends
the resulting document state to the document's ``log`` array, so history is
recorded atomically with the change. Reads hide ``_id``, ``log``, ``deleted``
and ``deleted_at``. UUIDs and URLs are stored as strings; datetimes as BSON
dates.

A subclass may declare ``pipeline`` (aggregation stages) and optionally
``pipeline_collection``; the pipeline runs after every upsert/delete to
enforce consistency with documents embedded in other collections.

Documents are edited in the route handlers: read with ``get``, change the
dict, write it back with ``upsert``.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, ClassVar

from pydantic import AnyUrl, BaseModel
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.results import UpdateResult

from verys.database import get_collection

LIVE = {"deleted": False}
PROJECTION = {"_id": 0, "log": 0, "deleted": 0, "deleted_at": 0}

# Appends a snapshot of the document (minus _id and the log itself) to `log`.
LOG_STAGE = {
    "$set": {
        "log": {
            "$concatArrays": [
                {"$ifNull": ["$log", []]},
                [
                    {
                        "$arrayToObject": {
                            "$filter": {
                                "input": {"$objectToArray": "$$ROOT"},
                                "cond": {"$not": {"$in": ["$$this.k", ["_id", "log"]]}},
                            }
                        }
                    }
                ],
            ]
        }
    }
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def bsonify(value: Any) -> Any:
    """Convert pydantic/py types that BSON can't encode into storable ones."""
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, AnyUrl):
        return str(value)
    if isinstance(value, dict):
        return {k: bsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [bsonify(v) for v in value]
    return value


def literal(value: Any) -> dict:
    """Wrap a value so an aggregation ``$set`` treats it as data, never as a
    field path or operator expression."""
    return {"$literal": value}


class Base:
    name: ClassVar[str]
    identity_fields: ClassVar[list[str]]
    schema: ClassVar[type[BaseModel]]
    # Optional consistency aggregation, run after every upsert/delete.
    pipeline: ClassVar[list[dict] | None] = None
    pipeline_collection: ClassVar[str | None] = None  # defaults to `name`

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        for attr in ("name", "identity_fields", "schema"):
            if not hasattr(cls, attr):
                raise TypeError(f"{cls.__name__} must define `{attr}`")

    # -- helpers ------------------------------------------------------------

    @classmethod
    def collection(cls) -> AsyncCollection:
        return get_collection(cls.name)

    @classmethod
    def to_doc(cls, obj: dict | BaseModel) -> dict:
        """Validate ``obj`` against ``schema`` and return a BSON-safe dict."""
        model = obj if isinstance(obj, cls.schema) else cls.schema.model_validate(obj)
        return bsonify(model.model_dump(mode="python"))

    @classmethod
    def identity(cls, doc: dict) -> dict:
        return {f: doc[f] for f in cls.identity_fields}

    @classmethod
    async def _write(cls, filter: dict, stages: list[dict], *, upsert: bool = False) -> UpdateResult:
        return await cls.collection().update_many(
            bsonify(filter), [*stages, LOG_STAGE], upsert=upsert
        )

    @classmethod
    async def run_pipeline(cls) -> None:
        """Run the subclass's consistency ``pipeline``, if it declares one."""
        if not cls.pipeline:
            return
        collection = get_collection(cls.pipeline_collection or cls.name)
        cursor = await collection.aggregate(cls.pipeline)
        await cursor.to_list()

    # -- API ----------------------------------------------------------------

    @classmethod
    async def upsert(cls, obj: dict | BaseModel) -> dict:
        """Insert or fully replace the live document matching
        ``identity_fields``. Raises ``DuplicateKeyError`` when the document
        collides with a unique index. Returns the stored document."""
        doc = cls.to_doc(obj)
        filter = cls.identity(doc)
        fields = {k: literal(v) for k, v in doc.items()}
        await cls._write(filter, [{"$set": {**fields, **LIVE}}], upsert=True)
        await cls.run_pipeline()
        return await cls.get(**filter)

    @classmethod
    async def get(cls, **filter: Any) -> dict | None:
        return await cls.collection().find_one({**bsonify(filter), **LIVE}, PROJECTION)

    @classmethod
    async def all(cls, **filter: Any) -> list[dict]:
        cursor = cls.collection().find({**bsonify(filter), **LIVE}, PROJECTION)
        return await cursor.to_list()

    @classmethod
    async def delete(cls, **filter: Any) -> int:
        """Soft-delete every live document matching ``filter``. Returns the
        number of documents deleted."""
        nulls = {f: None for f in cls.schema.model_fields}
        stages = [{"$set": {**nulls, "deleted": True, "deleted_at": "$$NOW"}}]
        result = await cls._write({**filter, **LIVE}, stages)
        if result.modified_count:
            await cls.run_pipeline()
        return result.modified_count
