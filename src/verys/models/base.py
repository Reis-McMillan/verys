from abc import ABC, abstractmethod
from pydantic import BaseModel
from pymongo.asynchronous.collection import AsyncCollection
from pymongo.asynchronous.mongo_client import AsyncMongoClient
from typing import Any

from ..config import config

class Base(ABC):
    mongo_uri = config.MONGO_URI
    db_name = config.DB_NAME
    client = AsyncMongoClient(mongo_uri, tz_aware=True)

    @property
    @abstractmethod
    def name(cls) -> str:
        raise NotImplementedError

    @property
    @abstractmethod
    def collection(cls) -> AsyncCollection:
        raise NotImplementedError

    @property
    @abstractmethod
    def identity_fields(cls) -> list[str]:
        raise NotImplementedError

    @property
    @abstractmethod
    def schema(cls) -> type[BaseModel]:
        raise NotImplementedError

    @classmethod
    async def upsert(cls, obj: dict):
        obj = cls.schema.model_validate(
            obj, strict=True, extra='forbid'
        )
        filter = {f: obj[f] for f in cls.identity_fields}
        result = await cls.collection.update_one(
            filter,
            update={
                "$set": obj,
                "$push": {"log": obj}
            },
            upsert=True
        )
        return result.upserted_id

    @classmethod
    async def get(cls, **kwargs):
        filter = {f: kwargs.get(f, None) for f in cls.identity_fields}
        return await cls.collection.find_one(
            filter,
            {"_id": 0, "logs": 0}
        )

    @classmethod
    async def delete(cls, **kwargs):
        filter = {f: kwargs.get(f, None) for f in cls.identity_fields}
        deleted_obj = {f: None for f in cls.schema.model_fields}
        result = await cls.collection.update_one(
            filter,
            {"$set": deleted_obj}
        )
        return result.modified_count == 1
