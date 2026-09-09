from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

from verys.models.base import Base, utcnow
from verys.modules.encryption import decrypt_field, encrypt_field


class ExternalProviderSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider_id: str
    display_name: str
    client_id: str
    client_secret: str  # encrypted at rest, plain in memory
    authorization_endpoint: HttpUrl
    token_endpoint: HttpUrl
    scopes: list[str] = Field(default_factory=list)
    jwks_uri: HttpUrl | None = None
    userinfo_endpoint: HttpUrl | None = None
    enabled: bool = True
    created_at: datetime = Field(default_factory=utcnow)


def _decrypt(doc: dict | None) -> dict | None:
    if doc and doc.get("client_secret"):
        doc["client_secret"] = decrypt_field(doc["client_secret"])
    return doc


class ExternalProvider(Base):
    name = "external_provider"
    identity_fields = ["provider_id"]
    schema = ExternalProviderSchema

    @classmethod
    async def upsert(cls, obj: dict) -> dict:
        doc = cls.to_doc(obj)
        doc["client_secret"] = encrypt_field(doc["client_secret"])
        return await super().upsert(doc)

    @classmethod
    async def get(cls, **filter) -> dict | None:
        return _decrypt(await super().get(**filter))

    @classmethod
    async def all(cls, **filter) -> list[dict]:
        return [_decrypt(doc) for doc in await super().all(**filter)]
