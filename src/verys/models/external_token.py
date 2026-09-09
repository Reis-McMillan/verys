import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, UUID4

from verys.models.base import Base, utcnow
from verys.modules.encryption import decrypt_field, encrypt_field

SECRET_FIELDS = ("access_token", "refresh_token")


class ExternalTokenSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID4 = Field(default_factory=uuid.uuid4)
    identity_id: UUID4
    provider_id: str
    email: EmailStr
    subject: str
    access_token: str | None = None  # encrypted at rest
    refresh_token: str | None = None  # encrypted at rest
    token_type: str = "Bearer"
    expires_at: datetime | None = None
    scopes_granted: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


def _decrypt(doc: dict | None) -> dict | None:
    if doc:
        for field in SECRET_FIELDS:
            if doc.get(field):
                doc[field] = decrypt_field(doc[field])
    return doc


class ExternalToken(Base):
    name = "external_token"
    identity_fields = ["identity_id", "provider_id", "subject"]
    schema = ExternalTokenSchema

    @classmethod
    async def upsert(cls, obj: dict) -> dict:
        doc = cls.to_doc(obj)
        for field in SECRET_FIELDS:
            if doc.get(field):
                doc[field] = encrypt_field(doc[field])
        return await super().upsert(doc)

    @classmethod
    async def get(cls, **filter) -> dict | None:
        return _decrypt(await super().get(**filter))

    @classmethod
    async def all(cls, **filter) -> list[dict]:
        return [_decrypt(doc) for doc in await super().all(**filter)]

    @staticmethod
    def is_expired(doc: dict) -> bool:
        expires_at = doc.get("expires_at")
        if not expires_at:
            return False
        return expires_at <= utcnow()
