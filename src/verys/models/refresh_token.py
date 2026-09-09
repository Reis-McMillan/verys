import secrets
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, UUID4

from verys.models.base import Base, utcnow


class RefreshTokenSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(default_factory=lambda: secrets.token_hex(48))
    client_id: str
    identity_id: UUID4
    scopes: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    revoked: bool = False
    replaced_by: str | None = None


class RefreshToken(Base):
    name = "refresh_token"
    identity_fields = ["token"]
    schema = RefreshTokenSchema

    @staticmethod
    def is_expired(doc: dict) -> bool:
        return utcnow() > doc["expires_at"]
