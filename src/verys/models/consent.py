from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, UUID4

from verys.models.base import Base, utcnow


class ConsentSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_id: UUID4
    client_id: str
    scopes: list[str] = Field(default_factory=list)
    granted_at: datetime = Field(default_factory=utcnow)


class Consent(Base):
    name = "consent"
    identity_fields = ["identity_id", "client_id"]
    schema = ConsentSchema
