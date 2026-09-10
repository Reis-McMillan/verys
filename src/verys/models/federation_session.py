import uuid
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field, UUID4

from verys.models.base import Base, utcnow

FEDERATION_SESSION_TTL = 10 * 60  # 10 minutes; see the TTL index in database.py


class FederationSessionSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    identity_id: UUID4
    provider_id: str
    # Registered client redirect URI to send the browser to after the
    # upstream flow completes; validated in /federation/initiate.
    redirect_uri: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class FederationSession(Base):
    name = "federation_session"
    identity_fields = ["session_id"]
    schema = FederationSessionSchema

    @staticmethod
    def is_expired(doc: dict) -> bool:
        return utcnow() >= doc["created_at"] + timedelta(seconds=FEDERATION_SESSION_TTL)
