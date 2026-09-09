import uuid
from datetime import datetime, timedelta

from pydantic import BaseModel, ConfigDict, Field

from verys.models.base import Base, utcnow

OAUTH2_SESSION_TTL = 10 * 60  # 10 minutes; see the TTL index in database.py


class OAuth2SessionSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str
    redirect_uri: str
    response_type: str
    scope: str
    state: str | None = None
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    csrf_token: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class OAuth2Session(Base):
    name = "oauth2_session"
    identity_fields = ["session_id"]
    schema = OAuth2SessionSchema

    @staticmethod
    def is_expired(doc: dict) -> bool:
        return utcnow() > doc["created_at"] + timedelta(seconds=OAUTH2_SESSION_TTL)
