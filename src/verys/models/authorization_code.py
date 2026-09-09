import secrets
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from verys.models.base import Base, utcnow


class AuthorizationCodeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(default_factory=lambda: secrets.token_hex(32))
    client_id: str
    identity_email: EmailStr
    # Plain string: OAuth requires an exact match against the registered URI,
    # and pydantic's URL types normalise (e.g. add a trailing slash).
    redirect_uri: str
    scopes: list[str] = Field(default_factory=list)
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    auth_time: datetime
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime
    used: bool = False


class AuthorizationCode(Base):
    name = "authorization_code"
    identity_fields = ["code"]
    schema = AuthorizationCodeSchema

    @staticmethod
    def is_expired(doc: dict) -> bool:
        return utcnow() > doc["expires_at"]
