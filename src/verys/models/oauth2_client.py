import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from verys.models.base import Base, utcnow


class OAuthClientSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    client_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_secret_hash: str | None = None
    client_name: str
    redirect_uris: list[str] = Field(default_factory=list)
    allowed_scopes: list[str] = Field(default_factory=lambda: ["openid"])
    prm_uri: str | None = None
    required_scopes: list[str] = Field(default_factory=list)
    grant_types: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    response_types: list[str] = Field(default_factory=lambda: ["code"])
    token_endpoint_auth_method: str = "client_secret_basic"
    is_public: bool = False
    created_at: datetime = Field(default_factory=utcnow)
    owner_email: str | None = None


class OAuthClient(Base):
    name = "oauth_client"
    identity_fields = ["client_id"]
    schema = OAuthClientSchema
