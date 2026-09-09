from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from verys.models.base import Base, utcnow

OIDC_SCOPES = [
    ("openid", "Verify your identity"),
    ("profile", "View your name and profile information"),
    ("email", "View your email address"),
]


class ScopeSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    description: str
    # Set when the scope is fulfilled by an external (federated) provider.
    provider_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Scope(Base):
    name = "scope"
    identity_fields = ["name"]
    schema = ScopeSchema
