import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, UUID4, field_validator

from verys.models.base import Base, utcnow
from verys.models.role import RoleSchema
from verys.modules.email import normalize_email


class IdentitySchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: UUID4 = Field(default_factory=uuid.uuid4)
    first_name: str
    last_name: str
    email: EmailStr
    email_verified: bool = False
    auth_key: str
    expires: datetime
    origination: datetime = Field(default_factory=utcnow)
    closed: bool = False
    last_auth_time: datetime | None = None
    # Embedded snapshots of canonical `role` documents, sorted by name.
    # Role.pipeline keeps them consistent with the `role` collection.
    roles: list[RoleSchema] = Field(default_factory=list)

    @field_validator("email", mode="before")
    @classmethod
    def transform_email(cls, v):
        return normalize_email(v)


class Identity(Base):
    name = "identity"
    identity_fields = ["id"]
    schema = IdentitySchema

    @staticmethod
    def make_auth_key() -> str:
        return str(uuid.uuid4())
