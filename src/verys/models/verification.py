import secrets
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from verys.models.base import Base, utcnow
from verys.modules.email import normalize_email


class VerificationSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: EmailStr
    code: int
    email_sent: datetime | None = None
    when: datetime = Field(default_factory=utcnow)

    @field_validator("email", mode="before")
    @classmethod
    def transform_email(cls, v):
        return normalize_email(v)


class Verification(Base):
    name = "verification"
    identity_fields = ["email"]
    schema = VerificationSchema

    @staticmethod
    def make_code() -> int:
        return secrets.randbelow(900_000) + 100_000
