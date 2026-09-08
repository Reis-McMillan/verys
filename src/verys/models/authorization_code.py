import secrets
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, EmailStr, HttpUrl


from ..config import config
from .base import Base


class AuthorizationCodeSchema(BaseModel):
    code: str
    client_id: str
    identity_email: EmailStr
    redirect_url: HttpUrl
    scopes: list[str]
    nonce: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    auth_time: datetime
    created_at: datetime
    expires_at: datetime
    used: bool


class AuthorizationCode(Base):
    name = "authorization_code"
    collection = Base.client[name]
    identity_fields = ["code"]
    schema = AuthorizationCodeSchema

    # consider just placing an expires at in Mongo -> not found == expired
    @staticmethod
    def is_expired(obj: dict):
        return datetime.now(timezone.utc) > obj.expires_at

    @classmethod
    def mark_used(obj: dict):
        obj["used"] = True
        return obj
    


# class AuthorizationCode(SQLModel, table=True):
#     __tablename__ = "authorization_code"

#     id: int | None = Field(default=None, primary_key=True)
#     code: str = Field(
#         default_factory=lambda: secrets.token_hex(32),
#         unique=True,
#         index=True,
#     )
#     client_id: str = Field()
#     identity_email: str = Field()
#     redirect_uri: str = Field()
#     scopes: List[str] = Field(
#         default_factory=list,
#         sa_column=Column(ARRAY(String)),
#     )
#     nonce: Optional[str] = Field(default=None)
#     code_challenge: Optional[str] = Field(default=None)
#     code_challenge_method: Optional[str] = Field(default=None)
#     auth_time: datetime = Field(sa_column=Column(DateTime(timezone=True)))
#     created_at: datetime = Field(
#         default_factory=lambda: datetime.now(timezone.utc),
#         sa_column=Column(DateTime(timezone=True)),
#     )
#     expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
#     used: bool = Field(default=False)

#     @classmethod
#     def get_by_code(cls, session: Session, code: str):
#         statement = select(cls).where(cls.code == code)
#         return session.exec(statement).first()

#     def is_expired(self) -> bool:
#         return datetime.now(timezone.utc) > self.expires_at

#     def mark_used(self, session: Session):
#         self.used = True
#         session.add(self)
#         session.commit()
