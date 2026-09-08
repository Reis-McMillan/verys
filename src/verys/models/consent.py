from datetime import datetime, timezone
from pydantic import BaseModel, EmailStr
from typing import List

from .base import Base


class ConsentSchema(BaseModel):
    identity_email: EmailStr
    client_id: str
    scopes: list[str]
    granted_at = datetime


class Consent(Base):
    name = "consent"
    collection = Base.client[name]
    identity_fields = ["identity_email", "client_id"]
    schema = ConsentSchema

    @staticmethod
    def grant(obj: dict, scopes: list[str]):
        obj["scopes"] = scopes
        obj["granted_at"] = datetime.now(timezone.utc)

    @staticmethod
    def covers_scopes(obj: dict, requested_scopes: list[str]):
        scopes = obj.get("scopes", [])
        return all(s in scopes for s in requested_scopes)


# class Consent(SQLModel, table=True):
#     __tablename__ = "consent"
#     __table_args__ = (
#         UniqueConstraint("identity_email", "client_id", name="uq_consent_user_client"),
#     )

#     id: int | None = Field(default=None, primary_key=True)
#     identity_email: str = Field()
#     client_id: str = Field()
#     scopes: List[str] = Field(
#         default_factory=list,
#         sa_column=Column(ARRAY(String)),
#     )
#     granted_at: datetime = Field(
#         default_factory=lambda: datetime.now(timezone.utc),
#         sa_column=Column(DateTime(timezone=True)),
#     )

#     @classmethod
#     def get(cls, session: Session, identity_email: str, client_id: str):
#         statement = select(cls).where(
#             cls.identity_email == identity_email,
#             cls.client_id == client_id,
#         )
#         return session.exec(statement).first()

#     @classmethod
#     def grant(
#         cls,
#         session: Session,
#         identity_email: str,
#         client_id: str,
#         scopes: list[str],
#     ):
#         existing = cls.get(session, identity_email, client_id)
#         if existing:
#             existing.scopes = scopes
#             existing.granted_at = datetime.now(timezone.utc)
#             session.add(existing)
#         else:
#             existing = cls(
#                 identity_email=identity_email,
#                 client_id=client_id,
#                 scopes=scopes,
#             )
#             session.add(existing)
#         session.commit()
#         session.refresh(existing)
#         return existing

#     def covers_scopes(self, requested_scopes: list[str]) -> bool:
#         return all(s in self.scopes for s in requested_scopes)
