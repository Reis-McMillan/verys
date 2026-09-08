from datetime import datetime, timezone
from pydantic import BaseModel
from typing import List, Optional

from verys.modules.encryption import encrypt_field, decrypt_field


class ExternalProviderSchema(BaseModel):
    provider_id: str
    display_name: str
    # to-do: finish

# class ExternalProvider(SQLModel, table=True):
#     __tablename__ = "external_provider"

#     id: int | None = Field(default=None, primary_key=True)
#     provider_id: str = Field(unique=True, index=True)
#     display_name: str = Field()
#     client_id: str = Field()
#     client_secret_encrypted: str = Field()
#     authorization_endpoint: str = Field()
#     token_endpoint: str = Field()
#     scopes: List[str] = Field(
#         default_factory=list,
#         sa_column=Column(ARRAY(String)),
#     )
#     jwks_uri: Optional[str] = Field(default=None)
#     userinfo_endpoint: Optional[str] = Field(default=None)
#     enabled: bool = Field(default=True)
#     created_at: datetime = Field(
#         default_factory=lambda: datetime.now(timezone.utc),
#         sa_column=Column(DateTime(timezone=True)),
#     )

#     @property
#     def client_secret(self) -> str:
#         return decrypt_field(self.client_secret_encrypted)

#     @client_secret.setter
#     def client_secret(self, value: str):
#         self.client_secret_encrypted = encrypt_field(value)

#     @classmethod
#     def get_by_provider_id(cls, session: Session, provider_id: str) -> Optional["ExternalProvider"]:
#         statement = select(cls).where(cls.provider_id == provider_id)
#         return session.exec(statement).first()

#     @classmethod
#     def all(cls, session: Session) -> list["ExternalProvider"]:
#         statement = select(cls)
#         return list(session.exec(statement).all())
