import uuid

from pydantic import BaseModel, ConfigDict, Field, UUID4

from verys.models.base import Base, LIVE, LOG_STAGE

DEFAULT_ROLES = ["admin", "service-account"]


class RoleSchema(BaseModel):
    """Canonical role document. The same shape is embedded in
    ``identity.roles``."""

    model_config = ConfigDict(extra="forbid")

    id: UUID4 = Field(default_factory=uuid.uuid4)
    name: str


class Role(Base):
    name = "role"
    identity_fields = ["id"]
    schema = RoleSchema

    # Re-derive every identity's embedded roles from this collection so that
    # renames propagate and deleted/missing roles drop out. Only identities
    # whose embedded copies differ are rewritten (with a log entry).
    pipeline_collection = "identity"
    pipeline = [
        {"$match": LIVE},
        {
            "$lookup": {
                "from": "role",
                "localField": "roles.id",
                "foreignField": "id",
                "pipeline": [
                    {"$match": LIVE},
                    {"$project": {"_id": 0, "id": 1, "name": 1}},
                    {"$sort": {"name": 1}},
                ],
                "as": "synced",
            }
        },
        {"$match": {"$expr": {"$ne": ["$roles", "$synced"]}}},
        {"$set": {"roles": "$synced"}},
        {"$unset": "synced"},
        LOG_STAGE,
        {
            "$merge": {
                "into": "identity",
                "on": "_id",
                "whenMatched": "replace",
                "whenNotMatched": "discard",
            }
        },
    ]
