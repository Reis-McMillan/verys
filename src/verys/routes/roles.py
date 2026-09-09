import logging

from pydantic import BaseModel, ValidationError
from pymongo.errors import DuplicateKeyError
from starlette.requests import Request
from starlette.routing import Route

from verys.models.identity import Identity
from verys.models.role import Role
from verys.modules.email import normalize_email
from verys.modules.http import json_error, json_message, check_body

logger = logging.getLogger("verys.roles")


class RoleCreateBody(BaseModel):
    name: str


def _require_admin(request: Request, action: str):
    if not request.user.is_admin:
        logger.warning("Forbidden: %s tried to %s", request.user.email, action)
        return json_error("Not authorized to perform this action.", status_code=403)
    return None


def _has_role(identity: dict, role: dict) -> bool:
    return any(r["id"] == role["id"] for r in identity["roles"])


async def list_roles(request: Request):
    if err := _require_admin(request, "list roles"):
        return err
    return json_message("Roles retrieved.", roles=sorted(r["name"] for r in await Role.all()))


async def create_role(request: Request):
    if err := _require_admin(request, "create a role"):
        return err
    body, err = await check_body(request, RoleCreateBody)
    if err:
        return err

    try:
        await Role.upsert({"name": body.name})
    except ValidationError as e:
        return json_error(str(e), status_code=400)
    except DuplicateKeyError:
        return json_error(f"Role {body.name} already exists.", status_code=409)

    return json_message(
        f"Role {body.name} created successfully.",
        status_code=201,
        headers={"Location": f"/roles/{body.name}"},
    )


async def get_role(request: Request):
    if err := _require_admin(request, "access role list"):
        return err

    role_name = request.path_params["role_name"]
    role = await Role.get(name=role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)

    identities = await Identity.all(**{"roles.id": role["id"]}, closed=False)
    identity_emails = [i["email"] for i in identities]

    return json_message(
        "Successfully retrieved role and associated identities.",
        identity_emails=identity_emails,
    )


async def delete_role(request: Request):
    if err := _require_admin(request, "delete a role"):
        return err

    role_name = request.path_params["role_name"]
    role = await Role.get(name=role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)

    # Role.pipeline strips the embedded copy from every identity.
    await Role.delete(id=role["id"])

    return json_message(f"Successfully deleted role {role_name}.")


async def assign_role(request: Request):
    role_name = request.path_params["role_name"]
    email = request.path_params["email"]
    if err := _require_admin(request, f"assign role {role_name} to {email}"):
        return err

    role = await Role.get(name=role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)
    identity = await Identity.get(email=normalize_email(email), closed=False)
    if not identity:
        return json_error(f"Identity {email} does not exist.", status_code=404)

    if _has_role(identity, role):
        return json_message(f"Identity {email} already has role {role_name}.")

    identity["roles"] = sorted([*identity["roles"], role], key=lambda r: r["name"])
    await Identity.upsert(identity)

    logger.info("Role %s assigned to %s by %s", role_name, email, request.user.email)
    return json_message(f"Role {role_name} assigned to {email}.", status_code=201)


async def revoke_role(request: Request):
    role_name = request.path_params["role_name"]
    email = request.path_params["email"]
    if err := _require_admin(request, f"revoke role {role_name} from {email}"):
        return err

    role = await Role.get(name=role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)
    identity = await Identity.get(email=normalize_email(email), closed=False)
    if not identity:
        return json_error(f"Identity {email} does not exist.", status_code=404)

    if not _has_role(identity, role):
        return json_error(
            f"Identity {email} does not have role {role_name}.", status_code=404
        )

    identity["roles"] = [r for r in identity["roles"] if r["id"] != role["id"]]
    await Identity.upsert(identity)

    logger.info("Role %s revoked from %s by %s", role_name, email, request.user.email)
    return json_message(f"Role {role_name} revoked from {email}.")


routes = [
    Route("/roles/", list_roles, methods=["GET"]),
    Route("/roles/", create_role, methods=["POST"]),
    Route("/roles/{role_name}", get_role, methods=["GET"]),
    Route("/roles/{role_name}", delete_role, methods=["DELETE"]),
    Route("/roles/{role_name}/identities/{email}", assign_role, methods=["POST"]),
    Route("/roles/{role_name}/identities/{email}", revoke_role, methods=["DELETE"]),
]
