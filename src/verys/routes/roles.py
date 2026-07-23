import logging

from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request
from starlette.routing import Route

from verys.models.role import Role
from verys.models.identity import Identity
from verys.models.identity_role import IdentityRole
from verys.modules.http import json_error, json_message, check_body

logger = logging.getLogger("verys.roles")


class RoleCreateBody(BaseModel):
    name: str


def _require_admin(request: Request, action: str):
    if not request.user.is_admin:
        logger.warning("Forbidden: %s tried to %s", request.user.email, action)
        return json_error("Not authorized to perform this action.", status_code=403)
    return None


async def list_roles(request: Request):
    if err := _require_admin(request, "list roles"):
        return err
    session = request.state.session
    return json_message("Roles retrieved.", roles=[r.name for r in Role.all(session)])


async def create_role(request: Request):
    if err := _require_admin(request, "create a role"):
        return err
    body, err = await check_body(request, RoleCreateBody)
    if err:
        return err

    session = request.state.session
    try:
        Role.new(session, body.name)
    except ValidationError as e:
        return json_error(str(e), status_code=400)
    except IntegrityError:
        session.rollback()
        return json_error(f"Role {body.name} already exists.", status_code=409)

    return json_message(
        f"Role {body.name} created successfully.",
        status_code=201,
        headers={"Location": f"/roles/{body.name}"},
    )


async def get_role(request: Request):
    if err := _require_admin(request, "access role list"):
        return err

    session = request.state.session
    role_name = request.path_params["role_name"]
    role = Role.get(session, role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)
    identity_ids = IdentityRole.list_role_identities(session, role.id)
    identities = Identity.get_by_id(session, identity_ids) if identity_ids else []
    identity_emails = [i.email for i in identities]

    return json_message(
        "Successfully retrieved role and associated identities.",
        identity_emails=identity_emails,
    )


async def delete_role(request: Request):
    if err := _require_admin(request, "delete a role"):
        return err

    session = request.state.session
    role_name = request.path_params["role_name"]
    if not Role.delete(session, role_name):
        return json_error(f"Role {role_name} does not exist.", status_code=404)

    return json_message(f"Successfully deleted role {role_name}.")


async def assign_role(request: Request):
    role_name = request.path_params["role_name"]
    email = request.path_params["email"]
    if err := _require_admin(request, f"assign role {role_name} to {email}"):
        return err

    session = request.state.session
    role = Role.get(session, role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)
    identity = Identity.get(session, email)
    if not identity:
        return json_error(f"Identity {email} does not exist.", status_code=404)

    try:
        IdentityRole.add_identity_role(session, identity.id, role.id)
    except IntegrityError:
        session.rollback()
        return json_message(f"Identity {email} already has role {role_name}.")

    logger.info("Role %s assigned to %s by %s", role_name, email, request.user.email)
    return json_message(f"Role {role_name} assigned to {email}.", status_code=201)


async def revoke_role(request: Request):
    role_name = request.path_params["role_name"]
    email = request.path_params["email"]
    if err := _require_admin(request, f"revoke role {role_name} from {email}"):
        return err

    session = request.state.session
    role = Role.get(session, role_name)
    if not role:
        return json_error(f"Role {role_name} does not exist.", status_code=404)
    identity = Identity.get(session, email)
    if not identity:
        return json_error(f"Identity {email} does not exist.", status_code=404)

    if not IdentityRole.remove_identity_role(session, identity.id, role.id):
        return json_error(
            f"Identity {email} does not have role {role_name}.", status_code=404
        )

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
