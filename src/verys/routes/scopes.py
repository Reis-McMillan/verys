import logging

from pydantic import BaseModel
from starlette.requests import Request
from starlette.routing import Route

from verys.models.scope import Scope
from verys.modules.http import json_error, json_message, check_body

logger = logging.getLogger("verys.scopes")


class ScopeCreateRequest(BaseModel):
    name: str
    description: str
    provider_id: str | None = None


class ScopeUpdateRequest(BaseModel):
    description: str | None = None
    provider_id: str | None = None


def _serialize(scope: Scope) -> dict:
    return {
        "name": scope.name,
        "description": scope.description,
        "provider_id": scope.provider_id,
        "created_at": scope.created_at.isoformat() if scope.created_at else None,
    }


async def create_scope(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)
    body, err = await check_body(request, ScopeCreateRequest)
    if err:
        return err

    session = request.state.session
    if Scope.get_by_name(session, body.name):
        return json_error("Scope already exists", status_code=409)

    scope = Scope(
        name=body.name,
        description=body.description,
        provider_id=body.provider_id,
    )
    session.add(scope)
    session.commit()
    session.refresh(scope)

    logger.info("Scope created: %s", scope.name)
    return json_message("Scope created.", status_code=201, **_serialize(scope))


async def list_scopes(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)

    session = request.state.session
    return json_message(
        "Scopes retrieved.",
        scopes=[_serialize(s) for s in Scope.all(session)],
    )


async def get_scope(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)

    session = request.state.session
    scope = Scope.get_by_name(session, request.path_params["name"])
    if not scope:
        return json_error("Scope not found", status_code=404)
    return json_message("Scope retrieved.", **_serialize(scope))


async def update_scope(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)
    body, err = await check_body(request, ScopeUpdateRequest)
    if err:
        return err

    session = request.state.session
    scope = Scope.get_by_name(session, request.path_params["name"])
    if not scope:
        return json_error("Scope not found", status_code=404)

    if body.description is not None:
        scope.description = body.description
    if body.provider_id is not None:
        scope.provider_id = body.provider_id

    session.add(scope)
    session.commit()
    session.refresh(scope)

    logger.info("Scope updated: %s", scope.name)
    return json_message("Scope updated.")


async def delete_scope(request: Request):
    if not request.user.is_admin:
        return json_error("Admin access required", status_code=403)

    name = request.path_params["name"]
    if name in ("openid", "profile", "email"):
        return json_error("Cannot delete standard OIDC scopes")

    session = request.state.session
    scope = Scope.get_by_name(session, name)
    if not scope:
        return json_error("Scope not found", status_code=404)

    session.delete(scope)
    session.commit()

    logger.info("Scope deleted: %s", name)
    return json_message("Scope deleted.")


routes = [
    Route("/scopes/", create_scope, methods=["POST"]),
    Route("/scopes/", list_scopes, methods=["GET"]),
    Route("/scopes/{name}", get_scope, methods=["GET"]),
    Route("/scopes/{name}", update_scope, methods=["PUT"]),
    Route("/scopes/{name}", delete_scope, methods=["DELETE"]),
]
