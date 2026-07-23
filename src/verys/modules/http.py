"""Helpers for building uniform JSON responses and parsing request input.

Response contract:
- success: ``{"message": ..., **payload}`` (payload merged at top level)
- error:   ``{"error": ..., **extra}``

Errors are returned inline at the call site rather than via a centralized
exception handler.
"""
import json
import logging

from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("verys.http")


def json_message(
    message: str,
    *,
    status_code: int = 200,
    headers: dict | None = None,
    **payload,
) -> JSONResponse:
    """Build a success response: ``{"message": message, **payload}``."""
    return JSONResponse(
        status_code=status_code,
        content={"message": message, **payload},
        headers=headers,
    )


def json_error(
    error: str,
    *,
    status_code: int = 400,
    headers: dict | None = None,
    **extra,
) -> JSONResponse:
    """Build an error response: ``{"error": error, **extra}``."""
    return JSONResponse(
        status_code=status_code,
        content={"error": error, **extra},
        headers=headers,
    )


async def check_body(request: Request, model: type[BaseModel]):
    """Parse and validate a JSON request body against a Pydantic model.

    Returns ``(instance, None)`` on success or ``(None, JSONResponse)`` with a
    ``400`` error body on malformed JSON or validation failure.
    """
    try:
        data = await request.json()
    except (json.JSONDecodeError, ValueError):
        return None, json_error("Request body must be valid JSON.")

    if not isinstance(data, dict):
        return None, json_error("Request body must be a JSON object.")

    try:
        return model(**data), None
    except ValidationError as e:
        return None, json_error(str(e))


def require_query(request: Request, *names: str) -> JSONResponse | None:
    """Return a ``422`` error response if any named query param is missing."""
    missing = [n for n in names if not request.query_params.get(n)]
    if missing:
        return json_error(
            f"Missing required query parameter(s): {', '.join(missing)}",
            status_code=422,
        )
    return None
