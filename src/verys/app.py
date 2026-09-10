import logging
from contextlib import asynccontextmanager

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from verys.config import config
from verys.database import close_db, ensure_indexes
from verys.middleware.authenticated import BearerToken, on_auth_error
from verys.middleware.logging import RequestLoggingMiddleware
from verys.models import Role
from verys.modules.logging import setup_logging, shutdown_logging
from verys.seed import seed_defaults
from verys.routes import (
    clients,
    discovery,
    federation,
    identity,
    jwks,
    oauth2,
    providers,
    registration,
    roles,
    scopes,
    session as session_routes,
    userinfo,
    verification,
)

logger = logging.getLogger("verys")


@asynccontextmanager
async def lifespan(app: Starlette):
    setup_logging()
    await ensure_indexes()
    await seed_defaults()
    # Repair any drift between the `role` collection and the copies embedded
    # in identity documents.
    await Role.run_pipeline()
    logger.info("Verys service starting")
    yield
    logger.info("Verys service shutting down")
    shutdown_logging()
    await close_db()


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"error": "Internal Server Error"})


routes = [
    *discovery.routes,
    *jwks.routes,
    *registration.routes,
    *verification.routes,
    *oauth2.routes,
    *userinfo.routes,
    *session_routes.routes,
    *federation.routes,
    *identity.routes,
    *clients.routes,
    *scopes.routes,
    *providers.routes,
    *roles.routes,
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=config.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    ),
    Middleware(RequestLoggingMiddleware),
    Middleware(AuthenticationMiddleware, backend=BearerToken(), on_error=on_auth_error),
]

app = Starlette(
    lifespan=lifespan,
    routes=routes,
    middleware=middleware,
    exception_handlers={Exception: unhandled_exception_handler},
)
