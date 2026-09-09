from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from verys.config import config
from verys.models.scope import Scope


async def openid_configuration(request: Request):
    scopes_supported = sorted(s["name"] for s in await Scope.all())
    return JSONResponse({
        "issuer": config.ISSUER,
        "authorization_endpoint": f"{config.ISSUER}/authorize",
        "token_endpoint": f"{config.ISSUER}/token",
        "userinfo_endpoint": f"{config.ISSUER}/userinfo",
        "jwks_uri": f"{config.ISSUER}/.well-known/jwks.json",
        "end_session_endpoint": f"{config.ISSUER}/end-session",
        "revocation_endpoint": f"{config.ISSUER}/token/revoke",
        "scopes_supported": scopes_supported,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "claims_supported": [
            "sub",
            "email",
            "email_verified",
            "iss",
            "aud",
            "exp",
            "iat",
            "auth_time",
            "nonce",
            "at_hash",
            "roles",
            "tokens",
            "given_name",
            "family_name",
            "name",
            "origination",
        ],
        "code_challenge_methods_supported": ["S256"],
        "request_parameter_supported": False,
        "request_uri_parameter_supported": False,
    })


routes = [
    Route("/.well-known/openid-configuration", openid_configuration, methods=["GET"]),
]
