# Verys

An OAuth2 / OpenID Connect identity provider built with Starlette, pydantic, and MongoDB.

Verys provides passwordless email-code authentication, OIDC discovery, JWKS, authorization code + refresh token flows with PKCE, consent management, federated login from external providers, and email verification.

## Requirements

- Python 3.14 (managed via [`uv`](https://docs.astral.sh/uv/))
- MongoDB 7+ (locally via Docker, or your own instance)
- An SMTP relay for verification emails (in dev: any service of your choosing)

## Quickstart with Docker

```bash
docker compose up
```

This starts both MongoDB and the Verys backend (on port `8080`). The container builds with the `dev` config by default; override with `--build-arg ENV=prod` if needed.

OIDC discovery is then available at:

```
http://localhost:8080/.well-known/openid-configuration
```

## Local development

```bash
docker compose up mongo -d   # or point MONGO_URI at your own instance
uv sync                      # installs runtime + test deps; creates .venv
uv run uvicorn verys.app:app --reload --port 8080
```

There are no migrations: collections and indexes are created on startup (see `ensure_indexes` in [src/verys/database.py](src/verys/database.py)).

Tests (both suites need a running MongoDB and `JWT_PRIVATE_KEY` in the environment):

```bash
cp src/verys/config/config.test.py src/verys/config/config.py
export JWT_PRIVATE_KEY="$(openssl genpkey -algorithm ed25519)"
uv run pytest tests/unit          # model / persistence layer
uv run pytest tests/functional    # endpoint tests
```

## Configuration

Environment-specific config lives in [src/verys/config/](src/verys/config/). At build time, the appropriate file is copied to `config.py`:

```
src/verys/config/
├── config.dev.py     # local development defaults
├── config.prod.py    # reads from environment variables
├── config.test.py    # used by the test suite
└── config.py         # selected at build/deploy time (gitignored)
```

Key environment variables expected in production:

| Variable | Purpose |
|---|---|
| `MONGO_URI` | MongoDB connection string |
| `MONGO_DB_NAME` | Database name (default `verys`) |
| `JWT_PRIVATE_KEY` | PEM-encoded Ed25519 signing key for OIDC tokens |
| `USERNAME_SMTP` / `PASSWORD_SMTP` | SMTP relay credentials for verification emails |
| `VERYS_CLIENT_ID` | OAuth2 client ID seeded at startup |
| `VERYS_CLIENT_REDIRECT_URI` | Where the Verys public client redirects after auth |
| `VERYS_CLIENT_REGISTRATION_URI` | External registration page URL (optional) |
| `OPENOBSERVE_ENDPOINT` / `OPENOBSERVE_USER` / `OPENOBSERVE_TOKEN` | Log shipping (optional) |

## Data model

Each model in [src/verys/models/](src/verys/models/) is a pydantic schema plus a collection name and a natural key. Persistence is the generic API on `Base`: `upsert`, `get`, `all`, `delete`. Route handlers read a document, edit the dict, and upsert it back.

- Deletes are soft: fields are nulled and the document is marked `deleted`. Unique indexes are partial on live documents.
- Every write appends the resulting document state to the document's `log` array.
- Roles are embedded in identity documents; `Role.pipeline` (a `$lookup`/`$merge` aggregation) re-syncs the embedded copies after any change to the `role` collection and at startup.
- Short-lived collections (auth codes, OAuth2/federation sessions, verification codes) expire via TTL indexes.

## Project layout

```
verys/
├── pyproject.toml          # project metadata + deps
├── uv.lock                 # resolved dependency graph
├── Dockerfile              # uv-based, src-layout aware
├── docker-compose.yml      # mongo + verys services
├── tests/
│   ├── unit/
│   ├── functional/
│   └── integration/
└── src/
    └── verys/
        ├── app.py          # Starlette app + lifespan (indexes, seeding)
        ├── database.py     # Mongo client per event loop + index definitions
        ├── config/
        ├── middleware/     # request logging, JWT auth
        ├── models/         # pydantic schemas + generic Mongo persistence
        ├── modules/        # JWT, cookies, PKCE, encryption, etc.
        ├── routes/         # Starlette route handlers
        └── templates/      # Jinja2 templates for login / consent / register
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[BSD 3-Clause](LICENSE).
