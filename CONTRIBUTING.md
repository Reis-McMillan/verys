# Contributing to Verys

Thanks for your interest in contributing. This document covers how to set up a development environment, run the test suite, and submit changes.

## Development setup

Verys uses [`uv`](https://docs.astral.sh/uv/) for dependency management and Python 3.14 (pinned via [.python-version](.python-version)).

```bash
git clone <repo-url>
cd verys
uv sync
```

This creates a `.venv/`, installs runtime and test dependencies, and installs Verys in editable mode.

MongoDB is required for the tests and for running the app. The fastest path is the bundled `docker-compose.yml`:

```bash
docker compose up mongo -d
```

The app reads `MONGO_URI` (default `mongodb://localhost:27017`) and `MONGO_DB_NAME`; the test config uses the `verys_test` database and drops it between test modules.

## Running the app

```bash
uv run uvicorn verys.app:app --reload --port 8080
```

The OIDC discovery document is then available at `http://localhost:8080/.well-known/openid-configuration`.

## Running tests

```bash
cp src/verys/config/config.test.py src/verys/config/config.py
export JWT_PRIVATE_KEY="$(openssl genpkey -algorithm ed25519)"
uv run pytest tests/unit          # model / persistence layer tests
uv run pytest tests/functional    # endpoint tests
uv run pytest tests/unit tests/functional
```

Both suites need a running MongoDB. `tests/integration/` exercises external services (SMTP, OpenObserve) and is not run by default — invoke individual files directly when working on the relevant integration.

## Data layer conventions

- Models are thin: a pydantic schema (`extra="forbid"`) plus `name`, `identity_fields`, and `schema`. Persistence is the generic `Base` API only: `upsert`, `get`, `all`, `delete`. Do not add per-model query or mutation methods; put that logic in the route handler (read with `get`, edit the dict, write with `upsert`).
- Indexes live in `INDEXES` in `src/verys/database.py` and are created at startup by `ensure_indexes()`. Changing an existing index's options requires dropping it by hand (`create_index` with a conflicting spec raises); adding a new one is automatic.
- Every write appends the resulting document to the document's `log` array; deletes are soft. Reads hide `_id`, `log`, `deleted`, `deleted_at`.
- UUIDs are stored as strings and datetimes as BSON dates (millisecond precision). Keep `redirect_uri` fields as plain `str`, never pydantic URL types, because OAuth requires an exact match.
- If a model embeds documents from another collection (currently only `identity.roles`), declare a consistency `pipeline` on the canonical model (see `Role.pipeline`); `Base` runs it after every upsert/delete.

## Code style

- **Imports**: use absolute `verys.*` paths throughout (`from verys.modules.jwt import ...`, not `from modules.jwt`).
- **Templates**: load via `Path(__file__).resolve().parent.parent / "templates"` — never a bare relative path that depends on cwd.
- **Comments**: explain *why*, not *what*. Function and variable names should make the *what* obvious.
- **Type hints**: required on public function signatures; encouraged elsewhere.
- **Logging**: use `logging.getLogger("verys.<area>")` rather than `print()`.

## Submitting changes

1. Open an issue first for non-trivial changes so the approach can be discussed before you invest time.
2. Branch from `main`. Keep PRs focused — a refactor and a feature shouldn't ship in the same PR.
3. Run `uv run pytest tests/unit tests/functional` before pushing.
4. Write a PR description that explains the *why*. The diff already shows the *what*.

## Reporting security issues

Do not file public issues for security vulnerabilities. Email a maintainer privately and we'll coordinate disclosure.

## License

By contributing you agree that your contributions will be licensed under the [BSD 3-Clause License](LICENSE).
