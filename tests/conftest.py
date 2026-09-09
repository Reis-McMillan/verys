from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from verys.app import app
from verys.config import config
from verys.database import close_db, ensure_indexes, get_client
from verys.models import Identity, Role
from verys.modules.cookie import encrypt_cookie
from verys.modules.jwt import create_signed_jwt

ADMIN_EMAIL = 'admin@mcmlln.dev'
ADMIN_KEY = 'paris_people'
SERVICE_EMAIL = 'service@mcmlln.dev'
SERVICE_KEY = 'jd vance erika kirk baby'


@pytest.fixture(scope='module')
async def db():
    """Fresh database per test module, seeded with an admin and a service
    account. Runs on pytest's module event loop; the app under TestClient
    uses its own loop and therefore its own Mongo client."""
    await get_client().drop_database(config.MONGO_DB_NAME)
    await ensure_indexes()

    admin_role = await Role.upsert({'name': 'admin'})
    service_role = await Role.upsert({'name': 'service-account'})
    expires = datetime.now(timezone.utc) + timedelta(days=30)

    await Identity.upsert({
        'first_name': 'Admin',
        'last_name': 'User',
        'email': ADMIN_EMAIL,
        'auth_key': ADMIN_KEY,
        'expires': expires,
        'email_verified': True,
        'roles': [admin_role],
    })
    await Identity.upsert({
        'first_name': 'Service',
        'last_name': 'Account',
        'email': SERVICE_EMAIL,
        'auth_key': SERVICE_KEY,
        'expires': expires,
        'email_verified': True,
        'roles': [service_role],
    })

    yield

    await get_client().drop_database(config.MONGO_DB_NAME)
    await close_db()


@pytest.fixture(scope='module')
async def admin_jwt(db):
    admin = await Identity.get(email=ADMIN_EMAIL)
    return create_signed_jwt(admin, ['openid'])


@pytest.fixture(scope='module')
def admin_creds():
    token, iv = encrypt_cookie(ADMIN_EMAIL, ADMIN_KEY)
    return token, iv


@pytest.fixture(scope='module')
def service_user_creds():
    token, iv = encrypt_cookie(SERVICE_EMAIL, SERVICE_KEY)
    return token, iv


@pytest.fixture(scope='module')
def client(db):
    with TestClient(app) as client:
        yield client
