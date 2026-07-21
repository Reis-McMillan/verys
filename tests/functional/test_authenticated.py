from datetime import datetime, timedelta, timezone
from unittest.mock import patch
import jwt as jwt_lib

from verys.app import app
from verys.modules.jwt import create_signed_jwt, _get_private_key


def test_not_requires_auth(client):
    res = client.get(
        '/providers',
    )
    assert res.status_code == 200


def test_missing_auth_header(client):
    res = client.get(
        '/identity',
    )
    assert res.status_code == 401
    result = res.json()
    assert result["error"] == "Authorization header required."


def test_bad_auth_header(client):
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer'}
    )
    assert res.status_code == 401
    assert res.json()["error"] == "Bad authorization header."


def test_bad_auth_header_2(client):
    res = client.get(
        '/identity',
        headers={'Authorization': 'BadFormat token123'}
    )
    assert res.status_code == 401
    assert res.json()['error'] == "Bad authorization header."


def test_jwt_auth_success(client, admin_jwt):
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'}
    )
    assert res.status_code == 200


def test_jwt_auth_expired_signature(session, client):
    from verys.models import Identity
    admin = Identity.get(session, 'admin@mcmlln.dev')
    now = datetime.now(timezone.utc)
    payload = {
        'sub': str(admin.id),
        'roles': ['admin'],
        'iat': now - timedelta(minutes=10),
        'exp': now - timedelta(minutes=5)
    }
    token = jwt_lib.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Not authenticated'


def test_missing_sub_claim(client):
    now = datetime.now(timezone.utc)
    payload = {
        'roles': ['admin'],
        'iat': now,
        'exp': now + timedelta(minutes=5)
    }
    token = jwt_lib.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Not authenticated'


def test_invalid_sub_claim(client):
    now = datetime.now(timezone.utc)
    payload = {
        'sub': 'invalid',
        'roles': ['admin'],
        'iat': now,
        'exp': now + timedelta(minutes=5)
    }
    token = jwt_lib.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Not authenticated'


def test_no_identity(client):
    now = datetime.now(timezone.utc)
    payload = {
        'sub': '-1',
        'roles': [],
        'iat': now,
        'exp': now + timedelta(minutes=5)
    }
    token = jwt_lib.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {token}'}
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Not authenticated'