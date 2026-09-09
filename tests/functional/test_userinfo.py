import jwt as pyjwt
from datetime import datetime, timedelta, timezone

from verys.models import Identity
from verys.modules.jwt import create_signed_jwt, _get_private_key
from verys.config import config


async def test_userinfo_get(db, client):
    admin = await Identity.get(email='admin@mcmlln.dev')
    token = create_signed_jwt(admin, ['openid', 'email'], config.ISSUER)
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['sub'] == admin['id']
    assert body['email'] == 'admin@mcmlln.dev'
    assert body['email_verified'] == True


async def test_userinfo_post(db, client):
    admin = await Identity.get(email='admin@mcmlln.dev')
    token = create_signed_jwt(admin, ['openid'], config.ISSUER)
    res = client.post(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['sub'] == admin['id']


async def test_userinfo_includes_roles(db, client):
    admin = await Identity.get(email='admin@mcmlln.dev')
    token = create_signed_jwt(admin, ['openid'])
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    body = res.json()
    assert 'roles' in body
    assert 'admin' in body['roles']


def test_userinfo_no_auth(client):
    res = client.get('/userinfo')
    assert res.status_code == 401


def test_userinfo_invalid_token(client):
    res = client.get(
        '/userinfo',
        headers={'Authorization': 'Bearer invalid.jwt.token'},
    )
    assert res.status_code == 401


async def test_userinfo_expired_token(db, client):
    admin = await Identity.get(email='admin@mcmlln.dev')
    now = datetime.now(timezone.utc)
    payload = {
        'sub': admin['id'],
        'roles': ['admin'],
        'iat': now - timedelta(minutes=10),
        'exp': now - timedelta(minutes=5),
    }
    token = pyjwt.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Token expired'


def test_userinfo_missing_sub(client):
    now = datetime.now(timezone.utc)
    payload = {
        'roles': ['admin'],
        'iat': now,
        'exp': now + timedelta(minutes=5),
        'aud': config.ISSUER
    }
    token = pyjwt.encode(payload, _get_private_key(), algorithm='EdDSA')
    res = client.get(
        '/userinfo',
        headers={'Authorization': f'Bearer {token}'},
    )
    assert res.status_code == 401
    assert res.json()['error'] == 'Invalid token: missing subject'
