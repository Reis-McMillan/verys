from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from verys.models import Identity
from verys.modules.jwt import create_signed_jwt
from tests.helpers import new_identity


async def _ensure_identity(email):
    """Fetch or create a non-admin identity for JWT tests."""
    identity = await Identity.get(email=email)
    if identity is None:
        identity = await new_identity(email)
    return identity


def test_all(admin_jwt, client):
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'}
    )
    assert res.status_code == 200
    assert len(res.json()['identities']) == 2


async def test_all_no_admin(db, client):
    identity = await new_identity(
        'abella.danger@pornhub.com', 'Abella', 'Danger', 'missionary',
        datetime.now(timezone.utc) + timedelta(days=1),
    )
    jwt = create_signed_jwt(identity, ['openid'])
    res = client.get(
        '/identity',
        headers={'Authorization': f'Bearer {jwt}'}
    )
    assert res.status_code == 403
    assert res.json()['error'] == 'Not authorized to perform this action.'


def test_create(admin_jwt, client):
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        params={'email': 'stewie.griffin@quahog.com'}
    )
    url_safe_email = quote('stewie.griffin@quahog.com')
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{url_safe_email}'


def test_create_duplicate(admin_jwt, client):
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        params={'email': 'stewie.griffin@quahog.com'}
    )
    assert res.status_code == 400


def test_create_with_expires(admin_jwt, client):
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        params={'email': 'peter.griffin@quahog.com', 'expires': expires}
    )
    url_safe_email = quote('peter.griffin@quahog.com')
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{url_safe_email}'


async def test_create_no_admin(db, client):
    id = await Identity.get(email='stewie.griffin@quahog.com')
    jwt = create_signed_jwt(id, ['openid'])
    res = client.post(
        '/identity',
        headers={'Authorization': f'Bearer {jwt}'},
        params={'email': 'louis.griffin@quahog.com'}
    )
    assert res.status_code == 403
    assert res.json()['error'] == 'Not authorized to perform this action.'


def test_get_admin(admin_jwt, client):
    email = quote('stewie.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    res_json = res.json()
    assert res_json['email'] == 'stewie.griffin@quahog.com'
    assert res_json['closed'] == False


def test_get_not_found(admin_jwt, client):
    email = quote('louis.griffin@quahog.com')
    res = client.get(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'Identity not found'


async def test_get_not_admin(db, client):
    """Test that a non-admin cannot read another identity"""
    email = quote('admin@mcmlln.dev')
    jwt = create_signed_jwt(await _ensure_identity('jeevacation@gmail.com'), ['openid'])
    res = client.get(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == 'Not authorized to perform this action.'


def test_update(admin_jwt, client):
    email = quote('stewie.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={'new_expires': expires}
    )
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{email}'


async def test_update_no_admin(db, client):
    jwt = create_signed_jwt(await _ensure_identity('jeevacation@gmail.com'), ['openid'])
    email = quote('stewie.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {jwt}'},
        json={'new_expires': expires}
    )
    assert res.status_code == 403
    assert res.json()['error'] == 'Not authorized to perform this action.'


def test_update_no_params(admin_jwt, client):
    """Test that update without any parameters still succeeds (returns current state)"""
    email = quote('stewie.griffin@quahog.com')
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={}
    )
    assert res.status_code == 201
    assert res.headers['Location'] == f'/identity/{email}'


def test_update_no_id(admin_jwt, client):
    email = quote('louis.griffin@quahog.com')
    expires = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    res = client.put(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={'new_expires': expires}
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'No Identity found.'


async def test_delete(db, admin_jwt, client):
    email = quote('peter.griffin@quahog.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200

    closed = await Identity.get(email='peter.griffin@quahog.com')
    assert closed['closed'] is True


def test_delete_no_id(admin_jwt, client):
    email = quote('nonexistent@example.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404
    assert res.json()['error'] == "Identity not found"


async def test_delete_not_admin(db, client):
    jwt = create_signed_jwt(await _ensure_identity('jeevacation@gmail.com'), ['openid'])
    email = quote('peter.griffin@quahog.com')
    res = client.delete(
        f'/identity/{email}',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Not authorized to perform this action."


async def test_logout(db, client):
    id = await Identity.get(email='stewie.griffin@quahog.com')
    old_auth_key = id['auth_key']
    jwt = create_signed_jwt(id, ['openid'])
    res = client.post(
        '/identity/logout',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 201

    id = await Identity.get(email='stewie.griffin@quahog.com')
    assert id['auth_key'] != old_auth_key


async def test_admin_logout(db, admin_jwt, client):
    stewie = await Identity.get(email='stewie.griffin@quahog.com')
    res = client.post(
        f"identity/{stewie['id']}/logout",
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 201

    after = await Identity.get(email='stewie.griffin@quahog.com')
    assert after['auth_key'] != stewie['auth_key']


async def test_admin_logout_no_id(db, admin_jwt, client):
    # peter was closed above, so his id no longer resolves to an open identity
    peter = await Identity.get(email='peter.griffin@quahog.com')
    res = client.post(
        f"identity/{peter['id']}/logout",
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404


async def test_logout_not_admin(db, client):
    jwt = create_signed_jwt(await _ensure_identity('jeevacation@gmail.com'), ['openid'])
    stewie = await Identity.get(email='stewie.griffin@quahog.com')
    res = client.post(
        f"/identity/{stewie['id']}/logout",
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Not authorized to perform this action."
