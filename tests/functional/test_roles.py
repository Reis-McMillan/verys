"""Role management routes and the identity/role embedding they maintain."""
import pytest

from verys.models import Identity, Role
from verys.modules.jwt import create_signed_jwt
from tests.helpers import new_identity


@pytest.fixture(scope='module')
async def service_jwt(db):
    svc = await Identity.get(email='service@mcmlln.dev')
    return create_signed_jwt(svc, ['openid'])


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


def test_list_roles(admin_jwt, client):
    res = client.get('/roles/', headers=_auth(admin_jwt))
    assert res.status_code == 200
    assert res.json()['roles'] == ['admin', 'service-account']


def test_list_roles_no_admin(service_jwt, client):
    res = client.get('/roles/', headers=_auth(service_jwt))
    assert res.status_code == 403


def test_create_role(admin_jwt, client):
    res = client.post('/roles/', headers=_auth(admin_jwt), json={'name': 'auditor'})
    assert res.status_code == 201
    assert res.headers['Location'] == '/roles/auditor'


def test_create_role_duplicate(admin_jwt, client):
    res = client.post('/roles/', headers=_auth(admin_jwt), json={'name': 'auditor'})
    assert res.status_code == 409


def test_get_role_not_found(admin_jwt, client):
    res = client.get('/roles/nope', headers=_auth(admin_jwt))
    assert res.status_code == 404


async def test_assign_role(db, admin_jwt, client):
    await new_identity('auditee@example.com')

    res = client.post('/roles/auditor/identities/auditee@example.com', headers=_auth(admin_jwt))
    assert res.status_code == 201

    identity = await Identity.get(email='auditee@example.com')
    assert [r['name'] for r in identity['roles']] == ['auditor']

    # Idempotent
    res = client.post('/roles/auditor/identities/auditee@example.com', headers=_auth(admin_jwt))
    assert res.status_code == 200
    assert 'already has role' in res.json()['message']


def test_assign_role_unknown_identity(admin_jwt, client):
    res = client.post('/roles/auditor/identities/ghost@example.com', headers=_auth(admin_jwt))
    assert res.status_code == 404


def test_assign_role_unknown_role(admin_jwt, client):
    res = client.post('/roles/nope/identities/auditee@example.com', headers=_auth(admin_jwt))
    assert res.status_code == 404


def test_get_role_lists_members(admin_jwt, client):
    res = client.get('/roles/auditor', headers=_auth(admin_jwt))
    assert res.status_code == 200
    assert res.json()['identity_emails'] == ['auditee@example.com']


async def test_assigned_role_appears_in_jwt(db, client):
    """Roles embedded in the identity flow through to token claims and auth."""
    identity = await Identity.get(email='auditee@example.com')
    token = create_signed_jwt(identity, ['openid'])
    res = client.get('/roles/', headers=_auth(token))
    assert res.status_code == 403  # authenticated, but not admin

    admin = await Identity.get(email='admin@mcmlln.dev')
    admin['roles'].append(await Role.get(name='auditor'))
    await Identity.upsert(admin)
    res = client.get('/roles/auditor', headers=_auth(create_signed_jwt(admin, ['openid'])))
    assert sorted(res.json()['identity_emails']) == ['admin@mcmlln.dev', 'auditee@example.com']


async def test_revoke_role(db, admin_jwt, client):
    res = client.delete('/roles/auditor/identities/auditee@example.com', headers=_auth(admin_jwt))
    assert res.status_code == 200

    identity = await Identity.get(email='auditee@example.com')
    assert identity['roles'] == []

    res = client.delete('/roles/auditor/identities/auditee@example.com', headers=_auth(admin_jwt))
    assert res.status_code == 404


async def test_delete_role_propagates(db, admin_jwt, client):
    admin = await Identity.get(email='admin@mcmlln.dev')
    assert 'auditor' in [r['name'] for r in admin['roles']]

    res = client.delete('/roles/auditor', headers=_auth(admin_jwt))
    assert res.status_code == 200
    assert await Role.get(name='auditor') is None

    admin = await Identity.get(email='admin@mcmlln.dev')
    assert [r['name'] for r in admin['roles']] == ['admin']

    res = client.delete('/roles/auditor', headers=_auth(admin_jwt))
    assert res.status_code == 404
