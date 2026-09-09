"""Scope and external-provider admin routes, including the delete cascade."""
import uuid

import pytest
import respx
from httpx import Response

from verys.models import ExternalProvider, ExternalToken, Scope
from verys.modules.jwt import create_signed_jwt
from verys.models import Identity


DISCOVERY_URL = 'https://idp.example.com/.well-known/openid-configuration'


@pytest.fixture(scope='module')
async def service_jwt(db):
    svc = await Identity.get(email='service@mcmlln.dev')
    return create_signed_jwt(svc, ['openid'])


@pytest.fixture(scope='module')
def mock_discovery():
    router = respx.mock(assert_all_called=False)
    with router:
        yield router.get(DISCOVERY_URL).mock(return_value=Response(
            status_code=200,
            json={
                'jwks_uri': 'https://idp.example.com/jwks',
                'userinfo_endpoint': 'https://idp.example.com/userinfo',
            },
        ))


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


# -- scopes -----------------------------------------------------------------

def test_list_scopes_seeded(admin_jwt, client):
    res = client.get('/scopes/', headers=_auth(admin_jwt))
    assert res.status_code == 200
    assert sorted(s['name'] for s in res.json()['scopes']) == ['email', 'openid', 'profile']


def test_create_scope(admin_jwt, client):
    res = client.post('/scopes/', headers=_auth(admin_jwt), json={
        'name': 'calendar', 'description': 'Read your calendar', 'provider_id': 'idp',
    })
    assert res.status_code == 201
    assert res.json()['provider_id'] == 'idp'


def test_create_scope_duplicate(admin_jwt, client):
    res = client.post('/scopes/', headers=_auth(admin_jwt), json={
        'name': 'calendar', 'description': 'again',
    })
    assert res.status_code == 409


def test_update_scope(admin_jwt, client):
    res = client.put('/scopes/calendar', headers=_auth(admin_jwt), json={'description': 'Updated'})
    assert res.status_code == 200
    res = client.get('/scopes/calendar', headers=_auth(admin_jwt))
    assert res.json()['description'] == 'Updated'
    assert res.json()['provider_id'] == 'idp'


def test_scopes_require_admin(service_jwt, client):
    assert client.get('/scopes/', headers=_auth(service_jwt)).status_code == 403


def test_delete_standard_scope_refused(admin_jwt, client):
    res = client.delete('/scopes/openid', headers=_auth(admin_jwt))
    assert res.status_code == 400


def test_discovery_lists_new_scope(client):
    body = client.get('/.well-known/openid-configuration').json()
    assert 'calendar' in body['scopes_supported']


# -- providers --------------------------------------------------------------

def test_create_provider(admin_jwt, client, mock_discovery):
    res = client.post('/providers/', headers=_auth(admin_jwt), json={
        'provider_id': 'idp',
        'display_name': 'Example IdP',
        'client_id': 'verys-at-idp',
        'client_secret': 'top-secret',
        'authorization_endpoint': 'https://idp.example.com/authorize',
        'token_endpoint': 'https://idp.example.com/token',
        'discovery_url': DISCOVERY_URL,
        'scopes': ['calendar.read'],
    })
    assert res.status_code == 201, res.json()
    body = res.json()
    assert body['jwks_uri'] == 'https://idp.example.com/jwks'
    assert body['userinfo_endpoint'] == 'https://idp.example.com/userinfo'
    assert 'client_secret' not in body


async def test_provider_secret_encrypted_at_rest(db):
    raw = await ExternalProvider.collection().find_one({'provider_id': 'idp'})
    assert raw['client_secret'] != 'top-secret'
    provider = await ExternalProvider.get(provider_id='idp')
    assert provider['client_secret'] == 'top-secret'


def test_create_provider_duplicate(admin_jwt, client, mock_discovery):
    res = client.post('/providers/', headers=_auth(admin_jwt), json={
        'provider_id': 'idp',
        'display_name': 'Dup',
        'client_id': 'x',
        'client_secret': 'y',
        'authorization_endpoint': 'https://idp.example.com/authorize',
        'token_endpoint': 'https://idp.example.com/token',
        'discovery_url': DISCOVERY_URL,
    })
    assert res.status_code == 409


def test_list_and_get_provider_public(client):
    res = client.get('/providers/')
    assert res.status_code == 200
    assert [p['provider_id'] for p in res.json()['providers']] == ['idp']
    res = client.get('/providers/idp')
    assert res.status_code == 200
    assert res.json()['display_name'] == 'Example IdP'


async def test_update_provider(db, admin_jwt, client):
    res = client.put('/providers/idp', headers=_auth(admin_jwt), json={
        'display_name': 'Renamed IdP', 'client_secret': 'new-secret', 'enabled': False,
    })
    assert res.status_code == 200
    provider = await ExternalProvider.get(provider_id='idp')
    assert provider['display_name'] == 'Renamed IdP'
    assert provider['client_secret'] == 'new-secret'
    assert provider['enabled'] is False


def test_update_provider_requires_admin(service_jwt, client):
    res = client.put('/providers/idp', headers=_auth(service_jwt), json={'display_name': 'x'})
    assert res.status_code == 403


async def test_delete_provider_cascades(db, admin_jwt, client):
    admin = await Identity.get(email='admin@mcmlln.dev')
    token = await ExternalToken.upsert({
        'identity_id': admin['id'],
        'provider_id': 'idp',
        'email': 'admin@mcmlln.dev',
        'subject': 'sub-1',
        'access_token': 'at',
        'refresh_token': 'rt',
    })
    assert (await ExternalToken.get(id=token['id']))['access_token'] == 'at'

    res = client.delete('/providers/idp', headers=_auth(admin_jwt))
    assert res.status_code == 200

    assert await ExternalProvider.get(provider_id='idp') is None
    assert await Scope.get(name='calendar') is None
    assert await ExternalToken.get(id=token['id']) is None

    res = client.delete('/providers/idp', headers=_auth(admin_jwt))
    assert res.status_code == 404
