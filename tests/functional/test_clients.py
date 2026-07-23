from httpx import Response
import pytest
import respx

from verys.config import config
from verys.modules.jwt import create_signed_jwt


def test_create_client_no_admin(client, session):
    from verys.models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {jwt}'},
        json={
            'client_name': 'Unauthorized App',
            'redirect_uris': ['https://bad.example.com/cb'],
            'allowed_scopes': ['openid', 'email', 'profile']
        }
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Unauthorized to perform this action"


def test_create_client_bad_body(client, admin_jwt):
    res = client.post(
        '/clients/',
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={
            'client_name': 'Bad Client'
        }
    )
    assert res.status_code == 400
    print(res.json())


def test_create_client_unknown_scope(client, admin_jwt):
    res = client.post(
        '/clients/',
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={
            'client_name': 'New Client',
            'redirect_uris': ["https://good.example.com/cb"],
            'allowed_scopes': ['RIP Argentina 2026']
        }
    )
    assert res.status_code == 400
    assert res.json()['error'] == "Unknown scope 'RIP Argentina 2026'"


def test_create_client(admin_jwt, client):
    res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Test OIDC App',
            'redirect_uris': ['https://testapp.example.com/callback'],
            'allowed_scopes': ['openid', 'email', 'profile'],
        }
    )
    assert res.status_code == 201
    body = res.json()
    assert 'client_id' in body
    assert 'client_secret' in body
    assert body['client_name'] == 'Test OIDC App'
    assert body['redirect_uris'] == ['https://testapp.example.com/callback']
    assert body['allowed_scopes'] == ['openid', 'email', 'profile']
    assert body['is_public'] == False


def test_create_public_client(admin_jwt, client):
    res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Public SPA',
            'redirect_uris': ['http://localhost:3000/callback'],
            'is_public': True,
            'token_endpoint_auth_method': 'none',
        }
    )
    assert res.status_code == 201
    body = res.json()
    assert 'client_secret' not in body
    assert body['is_public'] == True


def test_list_clients_no_admin(client, session):
    from verys.models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.get(
        '/clients/',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Unauthorized to perform this action"


def test_list_clients(admin_jwt, client):
    res = client.get(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert isinstance(body['clients'], list)
    assert len(body['clients']) >= 2  # created in previous tests


def test_get_client_no_admin(session, client):
    from verys.models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.get(
        '/clients/fake-client',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Unauthorized to perform this action"


def test_get_client_not_found(admin_jwt, client):
    res = client.get(
        '/clients/nonexistent-id',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'Client not found'


@pytest.fixture(scope='module')
def mock_prm():
    with respx.mock:
        yield respx.get('https://get.example.com/.well-known/oauth-protected-resource')


@pytest.fixture(scope='module')
def client_id(admin_jwt, client, mock_prm):
    mock_prm.mock(return_value=Response(
        status_code=200,
        json={
            'authorization_servers': [config.ISSUER],
            'resource_name': 'Test App',
            'scopes_supported': ['openid', 'profile', 'email']
        }
    ))
    create_res = client.post(
        '/clients/',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Test App',
            'redirect_uris': ['https://get.example.com/cb'],
            'prm_uri': 'https://get.example.com/.well-known/oauth-protected-resource'
        }
    )
    client_id = create_res.json()['client_id']

    yield client_id


def test_get_client(admin_jwt, client, client_id):
    # First create one to get a known client_id
    res = client.get(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200
    body = res.json()
    assert body['client_id'] == client_id
    assert body['client_name'] == 'Test App'
    assert 'client_secret' not in body  # secret should never be returned


def test_update_client_no_admin(session, client):
    from verys.models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.get(
        '/clients/fake-client',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Unauthorized to perform this action"


def test_update_client_not_found(admin_jwt, client):
    res = client.put(
        '/clients/nonexistent-id',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={'client_name': 'Nope'}
    )
    assert res.status_code == 404


def test_update_client_invalid_scope(admin_jwt, client, client_id):
    res = client.put(
        f'/clients/{client_id}',
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={
            'client_name': 'Updated App Name',
            'allowed_scopes': ['invalid']
        }
    )
    assert res.status_code == 400
    assert res.json()['error'] == "Unknown scope 'invalid'"


def test_update_client_bad_prm_uri(admin_jwt, client, client_id):
    respx.get('https://invalid.prm.com/').mock(return_value=Response(status_code=500))
    res = client.put(
        f'/clients/{client_id}',
        headers={"Authorization": f"Bearer {admin_jwt}"},
        json={'prm_uri': 'https://invalid.prm.com/'}
    )
    assert res.status_code == 400


def test_update_client(admin_jwt, client, client_id):
    res = client.put(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
        json={
            'client_name': 'Updated App Name',
            'redirect_uris': ['https://updated.example.com/cb', 'https://updated2.example.com/cb'],
        }
    )
    assert res.status_code == 200

    # Verify update
    get_res = client.get(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    body = get_res.json()
    assert body['client_name'] == 'Updated App Name'
    assert len(body['redirect_uris']) == 2


def test_delete_client(session, client):
    from verys.models import Identity
    svc = Identity.get(session, 'service@mcmlln.dev')
    jwt = create_signed_jwt(svc, ['openid'])
    res = client.delete(
        '/clients/fake-client',
        headers={'Authorization': f'Bearer {jwt}'},
    )
    assert res.status_code == 403
    assert res.json()['error'] == "Unauthorized to perform this action"


def test_delete_client_not_found(admin_jwt, client):
    res = client.delete(
        '/clients/nonexistent-id',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 404


def test_delete_client(admin_jwt, client, client_id):
    res = client.delete(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert res.status_code == 200

    # Verify deleted
    get_res = client.get(
        f'/clients/{client_id}',
        headers={'Authorization': f'Bearer {admin_jwt}'},
    )
    assert get_res.status_code == 404
