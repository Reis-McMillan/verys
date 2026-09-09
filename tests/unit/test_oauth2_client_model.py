from datetime import datetime, timezone

from verys.models.oauth2_client import OAuthClient


async def test_create(db):
    client = await OAuthClient.upsert({
        'client_name': 'Test App',
        'redirect_uris': ['https://example.com/callback'],
        'allowed_scopes': ['openid', 'email'],
    })

    assert len(client['client_id']) > 0
    assert client['client_name'] == 'Test App'
    assert client['redirect_uris'] == ['https://example.com/callback']
    assert client['allowed_scopes'] == ['openid', 'email']
    assert client['grant_types'] == ['authorization_code', 'refresh_token']
    assert client['response_types'] == ['code']
    assert client['token_endpoint_auth_method'] == 'client_secret_basic'
    assert client['is_public'] is False
    assert client['client_secret_hash'] is None
    assert client['created_at'] <= datetime.now(timezone.utc)


async def test_get_by_client_id(db):
    first = (await OAuthClient.all())[0]
    found = await OAuthClient.get(client_id=first['client_id'])
    assert found == first


async def test_get_by_client_id_not_found(db):
    assert await OAuthClient.get(client_id='nonexistent-id') is None


async def test_all(db):
    assert len(await OAuthClient.all()) >= 1


async def test_create_public_client(db):
    client = await OAuthClient.upsert({
        'client_name': 'Public SPA',
        'redirect_uris': ['http://localhost:3000/callback'],
        'is_public': True,
        'token_endpoint_auth_method': 'none',
    })
    assert client['is_public'] is True
    assert client['token_endpoint_auth_method'] == 'none'
    assert client['client_secret_hash'] is None


async def test_create_with_owner(db):
    client = await OAuthClient.upsert({
        'client_name': 'Owned App',
        'redirect_uris': ['https://owned.example.com/cb'],
        'owner_email': 'admin@mcmlln.dev',
    })
    assert client['owner_email'] == 'admin@mcmlln.dev'


async def test_multiple_redirect_uris(db):
    client = await OAuthClient.upsert({
        'client_name': 'Multi Redirect',
        'redirect_uris': [
            'https://app.example.com/callback',
            'https://app.example.com/auth/callback',
        ],
    })
    assert len(client['redirect_uris']) == 2


async def test_default_scopes(db):
    client = await OAuthClient.upsert({
        'client_name': 'Default Scopes App',
        'redirect_uris': ['https://default.example.com/cb'],
    })
    assert client['allowed_scopes'] == ['openid']
