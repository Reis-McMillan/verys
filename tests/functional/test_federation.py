"""Client-driven federation: /federation/initiate and /federation/callback."""
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from httpx import Response

from verys.models import ExternalProvider, ExternalToken, FederationSession, Identity
from tests.helpers import new_client

PROVIDER_ID = 'idp'
AUTHORIZATION_ENDPOINT = 'https://idp.example.com/authorize'
TOKEN_ENDPOINT = 'https://idp.example.com/token'
USERINFO_ENDPOINT = 'https://idp.example.com/userinfo'
CLIENT_REDIRECT_URI = 'https://app.example.com/cb'


@pytest.fixture(scope='module')
async def provider(db):
    return await ExternalProvider.upsert({
        'provider_id': PROVIDER_ID,
        'display_name': 'Example IdP',
        'client_id': 'verys-at-idp',
        'client_secret': 'top-secret',
        'authorization_endpoint': AUTHORIZATION_ENDPOINT,
        'token_endpoint': TOKEN_ENDPOINT,
        'userinfo_endpoint': USERINFO_ENDPOINT,
        'scopes': ['calendar.read'],
    })


@pytest.fixture(scope='module')
async def oauth_client(db):
    return await new_client('Federation App', [CLIENT_REDIRECT_URI])


@pytest.fixture
def browser(client, admin_creds):
    token, iv = admin_creds
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)
    yield client
    client.cookies.clear()


def _initiate(client, **params):
    return client.get(
        '/federation/initiate',
        params={'provider_id': PROVIDER_ID, **params},
        follow_redirects=False,
    )


async def _session(redirect_uri=None):
    admin = await Identity.get(email='admin@mcmlln.dev')
    return await FederationSession.upsert({
        'identity_id': admin['id'],
        'provider_id': PROVIDER_ID,
        'redirect_uri': redirect_uri,
    })


# -- initiate ---------------------------------------------------------------

def test_initiate_requires_browser_session(client, provider):
    assert _initiate(client).status_code == 401


def test_initiate_redirect_uri_requires_client_id(browser, provider):
    res = _initiate(browser, redirect_uri=CLIENT_REDIRECT_URI)
    assert res.status_code == 400
    assert 'together' in res.json()['error']


def test_initiate_client_id_requires_redirect_uri(browser, provider, oauth_client):
    res = _initiate(browser, client_id=oauth_client['client_id'])
    assert res.status_code == 400


def test_initiate_rejects_unknown_client(browser, provider):
    res = _initiate(browser, client_id='nope', redirect_uri=CLIENT_REDIRECT_URI)
    assert res.status_code == 400
    assert res.json()['error'] == 'Invalid client_id'


def test_initiate_rejects_unregistered_redirect_uri(browser, provider, oauth_client):
    res = _initiate(
        browser, client_id=oauth_client['client_id'],
        redirect_uri='https://evil.example.com/cb',
    )
    assert res.status_code == 400
    assert res.json()['error'] == 'Invalid redirect_uri'


def test_initiate_unknown_provider(browser, provider):
    res = _initiate(browser, provider_id='missing')
    assert res.status_code == 404


async def test_initiate_redirects_to_provider(db, browser, provider, oauth_client):
    res = _initiate(
        browser, client_id=oauth_client['client_id'], redirect_uri=CLIENT_REDIRECT_URI,
    )
    assert res.status_code == 302
    location = res.headers['location']
    assert location.startswith(AUTHORIZATION_ENDPOINT)
    params = parse_qs(urlparse(location).query)
    assert params['client_id'][0] == 'verys-at-idp'
    assert params['scope'][0] == 'calendar.read'

    fed_session = await FederationSession.get(session_id=params['state'][0])
    assert fed_session['redirect_uri'] == CLIENT_REDIRECT_URI
    assert 'oauth2_session_id' not in fed_session


# -- callback ---------------------------------------------------------------

async def test_callback_error_redirects_to_client(db, client, provider):
    fed_session = await _session(redirect_uri=f'{CLIENT_REDIRECT_URI}?keep=1')

    res = client.get(
        f'/federation/callback/{PROVIDER_ID}',
        params={
            'state': fed_session['session_id'],
            'error': 'access_denied',
            'error_description': 'User cancelled',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = urlparse(res.headers['location'])
    assert location.netloc == 'app.example.com' and location.path == '/cb'
    params = parse_qs(location.query)
    assert params['keep'][0] == '1'
    assert params['error'][0] == 'federation_failed'
    assert params['error_description'][0] == 'User cancelled'
    assert params['provider_id'][0] == PROVIDER_ID

    assert await FederationSession.get(session_id=fed_session['session_id']) is None


async def test_callback_error_without_redirect_returns_json(db, client, provider):
    fed_session = await _session()

    res = client.get(
        f'/federation/callback/{PROVIDER_ID}',
        params={'state': fed_session['session_id'], 'error': 'access_denied'},
        follow_redirects=False,
    )
    assert res.status_code == 400
    body = res.json()
    assert body['error'] == 'federation_failed'
    assert body['provider_id'] == PROVIDER_ID


def test_callback_unknown_session(client, provider):
    res = client.get(
        f'/federation/callback/{PROVIDER_ID}',
        params={'state': 'nope', 'code': 'abc'},
        follow_redirects=False,
    )
    assert res.status_code == 400


def _mock_upstream(router, refresh_token='rt-1'):
    router.post(TOKEN_ENDPOINT).mock(return_value=Response(200, json={
        'access_token': 'at-1',
        'refresh_token': refresh_token,
        'expires_in': 3600,
        'token_type': 'Bearer',
        'scope': 'calendar.read',
    }))
    router.get(USERINFO_ENDPOINT).mock(return_value=Response(200, json={
        'sub': 'idp-sub-1', 'email': 'admin@idp.example.com',
    }))


async def test_callback_success_stores_token_and_redirects(db, client, provider):
    fed_session = await _session(redirect_uri=CLIENT_REDIRECT_URI)

    with respx.mock(assert_all_called=True) as router:
        _mock_upstream(router)
        res = client.get(
            f'/federation/callback/{PROVIDER_ID}',
            params={'state': fed_session['session_id'], 'code': 'upstream-code'},
            follow_redirects=False,
        )

    assert res.status_code == 302
    location = urlparse(res.headers['location'])
    assert location.netloc == 'app.example.com' and location.path == '/cb'
    assert parse_qs(location.query) == {'provider_id': [PROVIDER_ID]}

    admin = await Identity.get(email='admin@mcmlln.dev')
    token = await ExternalToken.get(
        identity_id=admin['id'], provider_id=PROVIDER_ID, subject='idp-sub-1',
    )
    assert token['access_token'] == 'at-1'
    assert token['refresh_token'] == 'rt-1'
    assert token['scopes_granted'] == ['calendar.read']
    assert await FederationSession.get(session_id=fed_session['session_id']) is None


async def test_callback_success_without_redirect_returns_json(db, client, provider):
    fed_session = await _session()

    with respx.mock(assert_all_called=True) as router:
        _mock_upstream(router)
        res = client.get(
            f'/federation/callback/{PROVIDER_ID}',
            params={'state': fed_session['session_id'], 'code': 'upstream-code'},
            follow_redirects=False,
        )

    assert res.status_code == 200
    assert res.json()['provider'] == PROVIDER_ID
