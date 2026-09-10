from urllib.parse import parse_qs, urlparse

from verys.models.consent import Consent
from verys.models.external_token import ExternalToken
from verys.models.identity import Identity
from verys.models.oauth2_client import OAuthClient
from verys.models.oauth2_session import OAuth2Session
from verys.models.scope import Scope
from verys.modules.cookie import encrypt_cookie
from tests.helpers import new_client

REDIRECT_URI = 'https://authtest.example.com/callback'


async def _create_test_client(client_name="Auth Test App", redirect_uri="https://authtest.example.com/callback", scopes=None):
    """Helper to create a test OAuth2 client directly in the DB."""
    return await new_client(
        client_name,
        [redirect_uri],
        allowed_scopes=scopes or ["openid", "email", "profile"],
    )


def test_authorize_invalid_client_id(client):
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': 'nonexistent',
            'redirect_uri': 'https://example.com/cb',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 400
    assert 'Invalid client_id' in res.json()['error']


async def test_authorize_invalid_redirect_uri(db, client):
    oa = await _create_test_client("Redirect Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://evil.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 400
    assert 'Invalid redirect_uri' in res.json()['error']


async def test_authorize_unsupported_response_type(db, client):
    oa = await _create_test_client("Response Type Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'token',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'unsupported_response_type'


async def test_authorize_missing_openid_scope(db, client):
    oa = await _create_test_client("Scope Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'email',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'invalid_scope'


async def test_authorize_scope_not_allowed(db, client):
    oa = await _create_test_client("Scope Limit Test", scopes=["openid"])
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid email',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'invalid_scope'


async def test_authorize_unauthenticated_shows_login(db, client):
    oa = await _create_test_client("Login Test")
    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    # Should return the login HTML page (200)
    assert res.status_code == 200
    assert 'Sign In' in res.text
    assert 'Login Test' in res.text


async def test_authorize_authenticated_shows_consent(db, client):
    oa = await _create_test_client("Consent Test")

    # Set auth cookies
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid email',
        },
        follow_redirects=False,
    )
    assert res.status_code == 200
    assert 'Authorize Application' in res.text
    assert 'Consent Test' in res.text

    # Clean up cookies
    client.cookies.clear()


async def test_authorize_with_existing_consent_redirects(db, client):
    oa = await _create_test_client("Pre-consented Test")

    # Pre-grant consent
    admin = await Identity.get(email='admin@mcmlln.dev')
    await Consent.upsert({
        'identity_id': admin['id'],
        'client_id': oa['client_id'],
        'scopes': ['openid'],
    })

    # Set auth cookies
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
            'state': 'mystate123',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'mystate123'

    client.cookies.clear()


async def test_authorize_consent_approve(db, client):
    oa = await _create_test_client("Approve Consent Test")

    # Set auth cookies
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    # Create an oauth2 session with CSRF token
    csrf = 'test-csrf-approve'
    oauth2_sess = await OAuth2Session.upsert({
        'client_id': oa['client_id'],
        'redirect_uri': 'https://authtest.example.com/callback',
        'response_type': 'code',
        'scope': 'openid email',
        'state': 'consent-state',
        'csrf_token': csrf,
    })

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess['session_id'],
            'consent_action': 'approve',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'consent-state'

    # Consent is recorded against the identity id and the session is gone
    admin = await Identity.get(email='admin@mcmlln.dev')
    consent = await Consent.get(identity_id=admin['id'], client_id=oa['client_id'])
    assert consent['scopes'] == ['openid', 'email']
    assert await OAuth2Session.get(session_id=oauth2_sess['session_id']) is None

    client.cookies.clear()


async def test_authorize_consent_deny(db, client):
    oa = await _create_test_client("Deny Consent Test")

    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    csrf = 'test-csrf-deny'
    oauth2_sess = await OAuth2Session.upsert({
        'client_id': oa['client_id'],
        'redirect_uri': 'https://authtest.example.com/callback',
        'response_type': 'code',
        'scope': 'openid',
        'state': 'deny-state',
        'csrf_token': csrf,
    })

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess['session_id'],
            'consent_action': 'deny',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'access_denied'

    client.cookies.clear()


def test_authorize_consent_expired_session(client):
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': 'nonexistent-session-id',
            'consent_action': 'approve',
            'csrf_token': 'doesnt-matter',
        },
        follow_redirects=False,
    )
    assert res.status_code == 400

    client.cookies.clear()


async def test_authorize_consent_unauthenticated(db, client):
    oa = await _create_test_client("Unauth Consent Test")
    csrf = 'test-csrf-unauth'
    oauth2_sess = await OAuth2Session.upsert({
        'client_id': oa['client_id'],
        'redirect_uri': 'https://authtest.example.com/callback',
        'response_type': 'code',
        'scope': 'openid',
        'csrf_token': csrf,
    })

    # No cookies set
    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess['session_id'],
            'consent_action': 'approve',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 401


async def _federation_scope():
    """A scope fulfilled by an external provider; no provider record or
    external token is needed for the authorize endpoint to accept it."""
    return await Scope.upsert({
        'name': 'calendar', 'description': 'Read your calendar', 'provider_id': 'idp',
    })


async def test_authorize_federation_scope_issues_code_without_external_token(db, client):
    """Linking the provider is the client's job: authorize must not bounce to
    /federation/initiate when no external token exists for a federation scope."""
    await _federation_scope()
    oa = await _create_test_client("Federation Scope Test", scopes=["openid", "calendar"])

    admin = await Identity.get(email='admin@mcmlln.dev')
    assert await ExternalToken.all(identity_id=admin['id'], provider_id='idp') == []
    await Consent.upsert({
        'identity_id': admin['id'],
        'client_id': oa['client_id'],
        'scopes': ['openid', 'calendar'],
    })

    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': REDIRECT_URI,
            'scope': 'openid calendar',
            'state': 'fed-state',
            'prompt': 'none',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    assert location.startswith(REDIRECT_URI)
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'fed-state'

    client.cookies.clear()


async def test_authorize_consent_approve_federation_scope_issues_code(db, client):
    await _federation_scope()
    oa = await _create_test_client("Federation Consent Test", scopes=["openid", "calendar"])

    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    csrf = 'test-csrf-federation'
    oauth2_sess = await OAuth2Session.upsert({
        'client_id': oa['client_id'],
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid calendar',
        'state': 'fed-consent-state',
        'csrf_token': csrf,
    })

    res = client.post(
        '/authorize/consent',
        data={
            'oauth2_session_id': oauth2_sess['session_id'],
            'consent_action': 'approve',
            'csrf_token': csrf,
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    assert location.startswith(REDIRECT_URI)
    parsed = parse_qs(urlparse(location).query)
    assert 'code' in parsed
    assert parsed['state'][0] == 'fed-consent-state'
    assert await OAuth2Session.get(session_id=oauth2_sess['session_id']) is None

    client.cookies.clear()


async def test_authorize_public_client_requires_pkce(db, client):
    oa = await OAuthClient.upsert({
        'client_name': "PKCE Required Test",
        'redirect_uris': ["https://authtest.example.com/callback"],
        'allowed_scopes': ["openid"],
        'is_public': True,
        'token_endpoint_auth_method': "none",
    })

    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get(
        '/authorize',
        params={
            'response_type': 'code',
            'client_id': oa['client_id'],
            'redirect_uri': 'https://authtest.example.com/callback',
            'scope': 'openid',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    location = res.headers['location']
    parsed = parse_qs(urlparse(location).query)
    assert parsed['error'][0] == 'invalid_request'
    assert 'PKCE' in parsed['error_description'][0]

    client.cookies.clear()
