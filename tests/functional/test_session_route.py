from datetime import datetime, timedelta, timezone

from verys.models.identity import Identity
from verys.models.refresh_token import RefreshToken
from verys.modules.cookie import encrypt_cookie
from verys.modules.jwt import create_id_token
from tests.helpers import new_client


async def _refresh_token(identity: dict, client_id: str) -> dict:
    return await RefreshToken.upsert({
        'client_id': client_id,
        'identity_id': identity['id'],
        'scopes': ['openid'],
        'expires_at': datetime.now(timezone.utc) + timedelta(days=30),
    })


def test_end_session_clears_cookies(client):
    # Set cookies first
    token, iv = encrypt_cookie('admin@mcmlln.dev', 'paris_people')
    client.cookies.set('token', token)
    client.cookies.set('token_iv', iv)

    res = client.get('/end-session', follow_redirects=False)
    assert res.status_code == 200
    assert 'Logged Out' in res.text

    # Cookies should be cleared (set-cookie with max-age=0 or expires in the past)
    set_cookies = res.headers.get_list('set-cookie')
    cookie_names = [c.split('=')[0] for c in set_cookies]
    assert 'token' in cookie_names
    assert 'token_iv' in cookie_names

    client.cookies.clear()


async def test_end_session_with_id_token_hint(db, client):
    admin = await Identity.get(email="admin@mcmlln.dev")
    oa = await new_client(
        "Session Test App", ["https://session.example.com/callback"],
        secret="session-secret", allowed_scopes=["openid"],
    )

    # Create a refresh token for this user+client
    rt = await _refresh_token(admin, oa['client_id'])

    # Create id_token_hint
    id_token = create_id_token(
        identity=admin,
        client_id=oa['client_id'],
        client_scopes=["openid"],
        nonce=None,
        auth_time=datetime.now(timezone.utc),
    )

    res = client.get(
        '/end-session',
        params={'id_token_hint': id_token},
        follow_redirects=False,
    )
    assert res.status_code == 200

    # Verify the refresh token was revoked
    found = await RefreshToken.get(token=rt['token'])
    assert found['revoked'] is True


async def test_end_session_with_redirect(db, client):
    admin = await Identity.get(email="admin@mcmlln.dev")
    oa = await new_client(
        "Redirect Session App", ["https://session-redirect.example.com/callback"],
        secret="redirect-session-secret", allowed_scopes=["openid"],
    )

    id_token = create_id_token(
        identity=admin,
        client_id=oa['client_id'],
        client_scopes=["openid"],
        nonce=None,
        auth_time=datetime.now(timezone.utc),
    )

    res = client.get(
        '/end-session',
        params={
            'id_token_hint': id_token,
            'post_logout_redirect_uri': 'https://session-redirect.example.com/callback',
            'state': 'logout-state',
        },
        follow_redirects=False,
    )
    assert res.status_code == 302
    assert 'session-redirect.example.com/callback' in res.headers['location']
    assert 'logout-state' in res.headers['location']


async def test_end_session_redirect_invalid_uri(db, client):
    admin = await Identity.get(email="admin@mcmlln.dev")
    oa = await new_client(
        "Invalid Redirect Session App", ["https://valid.example.com/callback"],
        secret="inv-redirect-secret", allowed_scopes=["openid"],
    )

    id_token = create_id_token(
        identity=admin,
        client_id=oa['client_id'],
        client_scopes=["openid"],
        nonce=None,
        auth_time=datetime.now(timezone.utc),
    )

    # Use a redirect URI that's NOT registered
    res = client.get(
        '/end-session',
        params={
            'id_token_hint': id_token,
            'post_logout_redirect_uri': 'https://evil.example.com/callback',
        },
        follow_redirects=False,
    )
    # Should NOT redirect — show logout page instead
    assert res.status_code == 200
    assert 'Logged Out' in res.text


def test_end_session_no_params(client):
    res = client.get('/end-session', follow_redirects=False)
    assert res.status_code == 200
    assert 'Logged Out' in res.text


async def test_token_revoke(db, client):
    admin = await Identity.get(email="admin@mcmlln.dev")
    rt = await _refresh_token(admin, "revoke-route-client")

    res = client.post(
        '/token/revoke',
        data={'token': rt['token']},
    )
    assert res.status_code == 200

    found = await RefreshToken.get(token=rt['token'])
    assert found['revoked'] is True


def test_token_revoke_nonexistent(client):
    res = client.post(
        '/token/revoke',
        data={'token': 'nonexistent-token'},
    )
    # Per RFC 7009, always return 200
    assert res.status_code == 200


def test_token_revoke_no_token(client):
    res = client.post('/token/revoke', data={})
    assert res.status_code == 200
