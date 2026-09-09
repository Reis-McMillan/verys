import base64
import hashlib
from datetime import datetime, timedelta, timezone

import jwt as pyjwt

from verys.config import config
from verys.models.authorization_code import AuthorizationCode
from verys.models.identity import Identity
from verys.models.refresh_token import RefreshToken
from verys.modules.jwt import get_public_key_pem
from tests.helpers import new_client


async def _create_client_and_code(**code_overrides):
    """Helper that creates an OAuth2 client and a valid authorization code."""
    oa = await new_client(
        "Token Test App",
        ["https://tokentest.example.com/callback"],
        secret="token-test-secret",
        allowed_scopes=["openid", "email", "profile"],
    )

    now = datetime.now(timezone.utc)
    defaults = dict(
        client_id=oa["client_id"],
        identity_email="admin@mcmlln.dev",
        redirect_uri="https://tokentest.example.com/callback",
        scopes=["openid", "email"],
        auth_time=now,
        expires_at=now + timedelta(seconds=60),
    )
    defaults.update(code_overrides)

    auth_code = await AuthorizationCode.upsert(defaults)
    return oa, auth_code


def _basic_auth_header(client_id, client_secret):
    creds = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    return {"Authorization": f"Basic {creds}"}


async def test_token_authorization_code(db, client):
    oa, auth_code = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 200
    body = res.json()
    assert 'access_token' in body
    assert 'id_token' in body
    assert 'refresh_token' in body
    assert body['token_type'] == 'Bearer'
    assert body['expires_in'] == config.JWT_EXPIRY

    # Verify access token
    public_key = get_public_key_pem()
    admin = await Identity.get(email='admin@mcmlln.dev')
    decoded = pyjwt.decode(body['access_token'], public_key, algorithms=["EdDSA"], options={"verify_aud": False})
    assert decoded['sub'] == admin['id']
    assert decoded['iss'] == config.ISSUER

    # Verify ID token
    id_decoded = pyjwt.decode(body['id_token'], public_key, algorithms=["EdDSA"], options={"verify_aud": False})
    assert id_decoded['sub'] == admin['id']
    assert id_decoded['aud'] == oa['client_id']
    assert id_decoded['iss'] == config.ISSUER
    assert 'auth_time' in id_decoded
    assert 'at_hash' in id_decoded

    # The code is now single-use
    used = await AuthorizationCode.get(code=auth_code['code'])
    assert used['used'] is True


async def test_token_authorization_code_with_nonce(db, client):
    oa, auth_code = await _create_client_and_code(nonce="test-nonce-value")

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 200
    body = res.json()

    public_key = get_public_key_pem()
    id_decoded = pyjwt.decode(body['id_token'], public_key, algorithms=["EdDSA"], options={"verify_aud": False})
    assert id_decoded['nonce'] == 'test-nonce-value'


async def test_token_authorization_code_post_auth(db, client):
    """Test client_secret_post authentication method."""
    oa, auth_code = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
            'client_id': oa['client_id'],
            'client_secret': 'token-test-secret',
        },
    )
    assert res.status_code == 200
    assert 'access_token' in res.json()


async def test_token_invalid_client(db, client):
    _, auth_code = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header("nonexistent", "bad-secret"),
    )
    assert res.status_code == 401


async def test_token_wrong_client_secret(db, client):
    oa, auth_code = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "wrong-secret"),
    )
    assert res.status_code == 401


async def test_token_invalid_code(db, client):
    oa, _ = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': 'nonexistent-code',
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_expired_code(db, client):
    oa, auth_code = await _create_client_and_code(
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=10),
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_used_code(db, client):
    oa, auth_code = await _create_client_and_code()
    auth_code['used'] = True
    await AuthorizationCode.upsert(auth_code)

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_wrong_redirect_uri(db, client):
    oa, auth_code = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://wrong.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_wrong_client_for_code(db, client):
    _, auth_code = await _create_client_and_code()

    # Create a different client
    other = await new_client("Other Client", ["https://other.example.com/cb"], secret="other-secret")

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(other['client_id'], "other-secret"),
    )
    assert res.status_code == 400


async def test_token_pkce_success(db, client):
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    oa, auth_code = await _create_client_and_code(
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
            'code_verifier': code_verifier,
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 200
    assert 'access_token' in res.json()


async def test_token_pkce_wrong_verifier(db, client):
    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    oa, auth_code = await _create_client_and_code(
        code_challenge=code_challenge,
        code_challenge_method="S256",
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
            'code_verifier': 'wrong-verifier',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_pkce_missing_verifier(db, client):
    oa, auth_code = await _create_client_and_code(
        code_challenge="some-challenge",
        code_challenge_method="S256",
    )

    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_unsupported_grant_type(db, client):
    oa, _ = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'client_credentials',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


# ──────────────────────────────────────────────
# Refresh token grant
# ──────────────────────────────────────────────

async def test_token_refresh(db, client):
    oa, auth_code = await _create_client_and_code()

    # First get tokens via authorization_code
    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    first_tokens = res.json()

    # Now refresh
    res2 = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': first_tokens['refresh_token'],
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res2.status_code == 200
    body = res2.json()
    assert 'access_token' in body
    assert 'id_token' in body
    assert 'refresh_token' in body
    # Refresh token rotation: new token should differ
    assert body['refresh_token'] != first_tokens['refresh_token']

    old = await RefreshToken.get(token=first_tokens['refresh_token'])
    assert old['revoked'] is True
    assert old['replaced_by'] == body['refresh_token']


async def test_token_refresh_revoked(db, client):
    oa, auth_code = await _create_client_and_code()

    # Get tokens
    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    tokens = res.json()

    # Revoke the refresh token
    rt = await RefreshToken.get(token=tokens['refresh_token'])
    rt['revoked'] = True
    await RefreshToken.upsert(rt)

    # Try to use revoked token
    res2 = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token'],
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res2.status_code == 400


async def test_token_refresh_invalid_token(db, client):
    oa, _ = await _create_client_and_code()

    res = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': 'nonexistent-token',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    assert res.status_code == 400


async def test_token_refresh_wrong_client(db, client):
    oa, auth_code = await _create_client_and_code()

    # Get tokens
    res = client.post(
        '/token',
        data={
            'grant_type': 'authorization_code',
            'code': auth_code['code'],
            'redirect_uri': 'https://tokentest.example.com/callback',
        },
        headers=_basic_auth_header(oa['client_id'], "token-test-secret"),
    )
    tokens = res.json()

    # Create a different client
    other = await new_client("Other Refresh Client", ["https://other.example.com/cb"], secret="other-secret")

    # Try to use token with different client
    res2 = client.post(
        '/token',
        data={
            'grant_type': 'refresh_token',
            'refresh_token': tokens['refresh_token'],
        },
        headers=_basic_auth_header(other['client_id'], "other-secret"),
    )
    assert res2.status_code == 400
