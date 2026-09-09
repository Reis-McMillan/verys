from datetime import datetime, timedelta, timezone

from verys.models.authorization_code import AuthorizationCode


def _doc(**overrides):
    now = datetime.now(timezone.utc)
    return {
        'client_id': 'test-client-id',
        'identity_email': 'user@example.com',
        'redirect_uri': 'https://example.com/callback',
        'auth_time': now,
        'expires_at': now + timedelta(seconds=60),
        **overrides,
    }


async def test_create(db):
    code = await AuthorizationCode.upsert(_doc(scopes=['openid', 'email'], nonce='test-nonce'))

    assert len(code['code']) == 64  # 32 bytes hex
    assert code['client_id'] == 'test-client-id'
    assert code['identity_email'] == 'user@example.com'
    assert code['scopes'] == ['openid', 'email']
    assert code['nonce'] == 'test-nonce'
    assert code['used'] is False
    assert code['created_at'] <= datetime.now(timezone.utc)


async def test_get_by_code(db):
    first = (await AuthorizationCode.all())[0]
    found = await AuthorizationCode.get(code=first['code'])
    assert found == first


async def test_get_by_code_not_found(db):
    assert await AuthorizationCode.get(code='nonexistent-code') is None


async def test_is_expired(db):
    code = await AuthorizationCode.upsert(
        _doc(expires_at=datetime.now(timezone.utc) - timedelta(seconds=10))
    )
    assert AuthorizationCode.is_expired(code) is True


async def test_is_not_expired(db):
    code = await AuthorizationCode.upsert(_doc())
    assert AuthorizationCode.is_expired(code) is False


async def test_mark_used(db):
    code = await AuthorizationCode.upsert(_doc())
    assert code['used'] is False

    code['used'] = True
    await AuthorizationCode.upsert(code)

    found = await AuthorizationCode.get(code=code['code'])
    assert found['used'] is True


async def test_with_pkce(db):
    code = await AuthorizationCode.upsert(_doc(
        code_challenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        code_challenge_method='S256',
    ))
    assert code['code_challenge'] == 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
    assert code['code_challenge_method'] == 'S256'


async def test_redirect_uri_is_not_normalized(db):
    code = await AuthorizationCode.upsert(_doc(redirect_uri='http://localhost:8080'))
    assert code['redirect_uri'] == 'http://localhost:8080'
