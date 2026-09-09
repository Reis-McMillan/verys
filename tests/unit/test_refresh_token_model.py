import uuid
from datetime import datetime, timedelta, timezone

from verys.models.refresh_token import RefreshToken

IDENTITY_ID = str(uuid.uuid4())


def _doc(**overrides):
    return {
        'client_id': 'test-client-id',
        'identity_id': IDENTITY_ID,
        'scopes': ['openid'],
        'expires_at': datetime.now(timezone.utc) + timedelta(days=30),
        **overrides,
    }


async def test_create(db):
    rt = await RefreshToken.upsert(_doc(scopes=['openid', 'email']))

    assert len(rt['token']) == 96  # 48 bytes hex
    assert rt['client_id'] == 'test-client-id'
    assert rt['identity_id'] == IDENTITY_ID
    assert rt['scopes'] == ['openid', 'email']
    assert rt['revoked'] is False
    assert rt['replaced_by'] is None


async def test_get_by_token(db):
    rt = await RefreshToken.upsert(_doc())
    found = await RefreshToken.get(token=rt['token'])
    assert found == rt


async def test_get_by_token_not_found(db):
    assert await RefreshToken.get(token='nonexistent-token') is None


async def test_is_expired(db):
    rt = await RefreshToken.upsert(_doc(expires_at=datetime.now(timezone.utc) - timedelta(days=1)))
    assert RefreshToken.is_expired(rt) is True


async def test_is_not_expired(db):
    rt = await RefreshToken.upsert(_doc())
    assert RefreshToken.is_expired(rt) is False


async def test_revoke(db):
    rt = await RefreshToken.upsert(_doc())
    rt['revoked'] = True
    await RefreshToken.upsert(rt)

    found = await RefreshToken.get(token=rt['token'])
    assert found['revoked'] is True
    assert found['replaced_by'] is None


async def test_revoke_with_replacement(db):
    rt = await RefreshToken.upsert(_doc())
    rt['revoked'] = True
    rt['replaced_by'] = 'new-token-value'
    await RefreshToken.upsert(rt)

    found = await RefreshToken.get(token=rt['token'])
    assert found['revoked'] is True
    assert found['replaced_by'] == 'new-token-value'


async def test_revoke_all_for_user_client(db):
    other = str(uuid.uuid4())
    for _ in range(3):
        await RefreshToken.upsert(_doc(client_id='revoke-test-client', identity_id=other))

    for rt in await RefreshToken.all(identity_id=other, client_id='revoke-test-client', revoked=False):
        rt['revoked'] = True
        await RefreshToken.upsert(rt)

    tokens = await RefreshToken.all(identity_id=other, client_id='revoke-test-client')
    assert len(tokens) == 3
    assert all(t['revoked'] for t in tokens)
