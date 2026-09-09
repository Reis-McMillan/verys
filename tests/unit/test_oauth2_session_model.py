from datetime import datetime, timedelta, timezone

from verys.models.oauth2_session import OAuth2Session, OAUTH2_SESSION_TTL


def _doc(**overrides):
    return {
        'client_id': 'session-test-client',
        'redirect_uri': 'https://example.com/callback',
        'response_type': 'code',
        'scope': 'openid',
        **overrides,
    }


async def test_create(db):
    sess = await OAuth2Session.upsert(_doc(scope='openid email', state='random-state', nonce='random-nonce'))

    assert len(sess['session_id']) > 0
    assert sess['client_id'] == 'session-test-client'
    assert sess['scope'] == 'openid email'
    assert sess['state'] == 'random-state'
    assert sess['nonce'] == 'random-nonce'
    assert sess['csrf_token'] is None


async def test_get_by_session_id(db):
    sess = await OAuth2Session.upsert(_doc(client_id='lookup-test-client'))
    found = await OAuth2Session.get(session_id=sess['session_id'])
    assert found == sess


async def test_get_by_session_id_not_found(db):
    assert await OAuth2Session.get(session_id='nonexistent-session') is None


async def test_is_not_expired(db):
    sess = await OAuth2Session.upsert(_doc())
    assert OAuth2Session.is_expired(sess) is False


async def test_is_expired(db):
    sess = await OAuth2Session.upsert(_doc(
        created_at=datetime.now(timezone.utc) - timedelta(seconds=OAUTH2_SESSION_TTL + 1),
    ))
    assert OAuth2Session.is_expired(sess) is True


async def test_with_pkce(db):
    sess = await OAuth2Session.upsert(_doc(
        code_challenge='dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk',
        code_challenge_method='S256',
    ))
    assert sess['code_challenge'] == 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
    assert sess['code_challenge_method'] == 'S256'


async def test_delete(db):
    sess = await OAuth2Session.upsert(_doc(client_id='delete-test-client'))
    assert await OAuth2Session.delete(session_id=sess['session_id']) == 1
    assert await OAuth2Session.get(session_id=sess['session_id']) is None


async def test_expiry_is_enforced_by_ttl_index(db):
    """Expired sessions are purged by Mongo, not by application code."""
    indexes = await OAuth2Session.collection().index_information()
    ttl = [i for i in indexes.values() if i.get('key') == [('created_at', 1)]]
    assert ttl and ttl[0]['expireAfterSeconds'] == OAUTH2_SESSION_TTL
