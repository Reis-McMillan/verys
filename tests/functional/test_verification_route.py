from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

from verys.config import config
from verys.models import Verification, Identity
from tests.helpers import new_identity


async def _register(email: str):
    """Pre-create an Identity the way /register would have."""
    return await new_identity(email)


async def _make_entry(email: str, code: int, when: datetime | None = None) -> dict:
    entry = {'email': email, 'code': code}
    if when:
        entry['when'] = when
    return await Verification.upsert(entry)


async def test_request_verification(db, client):
    await _register('newuser@example.com')
    with patch('verys.routes.verification.aiosmtplib.send', new_callable=AsyncMock):
        res = client.post(
            '/verification',
            params={'email': 'newuser@example.com'}
        )
    assert res.status_code == 201


async def test_request_verification_creates_entry(db, client):
    await _register('entrycheck@example.com')
    with patch('verys.routes.verification.aiosmtplib.send', new_callable=AsyncMock):
        client.post(
            '/verification',
            params={'email': 'entrycheck@example.com'}
        )

    entry = await Verification.get(email='entrycheck@example.com')
    assert entry is not None
    assert entry['email'] == 'entrycheck@example.com'
    assert entry['email_sent'] is not None


async def test_verify_valid_code(db, client):
    await _register('verifytest@example.com')
    code = Verification.make_code()
    await _make_entry('verifytest@example.com', code)

    res = client.get(
        '/verification',
        params={'email': 'verifytest@example.com', 'code': str(code)}
    )
    assert res.status_code == 200
    assert config.ENCRYPT_COOKIE_NAME in res.cookies
    assert f"{config.ENCRYPT_COOKIE_NAME}_iv" in res.cookies

    # Code is single-use
    assert await Verification.get(email='verifytest@example.com') is None


async def test_verify_marks_email_verified(db, client):
    identity = await Identity.get(email='verifytest@example.com')
    assert identity is not None
    assert identity['email'] == 'verifytest@example.com'
    assert identity['email_verified'] is True
    assert identity['last_auth_time'] is not None


async def test_verify_refreshes_expired_identity(db, client):
    # Pre-create an identity whose session key has expired
    identity = await _register('existinguser@example.com')
    old_key = identity['auth_key']
    identity['expires'] = datetime.now(timezone.utc) - timedelta(days=1)
    await Identity.upsert(identity)

    code = Verification.make_code()
    await _make_entry('existinguser@example.com', code)

    res = client.get(
        '/verification',
        params={'email': 'existinguser@example.com', 'code': str(code)}
    )
    assert res.status_code == 200
    assert config.ENCRYPT_COOKIE_NAME in res.cookies

    identity = await Identity.get(email='existinguser@example.com')
    assert identity['auth_key'] != old_key
    assert identity['expires'] > datetime.now(timezone.utc)
    assert identity['email_verified'] is True


async def test_verify_invalid_code(db, client):
    await _register('invalidcode@example.com')
    code = Verification.make_code()
    await _make_entry('invalidcode@example.com', code)

    res = client.get(
        '/verification',
        params={'email': 'invalidcode@example.com', 'code': '000000'}
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'Invalid or expired code'


async def test_verify_expired_code(db, client):
    await _register('expiredcode@example.com')
    code = Verification.make_code()
    await _make_entry(
        'expiredcode@example.com', code,
        when=datetime.now(timezone.utc) - timedelta(hours=1),
    )

    res = client.get(
        '/verification',
        params={'email': 'expiredcode@example.com', 'code': str(code)}
    )
    assert res.status_code == 404
    assert res.json()['error'] == 'Invalid or expired code'


def test_verify_nonexistent_email(client):
    res = client.get(
        '/verification',
        params={'email': 'nobody@example.com', 'code': '123456'}
    )
    assert res.status_code == 404


def test_verify_non_numeric_code(client):
    res = client.get(
        '/verification',
        params={'email': 'test@example.com', 'code': 'abc'}
    )
    assert res.status_code == 404


async def test_email_send_failure(db, client):
    await _register('fail@example.com')
    with patch('verys.routes.verification.aiosmtplib.send', new_callable=AsyncMock, side_effect=Exception('SMTP error')):
        res = client.post(
            '/verification',
            params={'email': 'fail@example.com'}
        )
    assert res.status_code == 500
    assert res.json()['error'] == 'Email service failed.'


def test_missing_email_post(client):
    res = client.post('/verification')
    assert res.status_code == 422


def test_missing_params_get(client):
    res = client.get('/verification')
    assert res.status_code == 422
