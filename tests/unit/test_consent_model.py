import uuid
from datetime import datetime, timezone

from verys.models.consent import Consent
from verys.routes.oauth2 import _covers_scopes

IDENTITY_ID = str(uuid.uuid4())


async def test_grant(db):
    consent = await Consent.upsert({
        'identity_id': IDENTITY_ID,
        'client_id': 'consent-test-client',
        'scopes': ['openid', 'email'],
    })

    assert consent['identity_id'] == IDENTITY_ID
    assert consent['client_id'] == 'consent-test-client'
    assert consent['scopes'] == ['openid', 'email']
    assert consent['granted_at'] <= datetime.now(timezone.utc)


async def test_get(db):
    found = await Consent.get(identity_id=IDENTITY_ID, client_id='consent-test-client')
    assert found is not None
    assert found['scopes'] == ['openid', 'email']


async def test_get_not_found(db):
    assert await Consent.get(identity_id=str(uuid.uuid4()), client_id='no-client') is None


async def test_covers_scopes(db):
    consent = await Consent.get(identity_id=IDENTITY_ID, client_id='consent-test-client')
    assert _covers_scopes(consent, ['openid']) is True
    assert _covers_scopes(consent, ['openid', 'email']) is True
    assert _covers_scopes(consent, ['openid', 'profile']) is False


async def test_grant_updates_existing(db):
    consent = await Consent.get(identity_id=IDENTITY_ID, client_id='consent-test-client')
    consent['scopes'] = ['openid', 'email', 'profile']
    consent['granted_at'] = datetime.now(timezone.utc)
    updated = await Consent.upsert(consent)
    assert updated['scopes'] == ['openid', 'email', 'profile']

    # Still exactly one live record for this identity/client pair
    assert len(await Consent.all(identity_id=IDENTITY_ID, client_id='consent-test-client')) == 1


async def test_multiple_clients(db):
    await Consent.upsert({
        'identity_id': IDENTITY_ID,
        'client_id': 'another-client',
        'scopes': ['openid'],
    })

    assert len(await Consent.all(identity_id=IDENTITY_ID)) == 2
