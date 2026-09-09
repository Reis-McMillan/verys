import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from verys.config import config
from verys.models import Identity, Role
from verys.modules.email import normalize_email
from tests.helpers import ms, new_identity


def test_normalize_email():
    assert normalize_email(' Bob72@example.com ') == 'bob72@example.com'


async def test_new(db):
    auth_key = Identity.make_auth_key()
    expires = datetime.now(timezone.utc) + timedelta(seconds=config.AUTHENTICATION_TTL)
    await new_identity(' Bob72@example.com ', 'Bob', 'Jones', auth_key, expires)

    res = await Identity.get(email='bob72@example.com')
    assert uuid.UUID(res['id'])
    assert res['email'] == 'bob72@example.com'
    assert res['first_name'] == 'Bob'
    assert res['last_name'] == 'Jones'
    assert res['auth_key'] == auth_key
    assert res['expires'] == ms(expires)
    assert res['origination'] <= datetime.now(timezone.utc)
    assert res['roles'] == []
    assert res['closed'] is False
    assert res['email_verified'] is False


async def test_duplicate(db):
    with pytest.raises(DuplicateKeyError):
        await new_identity('bob72@example.com')


async def test_not_email(db):
    with pytest.raises(ValidationError):
        await new_identity('not an email')


async def test_get_normalized(db):
    res = await Identity.get(email=normalize_email('boB72@example.com'))
    assert res['email'] == 'bob72@example.com'


async def test_get_none(db):
    assert await Identity.get(email='nothere@example.com') is None


async def test_update_new_key(db):
    identity = await Identity.get(email='bob72@example.com')
    original_expires = identity['expires']

    identity['auth_key'] = Identity.make_auth_key()
    res = await Identity.upsert(identity)
    assert res['auth_key'] == identity['auth_key']
    assert res['expires'] == original_expires


async def test_update_new_email(db):
    identity = await Identity.get(email='bob72@example.com')
    identity['email'] = 'newemail@example.com'
    res = await Identity.upsert(identity)
    assert res['email'] == 'newemail@example.com'
    assert res['id'] == identity['id']
    assert await Identity.get(email='bob72@example.com') is None


async def test_update_new_expires(db):
    identity = await Identity.get(email='newemail@example.com')
    identity['expires'] = datetime.now(timezone.utc) + timedelta(seconds=1000)
    res = await Identity.upsert(identity)
    assert res['expires'] == ms(identity['expires'])


async def test_assign_role(db):
    identity = await Identity.get(email='newemail@example.com')
    role = await Role.get(name='admin')
    identity['roles'] = [role]
    await Identity.upsert(identity)

    identity = await Identity.get(email='newemail@example.com')
    assert [r['name'] for r in identity['roles']] == ['admin']


async def test_close(db):
    identity = await Identity.get(email='newemail@example.com')
    identity['closed'] = True
    res = await Identity.upsert(identity)
    assert res['closed'] is True
    assert await Identity.get(email='newemail@example.com', closed=False) is None


async def test_all(db):
    res = await Identity.all()
    assert len(res) == 3
    assert res[0]['email'] == 'admin@mcmlln.dev'


async def test_history_logged(db):
    identity = await Identity.get(email='newemail@example.com')
    raw = await Identity.collection().find_one({'id': identity['id']})
    emails = [entry['email'] for entry in raw['log']]
    assert emails[0] == 'bob72@example.com'
    assert emails[-1] == 'newemail@example.com'
    assert raw['log'][-1]['closed'] is True
