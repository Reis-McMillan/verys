"""Behaviour of the generic persistence layer, exercised through Role and
RefreshToken (simple schemas with unique indexes)."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError
from pymongo.errors import DuplicateKeyError

from verys.models import RefreshToken, Role
from tests.helpers import ms


async def test_upsert_returns_stored_doc(db):
    role = await Role.upsert({'name': 'base-test'})
    assert uuid.UUID(role['id'])
    assert role['name'] == 'base-test'
    assert set(role) == {'id', 'name'}  # no _id / log / deleted leaks


async def test_get_and_all_filter_by_any_field(db):
    role = await Role.get(name='base-test')
    assert role is not None
    assert await Role.get(id=role['id']) == role
    assert role in await Role.all()
    assert await Role.all(name='base-test') == [role]
    assert await Role.get(name='nope') is None


async def test_upsert_replaces_and_logs(db):
    role = await Role.get(name='base-test')
    role['name'] = 'base-test-renamed'
    updated = await Role.upsert(role)
    assert updated['id'] == role['id']
    assert await Role.get(name='base-test') is None

    raw = await Role.collection().find_one({'id': role['id']})
    assert [entry['name'] for entry in raw['log']] == ['base-test', 'base-test-renamed']
    assert raw['deleted'] is False


async def test_unique_index_raises_duplicate_key(db):
    with pytest.raises(DuplicateKeyError):
        await Role.upsert({'name': 'base-test-renamed'})


async def test_unknown_field_rejected(db):
    with pytest.raises(ValidationError):
        await Role.upsert({'name': 'x', 'bogus': 1})


async def test_soft_delete(db):
    role = await Role.get(name='base-test-renamed')
    assert await Role.delete(id=role['id']) == 1
    assert await Role.get(id=role['id']) is None
    assert await Role.all(name='base-test-renamed') == []

    raw = await Role.collection().find_one({'log.id': role['id']})
    assert raw['deleted'] is True
    assert raw['id'] is None and raw['name'] is None
    assert isinstance(raw['deleted_at'], datetime)
    assert raw['log'][-1]['deleted'] is True


async def test_soft_deleted_docs_do_not_collide(db):
    for _ in range(2):
        role = await Role.upsert({'name': 'transient'})
        assert await Role.delete(id=role['id']) == 1
    assert await Role.delete(id='missing') == 0


async def test_delete_many(db):
    for _ in range(3):
        await RefreshToken.upsert({
            'client_id': 'bulk',
            'identity_id': str(uuid.uuid4()),
            'expires_at': datetime.now(timezone.utc) + timedelta(days=1),
        })
    assert await RefreshToken.delete(client_id='bulk') == 3
    assert await RefreshToken.all(client_id='bulk') == []


async def test_types_round_trip(db):
    identity_id = uuid.uuid4()
    expires = datetime.now(timezone.utc) + timedelta(days=1)
    rt = await RefreshToken.upsert({
        'client_id': 'types',
        'identity_id': identity_id,
        'expires_at': expires,
    })
    assert rt['identity_id'] == str(identity_id)  # UUIDs stored as strings
    assert rt['expires_at'] == ms(expires)  # BSON dates are ms precision
    assert rt['expires_at'].tzinfo is not None
