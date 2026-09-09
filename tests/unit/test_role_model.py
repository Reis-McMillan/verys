"""Role documents embedded in identities stay consistent with the canonical
`role` collection via Role.pipeline."""
import pytest
from pymongo.errors import DuplicateKeyError

from verys.models import Identity, Role
from tests.helpers import new_identity


async def test_duplicate_name(db):
    with pytest.raises(DuplicateKeyError):
        await Role.upsert({'name': 'admin'})


async def test_embed_role(db):
    role = await Role.upsert({'name': 'tester'})
    identity = await new_identity('tester@example.com', roles=[role])
    assert identity['roles'] == [role]
    assert [i['email'] for i in await Identity.all(**{'roles.name': 'tester'})] == ['tester@example.com']


async def test_rename_propagates(db):
    role = await Role.get(name='tester')
    role['name'] = 'qa'
    await Role.upsert(role)

    identity = await Identity.get(email='tester@example.com')
    assert identity['roles'] == [{'id': role['id'], 'name': 'qa'}]


async def test_pipeline_is_idempotent(db):
    identity = await Identity.get(email='tester@example.com')
    before = await Identity.collection().find_one({'id': identity['id']})
    await Role.run_pipeline()
    after = await Identity.collection().find_one({'id': identity['id']})
    assert len(after['log']) == len(before['log'])


async def test_delete_propagates(db):
    role = await Role.get(name='qa')
    assert await Role.delete(id=role['id']) == 1

    identity = await Identity.get(email='tester@example.com')
    assert identity['roles'] == []
    # Admin seeded by the fixture is untouched.
    admin = await Identity.get(email='admin@mcmlln.dev')
    assert [r['name'] for r in admin['roles']] == ['admin']
