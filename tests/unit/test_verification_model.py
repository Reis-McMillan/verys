from datetime import datetime, timezone

from verys.models import Verification
from verys.modules.email import normalize_email
from tests.helpers import ms


def test_make_code():
    res = Verification.make_code()
    assert res >= 100_000
    assert res < 1_000_000


def test_normalize_email():
    assert normalize_email(' Some.Body@Example.COM ') == 'some.body@example.com'


async def test_make_entry(db):
    code = Verification.make_code()
    res = await Verification.upsert({'email': ' Test@Example.com ', 'code': code})
    assert res['email'] == 'test@example.com'
    assert res['code'] == code
    assert res['when'] <= datetime.now(timezone.utc)
    assert res['email_sent'] is None


async def test_email_sent_at(db):
    sent = datetime.now(timezone.utc)
    entry = await Verification.get(email='test@example.com')
    entry['email_sent'] = sent
    res = await Verification.upsert(entry)
    assert res['email_sent'] == ms(sent)


async def test_overwrite_entry(db):
    code = Verification.make_code()
    entry = await Verification.get(email='test@example.com')
    entry['code'] = code
    res = await Verification.upsert(entry)
    assert res['code'] == code
    assert res['email_sent'] is not None  # preserved from the earlier write
    assert len(await Verification.all(email='test@example.com')) == 1


async def test_get_non_existent(db):
    assert await Verification.get(email='nonexistent@example.com') is None


async def test_get_by_email_and_code(db):
    entry = await Verification.get(email='test@example.com')
    assert await Verification.get(email='test@example.com', code=entry['code']) == entry
    assert await Verification.get(email='test@example.com', code=0) is None


async def test_delete(db):
    assert await Verification.delete(email='test@example.com') == 1
    assert await Verification.get(email='test@example.com') is None
