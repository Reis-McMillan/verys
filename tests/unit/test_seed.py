"""Startup seeding is idempotent and fills gaps without overwriting."""
import pytest

from verys.config import config
from verys.models import ExternalProvider, OAuthClient, Role, Scope
from verys.seed import seed_defaults, seed_providers


def _google(**overrides):
    return {
        'provider_id': 'google',
        'display_name': 'Google',
        'client_id': 'google-client-id',
        'client_secret': 'google-secret',
        'authorization_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint': 'https://oauth2.googleapis.com/token',
        'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs',
        'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo',
        'scopes': ['openid', 'email', 'profile'],
        'scope': {'name': 'google', 'description': 'Link your Google account'},
        **overrides,
    }


@pytest.fixture
def seed_config(monkeypatch):
    def _set(providers):
        monkeypatch.setattr(config, 'SEED_PROVIDERS', providers, raising=False)
    return _set


async def test_seed_defaults_creates_roles_scopes_and_client(db, seed_config):
    seed_config([])
    await seed_defaults()

    assert sorted(r['name'] for r in await Role.all()) == ['admin', 'service-account']
    assert sorted(s['name'] for s in await Scope.all()) == ['email', 'openid', 'profile']
    verys = await OAuthClient.get(client_id=config.VERYS_CLIENT_ID)
    assert verys['is_public'] is True
    assert 'google' in verys['allowed_scopes']


async def test_seed_provider_and_scope(db, seed_config):
    seed_config([_google()])
    await seed_providers()

    provider = await ExternalProvider.get(provider_id='google')
    assert provider['display_name'] == 'Google'
    assert provider['client_secret'] == 'google-secret'
    raw = await ExternalProvider.collection().find_one({'provider_id': 'google'})
    assert raw['client_secret'] != 'google-secret'  # encrypted at rest

    scope = await Scope.get(name='google')
    assert scope['provider_id'] == 'google'
    assert scope['description'] == 'Link your Google account'


async def test_seed_does_not_overwrite_existing(db, seed_config):
    provider = await ExternalProvider.get(provider_id='google')
    provider['enabled'] = False
    provider['client_secret'] = 'rotated'
    await ExternalProvider.upsert(provider)
    raw_before = await ExternalProvider.collection().find_one({'provider_id': 'google'})

    seed_config([_google(display_name='Google (changed)')])
    await seed_providers()

    provider = await ExternalProvider.get(provider_id='google')
    assert provider['enabled'] is False
    assert provider['client_secret'] == 'rotated'
    assert provider['display_name'] == 'Google'
    raw_after = await ExternalProvider.collection().find_one({'provider_id': 'google'})
    assert len(raw_after['log']) == len(raw_before['log'])


async def test_seed_refills_missing_scope(db, seed_config):
    await Scope.delete(name='google')
    seed_config([_google()])
    await seed_providers()
    assert (await Scope.get(name='google'))['provider_id'] == 'google'


async def test_seed_skips_provider_without_credentials(db, seed_config):
    seed_config([_google(provider_id='nocreds', client_secret=None,
                         scope={'name': 'nocreds', 'description': 'x'})])
    await seed_providers()

    assert await ExternalProvider.get(provider_id='nocreds') is None
    assert await Scope.get(name='nocreds') is None
