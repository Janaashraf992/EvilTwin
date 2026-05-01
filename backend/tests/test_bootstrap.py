from types import SimpleNamespace

import pytest

from bootstrap import ensure_demo_user
from models import User
from services.auth import get_password_hash, verify_password


class FakeResult:
    def __init__(self, user):
        self._user = user

    def scalar_one_or_none(self):
        return self._user


class FakeSession:
    def __init__(self, existing_user=None):
        self.existing_user = existing_user
        self.added = []
        self.flushed = False

    async def execute(self, _statement):
        return FakeResult(self.existing_user)

    def add(self, user):
        self.added.append(user)
        self.existing_user = user

    async def flush(self):
        self.flushed = True


def _settings(**overrides):
    base = {
        "DEMO_BOOTSTRAP": True,
        "DEMO_USER_EMAIL": "analyst@eviltwin.local",
        "DEMO_USER_PASSWORD": "eviltwin-demo",
        "DEMO_USER_ROLE": "analyst",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.mark.asyncio
async def test_ensure_demo_user_creates_missing_user():
    session = FakeSession()

    created = await ensure_demo_user(session, _settings())

    assert created is True
    assert session.flushed is True
    assert len(session.added) == 1
    user = session.added[0]
    assert user.email == "analyst@eviltwin.local"
    assert user.role == "analyst"
    assert verify_password("eviltwin-demo", user.hashed_password)


@pytest.mark.asyncio
async def test_ensure_demo_user_updates_existing_user():
    user = User(
        email="analyst@eviltwin.local",
        hashed_password=get_password_hash("old-password"),
        role="viewer",
        is_active=False,
    )
    session = FakeSession(existing_user=user)

    updated = await ensure_demo_user(session, _settings(DEMO_USER_PASSWORD="fresh-password"))

    assert updated is True
    assert session.flushed is True
    assert session.added == []
    assert user.role == "analyst"
    assert user.is_active is True
    assert verify_password("fresh-password", user.hashed_password)


@pytest.mark.asyncio
async def test_ensure_demo_user_skips_when_disabled():
    session = FakeSession()

    skipped = await ensure_demo_user(session, _settings(DEMO_BOOTSTRAP=False))

    assert skipped is False
    assert session.flushed is False
    assert session.added == []