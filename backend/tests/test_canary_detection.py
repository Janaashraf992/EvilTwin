"""Unit tests for honeypot-side canary detection and the shared trigger."""

import ast
import types
import uuid
from pathlib import Path

import pytest

import services.canary as canary
from models import Alert, AttackerProfile, CanaryToken
from services.canary import match_bait_token, trigger_canary


# ---------------------------------------------------------------------------
# Bait pattern matching (pure)
# ---------------------------------------------------------------------------
def test_match_bait_token_cowrie_commands():
    assert match_bait_token("cat /root/.ssh/id_rsa", "cowrie") == ("7aedcaf0-b627-4f6f-95e8-5e59d891147e")
    assert match_bait_token("cat /tmp/database_backup.sql", "cowrie") == ("e8ca06a6-7123-4a08-9262-38c347248e51")
    assert (
        match_bait_token("cat /var/backups/db/prod_db_dump.sql", "cowrie")
        == "a1b2c3d4-e5f6-4071-8293-a4b5c6d7e8f9"
    )
    assert match_bait_token("cat /home/deploy/.aws/credentials", "cowrie") == ("c3f1a2b4-5d6e-4f80-9a1b-2c3d4e5f6071")
    assert match_bait_token("cat /opt/app/.env", "cowrie") == ("d4e2b3c5-6e7f-4a91-8b2c-3d4e5f607182")
    assert match_bait_token("cat /root/.bash_history", "cowrie") == ("b7c8d9e0-1f23-4a56-8b9c-0d1e2f3a4b5c")


def test_match_bait_token_dionaea_requests():
    assert match_bait_token("RETR aws_credentials", "dionaea") == ("083ee719-79d9-4174-b471-076ecc4248d7")
    assert match_bait_token("GET /passwords.txt", "dionaea") == ("19eee70f-aefd-4afb-ab06-3598d374876b")


def test_match_bait_token_ignores_benign_and_tripwire_baits():
    # .env.production is served by the tripwire (HMAC webhook), not detected here.
    assert match_bait_token("GET /.env.production", "dionaea") is None
    assert match_bait_token("ls -la", "cowrie") is None
    assert match_bait_token("", "cowrie") is None
    assert match_bait_token(None, "cowrie") is None


def test_every_planted_cowrie_bait_has_detection_pattern():
    """Guardrail: every bait planted into the Cowrie fake filesystem must have a
    matching detection pattern, otherwise reading it raises no canary/alert.

    Prevents drift between honeypots/cowrie/plant_baits.py (what is planted) and
    services/canary.py (what is detected) — the gap that let an attacker read
    /root/aws_keys.csv, /root/credentials.txt and /root/backups/prod_db_dump.sql
    over SSH without firing any alert.
    """
    plant_baits = (
        Path(__file__).resolve().parents[2] / "honeypots" / "cowrie" / "plant_baits.py"
    )
    assert plant_baits.is_file(), f"plant_baits.py not found at {plant_baits}"

    tree = ast.parse(plant_baits.read_text(encoding="utf-8"))
    baits = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "BAITS" for t in node.targets
        ):
            baits = ast.literal_eval(node.value)
            break
    assert baits, "Could not locate BAITS list in plant_baits.py"

    unmapped = [
        bait[0]
        for bait in baits
        if match_bait_token(f"cat {bait[0]}", "cowrie") is None
    ]
    assert not unmapped, (
        "Planted Cowrie baits with no detection pattern in services.canary "
        f"(reading them fires no alert): {unmapped}"
    )


# ---------------------------------------------------------------------------
# Shared trigger (with a lightweight fake async session)
# ---------------------------------------------------------------------------
class _FakeAlertManager:
    def __init__(self):
        self.broadcasts = []

    async def broadcast(self, data):
        self.broadcasts.append(data)


class _FakeState:
    def __init__(self):
        self.threat_scorer = None
        self.splunk_forwarder = None
        self.alert_manager = _FakeAlertManager()


class _FakeSession:
    def __init__(self, store):
        self._store = store
        self.added = []

    async def get(self, model, pk):
        return self._store.get((model.__name__, str(pk)))

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None


@pytest.fixture(autouse=True)
def _reset_cooldown():
    canary._last_fired.clear()
    yield
    canary._last_fired.clear()


async def test_trigger_canary_creates_alert_and_bumps_token():
    token = CanaryToken(
        id=uuid.UUID("7aedcaf0-b627-4f6f-95e8-5e59d891147e"),
        label="Root SSH key",
        difficulty=4,
        score_value=0.6,
        trigger_count=0,
    )
    db = _FakeSession({("CanaryToken", str(token.id)): token})
    state = _FakeState()

    alert = await trigger_canary(
        db,
        str(token.id),
        "203.0.113.5",
        source="webhook",
        runtime_state=state,
    )

    assert isinstance(alert, Alert)
    assert alert.threat_level == 4
    assert token.trigger_count == 1
    assert token.last_triggered_at is not None
    profile = next(o for o in db.added if isinstance(o, AttackerProfile))
    assert profile.canary_triggered is True
    assert profile.canary_max_difficulty == 4
    assert profile.threat_level == 4
    assert state.alert_manager.broadcasts


async def test_trigger_canary_respects_cooldown():
    token = CanaryToken(
        id=uuid.UUID("083ee719-79d9-4174-b471-076ecc4248d7"),
        label="AWS keys",
        difficulty=2,
        score_value=0.25,
        trigger_count=0,
    )
    profile = AttackerProfile(ip="203.0.113.9")
    db = _FakeSession({("CanaryToken", str(token.id)): token})
    state = _FakeState()

    fake_session = types.SimpleNamespace(id=uuid.uuid4())
    first = await trigger_canary(
        db,
        str(token.id),
        "203.0.113.9",
        session=fake_session,
        profile=profile,
        source="dionaea",
        runtime_state=state,
        cooldown_key="203.0.113.9:aws",
        cooldown_seconds=30,
    )
    second = await trigger_canary(
        db,
        str(token.id),
        "203.0.113.9",
        session=fake_session,
        profile=profile,
        source="dionaea",
        runtime_state=state,
        cooldown_key="203.0.113.9:aws",
        cooldown_seconds=30,
    )

    assert first is not None
    assert second is None
    assert token.trigger_count == 1
