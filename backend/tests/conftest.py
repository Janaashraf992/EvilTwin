import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


os.environ.setdefault("POSTGRES_PASSWORD", "testpass")
os.environ.setdefault("CANARY_WEBHOOK_SECRET", "testsecret")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-tests-only")


@pytest_asyncio.fixture
async def integration_db_session():
    from models import Base

    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("TEST_DATABASE_URL not set; skipping integration DB tests")

    requested_url = make_url(database_url)
    base_database = requested_url.database or "eviltwin"
    isolated_database = f"{base_database}_test_{uuid4().hex[:8]}"
    admin_database = os.getenv("TEST_DATABASE_ADMIN_DB", "postgres")

    admin_engine = create_async_engine(
        requested_url.set(database=admin_database).render_as_string(hide_password=False),
        future=True,
        isolation_level="AUTOCOMMIT",
    )

    isolated_url = requested_url.set(database=isolated_database).render_as_string(hide_password=False)

    try:
        async with admin_engine.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{isolated_database}"'))
            await conn.execute(text(f'CREATE DATABASE "{isolated_database}"'))
    except Exception as exc:
        await admin_engine.dispose()
        pytest.skip(f"Integration DB unavailable: {exc}")

    engine = create_async_engine(isolated_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as session:
            yield session
            await session.rollback()
    except Exception as exc:
        pytest.skip(f"Integration DB unavailable: {exc}")
    finally:
        await engine.dispose()
        async with admin_engine.connect() as conn:
            await conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) "
                    "FROM pg_stat_activity "
                    "WHERE datname = :datname AND pid <> pg_backend_pid()"
                ),
                {"datname": isolated_database},
            )
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{isolated_database}"'))
        await admin_engine.dispose()


@pytest_asyncio.fixture
async def integration_client(integration_db_session: AsyncSession):
    from deps import get_current_user
    from database import get_db
    from main import app
    from models import User
    from state import app_state

    app_state.threat_scorer = None
    app_state.vpn_detector = None

    async def override_get_db():
        try:
            yield integration_db_session
            await integration_db_session.commit()
        except Exception:
            await integration_db_session.rollback()
            raise

    async def override_get_current_user():
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return User(
            id=uuid4(),
            email="integration@eviltwin.local",
            hashed_password="not-used-in-tests",
            role="analyst",
            is_active=True,
            created_at=now,
            updated_at=now,
        )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
