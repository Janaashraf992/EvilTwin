import os
import sys
from pathlib import Path

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


os.environ.setdefault("POSTGRES_PASSWORD", "testpass")
os.environ.setdefault("CANARY_WEBHOOK_SECRET", "testsecret")


@pytest_asyncio.fixture
async def integration_db_session():
    from models import Base

    database_url = os.getenv("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("TEST_DATABASE_URL not set; skipping integration DB tests")

    engine = create_async_engine(database_url, future=True)
    try:
        async with engine.begin() as conn:
            await conn.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with session_factory() as session:
            yield session
            await session.rollback()
    except Exception as exc:
        pytest.skip(f"Integration DB unavailable: {exc}")
    finally:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()


@pytest_asyncio.fixture
async def integration_client(integration_db_session: AsyncSession):
    from database import get_db
    from main import app
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

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
