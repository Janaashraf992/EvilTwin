from __future__ import annotations

import asyncio
import logging
from typing import Any

from sqlalchemy import select

from config import Settings, get_settings
from database import get_db_context, init_db
from models import User
from services.auth import get_password_hash

logger = logging.getLogger(__name__)


def _demo_bootstrap_enabled(settings: Settings) -> bool:
    return bool(
        settings.DEMO_BOOTSTRAP
        and settings.DEMO_USER_EMAIL
        and settings.DEMO_USER_PASSWORD
    )


async def ensure_demo_user(session: Any, settings: Settings) -> bool:
    if not _demo_bootstrap_enabled(settings):
        return False

    result = await session.execute(select(User).where(User.email == settings.DEMO_USER_EMAIL))
    user = result.scalar_one_or_none()
    hashed_password = get_password_hash(settings.DEMO_USER_PASSWORD or "")

    if user is None:
        user = User(
            email=settings.DEMO_USER_EMAIL or "",
            hashed_password=hashed_password,
            role=settings.DEMO_USER_ROLE,
            is_active=True,
        )
        session.add(user)
        logger.info("Created demo analyst account for %s", settings.DEMO_USER_EMAIL)
    else:
        user.hashed_password = hashed_password
        user.role = settings.DEMO_USER_ROLE
        user.is_active = True
        logger.info("Updated demo analyst account for %s", settings.DEMO_USER_EMAIL)

    await session.flush()
    return True


async def bootstrap_demo_user(settings: Settings | None = None) -> bool:
    current_settings = settings or get_settings()
    if not _demo_bootstrap_enabled(current_settings):
        logger.info("Demo bootstrap disabled; skipping demo analyst seed")
        return False

    init_db(current_settings.database_url)
    async with get_db_context() as session:
        return await ensure_demo_user(session, current_settings)


def main() -> None:
    asyncio.run(bootstrap_demo_user())


if __name__ == "__main__":
    main()