"""
Database configuration and session management for EvilTwin platform.
Provides async SQLAlchemy engine and session factory.
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import logging

logger = logging.getLogger(__name__)

# Global engine and session factory (initialized by init_db)
engine = None
async_session_factory = None


def init_db(database_url: str):
    """
    Initialize the async database engine and session factory.
    
    Args:
        database_url: PostgreSQL connection string with asyncpg driver
                     Format: postgresql+asyncpg://user:pass@host:port/dbname
    """
    global engine, async_session_factory
    
    engine = create_async_engine(
        database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=10,
        poolclass=NullPool if "test" in database_url else None
    )
    
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False
    )
    
    logger.info(f"Database initialized: {database_url.split('@')[1] if '@' in database_url else 'unknown'}")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency injection function for FastAPI endpoints.
    Provides an async database session with automatic cleanup.
    
    Usage:
        @app.get("/endpoint")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            # Use db session here
            pass
    
    Yields:
        AsyncSession: Database session that auto-commits on success, rolls back on error
    """
    if async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for database sessions outside of FastAPI dependency injection.
    
    Usage:
        async with get_db_context() as db:
            result = await db.execute(select(AttackerProfile))
    
    Yields:
        AsyncSession: Database session with automatic commit/rollback
    """
    if async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db():
    """
    Close the database engine and clean up connections.
    Should be called on application shutdown.
    """
    global engine
    
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")
