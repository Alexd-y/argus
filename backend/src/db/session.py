"""Async database session — SQLAlchemy 2.0 + asyncpg."""

import uuid
from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.core.config import settings
from src.db.models import Base

# PostgreSQL SET LOCAL does not support bound parameters ($1).
# We must embed the value; tenant_id is validated as UUID to prevent injection.


def _validate_tenant_id(tenant_id: str) -> str:
    """Validate tenant_id is a UUID. Raises ValueError if invalid."""
    uuid.UUID(tenant_id)
    return tenant_id


engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


def create_task_engine_and_session():
    """
    Create engine and session factory bound to current event loop.
    Use inside Celery tasks to avoid "Future attached to different loop" with asyncpg.
    Caller must await engine.dispose() when done.
    """
    task_engine = create_async_engine(
        settings.database_url,
        echo=False,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )
    task_session_factory = async_sessionmaker(
        task_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    return task_engine, task_session_factory


async def set_session_tenant(session: AsyncSession, tenant_id: str) -> None:
    """
    Set app.current_tenant_id for RLS policies.
    Must be called at start of each DB operation when RLS is enabled.
    PostgreSQL SET LOCAL does not accept bound parameters; tenant_id is validated as UUID.
    """
    _validate_tenant_id(tenant_id)
    # Use literal: SET LOCAL does not support $1; value is validated UUID.
    escaped = tenant_id.replace("'", "''")
    await session.execute(text(f"SET LOCAL app.current_tenant_id = '{escaped}'"))


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI — yields async session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create tables (for dev). Production uses Alembic migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
