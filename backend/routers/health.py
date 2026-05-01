from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from state import app_state

router = APIRouter(tags=["health"])


@router.get("/health")
async def health_check(db: AsyncSession = Depends(get_db)):
    db_ok = True
    try:
        await db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    model_ok = app_state.threat_scorer is not None and app_state.threat_scorer.pipeline is not None
    uptime = int((datetime.now(timezone.utc) - app_state.started_at).total_seconds())

    body = {
        "status": "healthy" if db_ok else "unhealthy",
        "database": db_ok,
        "model": model_ok,
        "uptime": uptime,
    }

    if db_ok:
        return body
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=body)
