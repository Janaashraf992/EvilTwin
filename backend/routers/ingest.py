from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from schemas import LogIngestRequest, LogIngestResponse
from services.ingest import ingest_event

router = APIRouter(prefix="", tags=["ingest"])


@router.post("/log", response_model=LogIngestResponse)
async def ingest_log(payload: LogIngestRequest, db: AsyncSession = Depends(get_db)) -> LogIngestResponse:
    return await ingest_event(payload, db)
