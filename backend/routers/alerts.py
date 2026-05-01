import uuid

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from jose import jwt, JWTError

from config import get_settings
from state import app_state

router = APIRouter(tags=["alerts"])

settings = get_settings()


@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket, token: str = Query(default=None)) -> None:
    # Validate JWT token from query param for WebSocket auth
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    client_id = str(uuid.uuid4())
    queue = await app_state.alert_manager.connect(client_id)

    try:
        while True:
            message = await queue.get()
            await websocket.send_json(message)
    except WebSocketDisconnect:
        app_state.alert_manager.disconnect(client_id)
    except Exception:
        app_state.alert_manager.disconnect(client_id)
        await websocket.close()
