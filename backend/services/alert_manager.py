import asyncio
from typing import Any


class AlertManager:
    def __init__(self) -> None:
        self.connections: dict[str, asyncio.Queue] = {}

    async def connect(self, client_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=100)
        self.connections[client_id] = queue
        return queue

    def disconnect(self, client_id: str) -> None:
        self.connections.pop(client_id, None)

    async def broadcast(self, alert: dict[str, Any]) -> None:
        dead_clients: list[str] = []
        for client_id, queue in self.connections.items():
            try:
                queue.put_nowait(alert)
            except asyncio.QueueFull:
                try:
                    queue.get_nowait()
                    queue.put_nowait(alert)
                except Exception:
                    dead_clients.append(client_id)
        for client_id in dead_clients:
            self.disconnect(client_id)
