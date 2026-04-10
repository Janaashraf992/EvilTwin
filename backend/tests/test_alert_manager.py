import asyncio

from services.alert_manager import AlertManager


def test_alert_manager_connect_broadcast_disconnect():
    manager = AlertManager()

    async def run():
        queue = await manager.connect("client-1")
        await manager.broadcast({"msg": "hello"})
        item = await asyncio.wait_for(queue.get(), timeout=1)
        manager.disconnect("client-1")
        return item

    item = asyncio.run(run())
    assert item["msg"] == "hello"
    assert "client-1" not in manager.connections
