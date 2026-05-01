from __future__ import annotations

from typing import Any

import httpx


class SplunkForwarder:
    def __init__(self, hec_url: str, hec_token: str) -> None:
        self.hec_url = hec_url
        self.hec_token = hec_token
        self.client = httpx.AsyncClient(timeout=5.0)

    async def send_event(self, event: dict[str, Any], source: str = "eviltwin") -> bool:
        if not self.hec_url or not self.hec_token:
            return False
        payload = {
            "event": event,
            "source": source,
            "sourcetype": "cowrie:json",
            "index": "eviltwin",
        }
        headers = {"Authorization": f"Splunk {self.hec_token}"}
        resp = await self.client.post(self.hec_url, json=payload, headers=headers)
        return resp.status_code < 300

    async def close(self) -> None:
        if not self.client.is_closed:
            await self.client.aclose()
