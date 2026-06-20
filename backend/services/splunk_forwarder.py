from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SplunkForwarder:
    def __init__(self, hec_url: str, hec_token: str) -> None:
        self.hec_url = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.client = httpx.AsyncClient(timeout=5.0)
        self.total_sent = 0
        self.total_failed = 0
        logger.info("SplunkForwarder initialized: %s", self.hec_url)

    async def send_event(self, event: dict[str, Any], source: str = "eviltwin") -> bool:
        if not self.hec_url or not self.hec_token:
            logger.warning("Splunk HEC not configured – skipping forward")
            return False
        import json as _json
        raw_url = self.hec_url.replace("/event", "/raw")
        params = {
            "source": source,
            "sourcetype": "cowrie:json",
            "index": "eviltwin",
        }
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }
        try:
            resp = await self.client.post(
                raw_url, content=_json.dumps(event), headers=headers, params=params
            )
            if resp.status_code < 300:
                self.total_sent += 1
                return True
            logger.warning("Splunk HEC returned %d: %s", resp.status_code, resp.text[:200])
            self.total_failed += 1
            return False
        except Exception as exc:
            logger.warning("Splunk HEC forward failed: %s", exc)
            self.total_failed += 1
            return False

    async def health_check(self) -> dict[str, Any]:
        try:
            resp = await self.client.get(
                f"{self.hec_url}/../../../services/collector/health",
                headers={"Authorization": f"Splunk {self.hec_token}"},
                timeout=httpx.Timeout(3.0),
            )
            return {"reachable": True, "status": resp.status_code}
        except Exception as exc:
            return {"reachable": False, "error": str(exc)}

    async def close(self) -> None:
        if not self.client.is_closed:
            await self.client.aclose()
        logger.info("SplunkForwarder closed (sent=%d failed=%d)", self.total_sent, self.total_failed)
