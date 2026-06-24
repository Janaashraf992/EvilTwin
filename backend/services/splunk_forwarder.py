from __future__ import annotations

import json as _json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class SplunkForwarder:
    def __init__(self, hec_url: str, hec_token: str) -> None:
        self.hec_url = hec_url.rstrip("/")
        self.hec_token = hec_token
        self.client = httpx.AsyncClient(timeout=10.0)
        self.total_sent = 0
        self.total_failed = 0
        self._event_url = self._resolve_event_endpoint()
        logger.info("SplunkForwarder initialized: event_url=%s", self._event_url)

    def _resolve_event_endpoint(self) -> str:
        if "/event" in self.hec_url:
            return self.hec_url
        if "/raw" in self.hec_url:
            endpoint = self.hec_url.replace("/raw", "/event")
            logger.info("Rewriting HEC URL from /raw to /event: %s", endpoint)
            return endpoint
        endpoint = f"{self.hec_url}/services/collector/event"
        logger.warning(
            "Splunk HEC URL has no known endpoint path – using %s", endpoint
        )
        return endpoint

    async def send_event(self, event: dict[str, Any], source: str = "eviltwin") -> bool:
        if not self.hec_url or not self.hec_token:
            logger.warning("Splunk HEC not configured – skipping forward")
            return False
        payload = {
            "event": event,
            "source": source,
            "sourcetype": "cowrie:json",
            "index": "eviltwin",
        }
        headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json",
        }
        body = _json.dumps(payload)
        try:
            resp = await self.client.post(
                self._event_url, content=body, headers=headers
            )
            if resp.status_code < 300:
                self.total_sent += 1
                logger.info(
                    "Splunk event sent: source=%s total_sent=%d",
                    source, self.total_sent,
                )
                return True
            logger.error(
                "Splunk HEC HTTP %d: %s",
                resp.status_code,
                resp.text[:500],
            )
            self.total_failed += 1
            return False
        except httpx.ConnectError as exc:
            logger.error(
                "Splunk HEC unreachable at %s: %s", self._event_url, exc
            )
            self.total_failed += 1
            return False
        except Exception as exc:
            logger.error(
                "Splunk forward failed (%s): %s", type(exc).__name__, exc
            )
            self.total_failed += 1
            return False

    async def health_check(self) -> dict[str, Any]:
        try:
            base = self.hec_url.split("/services")[0] if "/services" in self.hec_url else self.hec_url
            resp = await self.client.get(
                f"{base}/services/collector/health",
                headers={"Authorization": f"Splunk {self.hec_token}"},
                timeout=httpx.Timeout(3.0),
            )
            return {"reachable": True, "status": resp.status_code}
        except Exception as exc:
            return {"reachable": False, "error": str(exc)}

    async def warmup_check(self, retries: int = 5, delay: float = 3.0) -> bool:
        import asyncio as _asyncio
        for attempt in range(1, retries + 1):
            result = await self.health_check()
            if result["reachable"]:
                logger.info("Splunk HEC reachable on attempt %d/%d", attempt, retries)
                return True
            logger.warning(
                "Splunk HEC health check attempt %d/%d failed: %s",
                attempt, retries, result.get("error", "unknown"),
            )
            if attempt < retries:
                await _asyncio.sleep(delay)
        logger.error("Splunk HEC unreachable after %d attempts", retries)
        return False

    async def close(self) -> None:
        if not self.client.is_closed:
            await self.client.aclose()
        logger.info(
            "SplunkForwarder closed (sent=%d failed=%d)",
            self.total_sent, self.total_failed,
        )
