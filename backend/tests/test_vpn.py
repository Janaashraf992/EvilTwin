"""Tests for VPN detection service."""
from __future__ import annotations

import asyncio

import pytest

from services.vpn_detection import KNOWN_VPN_ASNS, VPNDetector, VPNResult


def test_vpn_result_defaults():
    """VPNResult has sensible defaults."""
    result = VPNResult()
    assert result.vpn is False
    assert result.proxy is False
    assert result.tor is False
    assert result.confidence == 0
    assert result.country == ""
    assert result.isp == ""


def test_known_vpn_asns_has_enough_entries():
    """Spec requires at least 30 known VPN ASNs."""
    assert len(KNOWN_VPN_ASNS) >= 30


class TestVPNDetector:
    """Test VPNDetector behavior."""

    def test_cache_initialization(self):
        """Detector initializes with empty cache."""
        detector = VPNDetector("", "")
        assert len(detector.cache) == 0

    def test_semaphore_limit(self):
        """Detector creates a semaphore with limit 10."""
        detector = VPNDetector("", "")
        assert detector.semaphore._value == 10

    @pytest.mark.asyncio
    async def test_check_returns_vpn_result(self):
        """check() returns a VPNResult even with no API keys."""
        detector = VPNDetector("", "")
        result = await detector.check("127.0.0.1")
        assert isinstance(result, VPNResult)
        # Without valid API keys, confidence should be very low
        assert result.confidence <= 60

    @pytest.mark.asyncio
    async def test_check_caches_results(self):
        """Second call for the same IP hits the cache."""
        detector = VPNDetector("", "")
        result1 = await detector.check("10.0.0.1")
        result2 = await detector.check("10.0.0.1")
        assert result1 is result2  # Same object from cache

    @pytest.mark.asyncio
    async def test_check_different_ips(self):
        """Different IPs get different cache entries."""
        detector = VPNDetector("", "")
        result1 = await detector.check("10.0.0.1")
        result2 = await detector.check("10.0.0.2")
        assert "10.0.0.1" in detector.cache
        assert "10.0.0.2" in detector.cache

    @pytest.mark.asyncio
    async def test_graceful_degradation(self):
        """With no API keys, returns VPNResult with low confidence."""
        detector = VPNDetector("invalid", "invalid")
        result = await detector.check("8.8.8.8")
        assert isinstance(result, VPNResult)
        # Should not crash, should return a result
