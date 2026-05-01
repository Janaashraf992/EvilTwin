from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx
from cachetools import TTLCache


@dataclass
class VPNResult:
    vpn: bool = False
    proxy: bool = False
    tor: bool = False
    country: str = ""
    city: str = ""
    isp: str = ""
    latitude: float | None = None
    longitude: float | None = None
    confidence: int = 0


KNOWN_VPN_ASNS = {
    # NordVPN
    "AS62041", "AS212238",
    # ExpressVPN
    "AS396982", "AS206238",
    # Mullvad
    "AS198093", "AS31377",
    # PIA (Private Internet Access)
    "AS46562", "AS40676",
    # Surfshark
    "AS51167", "AS209854",
    # ProtonVPN
    "AS209103",
    # CyberGhost
    "AS200130",
    # Windscribe
    "AS49367",
    # IVPN
    "AS44477",
    # AzireVPN
    "AS60068",
    # TorGuard
    "AS8100",
    # Vultr / hosting providers
    "AS20473", "AS63949",
    # Cloudflare (WARP)
    "AS13335",
    # AWS
    "AS16509", "AS14618",
    # Google Cloud
    "AS15169", "AS396982",
    # Azure
    "AS8075",
    # DigitalOcean
    "AS14061",
    # OVH
    "AS16276",
    # Hetzner
    "AS24940",
    # Linode / Akamai
    "AS63949",
    # Psychz Networks
    "AS40676",
    # Choopa
    "AS20473",
    # M247 / Data Packet
    "AS9009",
    # TOR exit‐relay heavy ASNs
    "AS35913", "AS29802", "AS36352",
    # Zscaler
    "AS22616",
    # Leaseweb
    "AS30083", "AS21859",
    # ColoCrossing
    "AS36352",
    # QuadraNet
    "AS14593",
    # GTT
    "AS3257",
    # Datacamp Limited
    "AS55293", "AS210083",
    # FDCservers / VPN heavy
    "AS174", "AS30083",
    # HideMyAss
    "AS51852",
    # IPVanish
    "AS33438",
}


class VPNDetector:
    def __init__(self, ipinfo_token: str, abuseipdb_api_key: str) -> None:
        self.ipinfo_token = ipinfo_token
        self.abuseipdb_api_key = abuseipdb_api_key
        self.cache: TTLCache = TTLCache(maxsize=10000, ttl=3600)
        self.semaphore = asyncio.Semaphore(10)
        self.client = httpx.AsyncClient(timeout=5.0)

    async def _query_ipinfo(self, ip: str) -> VPNResult:
        if not self.ipinfo_token:
            return VPNResult()
        headers = {"Authorization": f"Bearer {self.ipinfo_token}"}
        resp = await self.client.get(f"https://ipinfo.io/{ip}/json", headers=headers)
        if resp.status_code != 200:
            return VPNResult()
        data = resp.json()
        org = str(data.get("org", ""))
        asn = org.split()[0] if org else ""
        is_vpn = asn in KNOWN_VPN_ASNS
        
        lat = None
        lon = None
        loc_str = data.get("loc")
        if loc_str and "," in loc_str:
            try:
                lat = float(loc_str.split(",")[0])
                lon = float(loc_str.split(",")[1])
            except ValueError:
                pass

        return VPNResult(
            vpn=is_vpn,
            country=str(data.get("country", "")),
            city=str(data.get("city", "")),
            isp=org,
            latitude=lat,
            longitude=lon,
            confidence=90 if is_vpn else 0,
        )

    async def _query_abuseipdb(self, ip: str, result: VPNResult) -> VPNResult:
        if not self.abuseipdb_api_key:
            return result
        headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
        resp = await self.client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
        )
        if resp.status_code != 200:
            return result
        data = resp.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0))
        if confidence > 70:
            result.proxy = True
            result.confidence = max(result.confidence, 75)
        return result

    async def _query_ip_api(self, ip: str, result: VPNResult) -> VPNResult:
        resp = await self.client.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,proxy,hosting,lat,lon")
        if resp.status_code != 200:
            return result
        data = resp.json()
        if data.get("status") != "success":
            return result
        result.country = result.country or str(data.get("country", ""))
        result.city = result.city or str(data.get("city", ""))
        result.isp = result.isp or str(data.get("isp", ""))
        
        if result.latitude is None and "lat" in data:
            result.latitude = float(data["lat"])
        if result.longitude is None and "lon" in data:
            result.longitude = float(data["lon"])
            
        if data.get("proxy") or data.get("hosting"):
            result.proxy = True
            result.confidence = max(result.confidence, 60)
        return result

    async def check(self, ip: str) -> VPNResult:
        if ip in self.cache:
            return self.cache[ip]

        async with self.semaphore:
            try:
                result = await self._query_ipinfo(ip)
                if result.confidence < 90:
                    result = await self._query_abuseipdb(ip, result)
                if result.confidence < 60:
                    result = await self._query_ip_api(ip, result)
            except Exception:
                result = VPNResult()

        self.cache[ip] = result
        return result

    async def close(self) -> None:
        if not self.client.is_closed:
            await self.client.aclose()
