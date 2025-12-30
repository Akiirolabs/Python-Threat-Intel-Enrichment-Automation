from __future__ import annotations

import os
from typing import Optional
import httpx
from dotenv import load_dotenv
from soc_automation.intel.base import IntelProvider
from soc_automation.models import IntelVerdict, IndicatorType

load_dotenv()

class VirusTotalProvider(IntelProvider):
    name = "vt"

    def __init__(self, timeout_seconds: int = 12) -> None:
        self.api_key = os.getenv("VT_API_KEY", "").strip()
        self.timeout_seconds = timeout_seconds

    def enabled(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator_type: IndicatorType, value: str) -> Optional[IntelVerdict]:
        if not self.enabled():
            return None

        base = "https://www.virustotal.com/api/v3"
        if indicator_type == "ip":
            url = f"{base}/ip_addresses/{value}"
        elif indicator_type == "domain":
            url = f"{base}/domains/{value}"
        else:
            url = f"{base}/files/{value}"

        headers = {"x-apikey": self.api_key}
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            r = await client.get(url, headers=headers)
            if r.status_code != 200:
                return None
            data = r.json()

        attrs = data.get("data", {}).get("attributes", {}) or {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        if malicious >= 5:
            verdict, conf = "malicious", 90
        elif malicious > 0 or suspicious > 0:
            verdict, conf = "suspicious", 75
        else:
            verdict, conf = "unknown", 45

        return IntelVerdict(
            provider=self.name,
            indicator_type=indicator_type,
            value=value,
            verdict=verdict,
            confidence=conf,
            details={"analysis_stats": stats},
        )

