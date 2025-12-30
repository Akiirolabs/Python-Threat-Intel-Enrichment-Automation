from __future__ import annotations

import os
from typing import Optional
import httpx
from dotenv import load_dotenv
from soc_automation.intel.base import IntelProvider
from soc_automation.models import IntelVerdict, IndicatorType

load_dotenv()

class OTXProvider(IntelProvider):
    name = "otx"

    def __init__(self, timeout_seconds: int = 12) -> None:
        self.api_key = os.getenv("OTX_API_KEY", "").strip()
        self.timeout_seconds = timeout_seconds

    def enabled(self) -> bool:
        return bool(self.api_key)

    async def lookup(self, indicator_type: IndicatorType, value: str) -> Optional[IntelVerdict]:
        if not self.enabled():
            return None

        base = "https://otx.alienvault.com/api/v1/indicators"
        if indicator_type == "ip":
            url = f"{base}/IPv4/{value}/general"
        elif indicator_type == "domain":
            url = f"{base}/domain/{value}/general"
        else:
            return None

        headers = {"X-OTX-API-KEY": self.api_key}
        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            r = await client.get(url, headers=headers)
            if r.status_code != 200:
                return None
            data = r.json()

        pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        if pulse_count > 10:
            verdict, conf = "malicious", 85
        elif pulse_count > 0:
            verdict, conf = "suspicious", 70
        else:
            verdict, conf = "unknown", 40

        return IntelVerdict(
            provider=self.name,
            indicator_type=indicator_type,
            value=value,
            verdict=verdict,
            confidence=conf,
            details={"pulse_count": pulse_count},
        )

