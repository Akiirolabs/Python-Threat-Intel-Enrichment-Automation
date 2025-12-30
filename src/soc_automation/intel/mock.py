from __future__ import annotations

from typing import Optional
from soc_automation.intel.base import IntelProvider
from soc_automation.models import IntelVerdict, IndicatorType

class MockProvider(IntelProvider):
    name = "mock"

    async def lookup(self, indicator_type: IndicatorType, value: str) -> Optional[IntelVerdict]:
        v = value.lower()
        verdict = "unknown"
        confidence = 40
        details = {}

        if indicator_type == "domain":
            if any(x in v for x in ["drop", "telemetry", "security", "sync", "cdn-updates"]):
                verdict = "suspicious"
                confidence = 70
                details = {"reason": "keyword_match", "matched": [x for x in ["drop", "telemetry", "security", "sync", "cdn-updates"] if x in v]}

        elif indicator_type == "hash":
            if v == "44d88612fea8a8f36de82e1278abb02f":
                verdict = "malicious"
                confidence = 95
                details = {"family": "eicar-like-demo", "note": "demo hash flagged malicious"}

        elif indicator_type == "ip":
            if v.startswith("185.220.") or v.startswith("104.21."):
                verdict = "suspicious"
                confidence = 65
                details = {"reason": "range_flag", "note": "demo range flagged suspicious"}

        return IntelVerdict(
            provider=self.name,
            indicator_type=indicator_type,
            value=value,
            verdict=verdict,
            confidence=confidence,
            details=details,
        )

