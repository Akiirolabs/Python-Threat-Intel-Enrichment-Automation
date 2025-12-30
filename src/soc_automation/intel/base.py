from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional
from soc_automation.models import IntelVerdict, IndicatorType

class IntelProvider(ABC):
    name: str

    @abstractmethod
    async def lookup(self, indicator_type: IndicatorType, value: str) -> Optional[IntelVerdict]:
        raise NotImplementedError

