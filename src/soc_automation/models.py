from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional, Dict, Any, List
from pydantic import BaseModel, Field

IndicatorType = Literal["ip", "domain", "hash"]

class Alert(BaseModel):
    timestamp: datetime
    event_type: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    domain: Optional[str] = None
    hash: Optional[str] = Field(default=None, alias="hash")
    user: Optional[str] = None
    host: Optional[str] = None
    alert_id: str

class Asset(BaseModel):
    host: str
    owner: str
    department: str
    criticality: Literal["low", "medium", "high", "critical"]
    notes: Optional[str] = None

class Sightings(BaseModel):
    indicator_type: str
    indicator: str
    value: str
    first_seen: datetime
    last_seen: datetime
    count: int

class IntelVerdict(BaseModel):
    provider: str
    indicator_type: IndicatorType
    value: str
    verdict: Literal["benign", "unknown", "suspicious", "malicious"]
    confidence: int = Field(ge=0, le=100)
    details: Dict[str, Any] = Field(default_factory=dict)

class EnrichedAlert(BaseModel):
    alert: Alert
    normalized: Dict[str, Optional[str]]
    asset: Optional[Asset] = None
    sightings_count: int = 0
    intel: List[IntelVerdict] = Field(default_factory=list)
    risk_score: int = 0
    risk_level: Literal["low", "medium", "high", "critical"] = "low"
    score_explain: Dict[str, Any] = Field(default_factory=dict)

class Case(BaseModel):
    case_id: str
    created_at: datetime
    alert_ids: List[str]
    title: str
    risk_level: Literal["low", "medium", "high", "critical"]
    risk_score: int
    summary: str
    recommended_actions: List[str]
    indicators: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]


