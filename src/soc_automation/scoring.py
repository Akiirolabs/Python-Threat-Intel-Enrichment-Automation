from __future__ import annotations

from typing import Dict, Any, List, Tuple
from soc_automation.models import EnrichedAlert, IntelVerdict

def _best_intel(intel: List[IntelVerdict]) -> Tuple[str, int]:
    order = {"malicious": 3, "suspicious": 2, "unknown": 1, "benign": 0}
    best = ("unknown", 0)
    for v in intel:
        if order[v.verdict] > order[best[0]]:
            best = (v.verdict, v.confidence)
        elif v.verdict == best[0] and v.confidence > best[1]:
            best = (v.verdict, v.confidence)
    return best

def score_alert(enriched: EnrichedAlert, scoring_cfg: Dict[str, Any]) -> EnrichedAlert:
    weights = scoring_cfg["weights"]
    thresholds = scoring_cfg["thresholds"]
    asset_map = scoring_cfg["asset_criticality_map"]
    event_map = scoring_cfg["event_severity_map"]

    total = 0
    explain: Dict[str, Any] = {"components": []}

    best_verdict, best_conf = _best_intel(enriched.intel)

    if best_verdict == "malicious":
        pts = weights["intel_malicious"]
        total += pts
        explain["components"].append({"factor": "intel_malicious", "points": pts, "best_verdict": best_verdict, "confidence": best_conf})
    elif best_verdict == "suspicious":
        pts = weights["intel_suspicious"]
        total += pts
        explain["components"].append({"factor": "intel_suspicious", "points": pts, "best_verdict": best_verdict, "confidence": best_conf})
    else:
        explain["components"].append({"factor": "intel", "points": 0, "best_verdict": best_verdict, "confidence": best_conf})

    s = min(enriched.sightings_count, 20)
    sight_pts = int((s / 20) * weights["sightings_count"])
    total += sight_pts
    explain["components"].append({"factor": "sightings", "points": sight_pts, "count": enriched.sightings_count})

    if enriched.asset:
        apts = asset_map.get(enriched.asset.criticality, 0)
        total += apts
        explain["components"].append({"factor": "asset_criticality", "points": apts, "criticality": enriched.asset.criticality})
    else:
        explain["components"].append({"factor": "asset_criticality", "points": 0, "criticality": "unknown"})

    ev = enriched.alert.event_type
    epts = event_map.get(ev, 0)
    epts = min(epts, weights["event_severity"])
    total += epts
    explain["components"].append({"factor": "event_severity", "points": epts, "event_type": ev})

    if total >= thresholds["critical"]:
        level = "critical"
    elif total >= thresholds["high"]:
        level = "high"
    elif total >= thresholds["medium"]:
        level = "medium"
    else:
        level = "low"

    enriched.risk_score = int(total)
    enriched.risk_level = level
    enriched.score_explain = explain
    return enriched

