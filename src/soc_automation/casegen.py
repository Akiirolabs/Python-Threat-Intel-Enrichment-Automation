from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Any
from soc_automation.models import EnrichedAlert, Case

def _recommendations(risk_level: str, event_type: str) -> List[str]:
    base = [
        "Validate indicator context (asset owner, business use, change tickets).",
        "Check related telemetry (DNS, proxy, EDR, auth logs) for lateral movement or persistence.",
        "Hunt for additional indicators and scope impact (other hosts/users).",
    ]
    if risk_level in {"high", "critical"}:
        base.insert(0, "Consider containment: isolate host or block IOC if confirmed malicious.")
        base.append("Escalate per incident response policy and preserve evidence.")
    if event_type == "brute_force":
        base.append("Review authentication logs for successful logins and enforce MFA/lockout policies.")
    if event_type == "data_exfil":
        base.append("Inspect egress volume/destinations; validate DLP controls and sensitive data access.")
    return base

def build_cases(enriched_alerts: List[EnrichedAlert]) -> List[Case]:
    by_host: Dict[str, List[EnrichedAlert]] = defaultdict(list)
    for ea in enriched_alerts:
        key = ea.alert.host or f"unknown-{ea.alert.alert_id}"
        by_host[key].append(ea)

    cases: List[Case] = []
    now = datetime.now(timezone.utc)

    for host, items in by_host.items():
        items_sorted = sorted(items, key=lambda x: x.alert.timestamp)
        max_item = max(items_sorted, key=lambda x: x.risk_score)

        indicators: List[Dict[str, Any]] = []
        for ea in items_sorted:
            for v in ea.intel:
                indicators.append(
                    {
                        "type": v.indicator_type,
                        "value": v.value,
                        "provider": v.provider,
                        "verdict": v.verdict,
                        "confidence": v.confidence,
                    }
                )

        timeline = []
        for ea in items_sorted:
            timeline.append(
                {
                    "timestamp": ea.alert.timestamp.isoformat(),
                    "event_type": ea.alert.event_type,
                    "alert_id": ea.alert.alert_id,
                    "user": ea.alert.user,
                    "src_ip": ea.normalized.get("src_ip"),
                    "dst_ip": ea.normalized.get("dst_ip"),
                    "domain": ea.normalized.get("domain"),
                    "hash": ea.normalized.get("hash"),
                    "risk_score": ea.risk_score,
                    "risk_level": ea.risk_level,
                }
            )

        title = f"{max_item.risk_level.upper()} - {host} - {max_item.alert.event_type}"
        summary = (
            f"Case generated from {len(items_sorted)} alert(s) on host {host}. "
            f"Highest risk: {max_item.alert.event_type} (score {max_item.risk_score}, level {max_item.risk_level})."
        )

        cases.append(
            Case(
                case_id=f"CASE-{host}-{max_item.alert.alert_id}",
                created_at=now,
                alert_ids=[x.alert.alert_id for x in items_sorted],
                title=title,
                risk_level=max_item.risk_level,
                risk_score=max_item.risk_score,
                summary=summary,
                recommended_actions=_recommendations(max_item.risk_level, max_item.alert.event_type),
                indicators=indicators,
                timeline=timeline,
            )
        )

    return sorted(cases, key=lambda c: (c.risk_score, c.created_at), reverse=True)

def render_case_report_md(cases: List[Case]) -> str:
    lines: List[str] = []
    lines.append("# SOC Case Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")

    for c in cases:
        lines.append(f"## {c.title}")
        lines.append("")
        lines.append(f"- **Case ID:** {c.case_id}")
        lines.append(f"- **Created:** {c.created_at.isoformat()}")
        lines.append(f"- **Risk:** {c.risk_level} ({c.risk_score})")
        lines.append(f"- **Alert IDs:** {', '.join(c.alert_ids)}")
        lines.append("")
        lines.append("### Summary")
        lines.append(c.summary)
        lines.append("")
        lines.append("### Recommended Actions")
        for a in c.recommended_actions:
            lines.append(f"- {a}")
        lines.append("")
        lines.append("### Timeline")
        for t in c.timeline:
            lines.append(f"- `{t['timestamp']}` **{t['event_type']}** (alert {t['alert_id']}) user={t.get('user')} score={t['risk_score']}/{t['risk_level']}")
        lines.append("")
        lines.append("### Indicators")
        if c.indicators:
            lines.append("| type | value | provider | verdict | confidence |")
            lines.append("|---|---|---|---|---|")
            for i in c.indicators[:50]:
                lines.append(f"| {i['type']} | {i['value']} | {i['provider']} | {i['verdict']} | {i['confidence']} |")
        else:
            lines.append("_No indicators enriched._")
        lines.append("")

    return "\n".join(lines)

