from datetime import datetime, timezone

from soc_automation.models import Alert, EnrichedAlert, Asset, IntelVerdict
from soc_automation.scoring import score_alert


def test_scoring_malicious_high_asset():
    scoring_cfg = {
        "weights": {"intel_malicious": 40, "intel_suspicious": 20, "sightings_count": 10, "asset_criticality": 20, "event_severity": 10},
        "thresholds": {"low": 0, "medium": 35, "high": 60, "critical": 80},
        "asset_criticality_map": {"low": 5, "medium": 10, "high": 15, "critical": 20},
        "event_severity_map": {"malware_hash": 9},
    }

    alert = Alert(
        timestamp=datetime.now(timezone.utc),
        event_type="malware_hash",
        src_ip="10.0.0.1",
        dst_ip="1.1.1.1",
        domain=None,
        hash="44d88612fea8a8f36de82e1278abb02f",
        user="u",
        host="H",
        alert_id="A1",
    )

    ea = EnrichedAlert(alert=alert, normalized={"src_ip": "10.0.0.1", "dst_ip": "1.1.1.1", "domain": None, "hash": alert.hash})
    ea.asset = Asset(host="H", owner="u", department="IT", criticality="critical", notes=None)
    ea.sightings_count = 20
    ea.intel = [IntelVerdict(provider="mock", indicator_type="hash", value=alert.hash, verdict="malicious", confidence=95, details={})]

    ea = score_alert(ea, scoring_cfg)
    assert ea.risk_score >= 80
    assert ea.risk_level in {"critical", "high"}

