from __future__ import annotations

import csv
import json
import logging
import os
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
import yaml
from rich.console import Console
from rich.progress import Progress
from soc_automation.models import Alert, Asset, Sightings, EnrichedAlert, IntelVerdict, IndicatorType
from soc_automation.normalize import normalize_alert_iocs
from soc_automation.intel import MockProvider, OTXProvider, VirusTotalProvider
from soc_automation.intel.retry import retry_async
from soc_automation.storage import SQLiteCache
from soc_automation.scoring import score_alert
from soc_automation.casegen import build_cases, render_case_report_md
from soc_automation.logging_setup import setup_logging

console = Console()

def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def load_alerts_csv(path: str) -> List[Alert]:
    alerts: List[Alert] = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            alerts.append(Alert.model_validate(row))
    return alerts

def load_assets_csv(path: str) -> Dict[str, Asset]:
    out: Dict[str, Asset] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            a = Asset.model_validate(row)
            out[a.host] = a
    return out

def load_sightings_csv(path: str) -> Dict[Tuple[str, str], Sightings]:
    out: Dict[Tuple[str, str], Sightings] = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            s = Sightings.model_validate(row)
            out[(s.indicator_type, s.value)] = s
    return out

def _ioc_candidates(normalized: Dict[str, Optional[str]]) -> List[Tuple[IndicatorType, str]]:
    cands: List[Tuple[IndicatorType, str]] = []
    if normalized.get("src_ip"):
        cands.append(("ip", normalized["src_ip"]))  # type: ignore[arg-type]
    if normalized.get("dst_ip"):
        cands.append(("ip", normalized["dst_ip"]))  # type: ignore[arg-type]
    if normalized.get("domain"):
        cands.append(("domain", normalized["domain"]))  # type: ignore[arg-type]
    if normalized.get("hash"):
        cands.append(("hash", normalized["hash"]))  # type: ignore[arg-type]
    seen = set()
    uniq = []
    for t, v in cands:
        k = (t, v)
        if k not in seen:
            uniq.append((t, v))
            seen.add(k)
    return uniq

async def enrich_ioc(
    cache: SQLiteCache,
    providers,
    indicator_type: IndicatorType,
    value: str,
) -> List[IntelVerdict]:
    key = f"{indicator_type}:{value}"
    cached = cache.get(key)
    if cached:
        return [IntelVerdict.model_validate(x) for x in cached.get("intel", [])]

    verdicts: List[IntelVerdict] = []
    for p in providers:
        try:
            async def _call():
                return await p.lookup(indicator_type, value)

            v = await retry_async(_call, attempts=3, base_delay=0.5, max_delay=4.0)
            if v:
                verdicts.append(v)
        except Exception as e:
            verdicts.append(
                IntelVerdict(
                    provider=getattr(p, "name", "unknown"),
                    indicator_type=indicator_type,
                    value=value,
                    verdict="unknown",
                    confidence=0,
                    details={"error": str(e)},
                )
            )

    cache.set(key, {"intel": [v.model_dump() for v in verdicts], "cached_at": datetime.utcnow().isoformat()})
    return verdicts

async def run_pipeline(config_path: str) -> None:
    cfg = load_yaml(config_path)
    setup_logging(cfg)
    log = logging.getLogger("soc_automation.pipeline")
    log.info("pipeline_start config=%s", config_path)
    scoring_cfg = load_yaml("config/scoring.yaml")

    os.makedirs(cfg["output"]["dir"], exist_ok=True)

    alerts = load_alerts_csv(cfg["input"]["alerts_csv"])
    assets = load_assets_csv(cfg["input"]["assets_csv"])
    sightings = load_sightings_csv(cfg["input"]["sightings_csv"])

    cache = SQLiteCache(cfg["enrichment"]["cache_db"], int(cfg["enrichment"]["cache_ttl_hours"]))

    mock = MockProvider()
    otx = OTXProvider(timeout_seconds=int(cfg["enrichment"]["timeout_seconds"]))
    vt = VirusTotalProvider(timeout_seconds=int(cfg["enrichment"]["timeout_seconds"]))

    mode = cfg.get("mode", "offline")
    if mode == "offline":
        providers = [mock]
    else:
        providers = [mock]
        if otx.enabled():
            providers.append(otx)
        if vt.enabled():
            providers.append(vt)

    log.info("mode=%s providers=%s", mode, [p.name for p in providers])
    console.print(f"[bold]Mode:[/bold] {mode} | Providers: {[p.name for p in providers]}")

    import asyncio

    sem = asyncio.Semaphore(int(cfg["enrichment"]["concurrency"]))

    async def enrich_one(alert: Alert) -> EnrichedAlert:
        normalized = normalize_alert_iocs(alert.src_ip, alert.dst_ip, alert.domain, alert.hash)
        ea = EnrichedAlert(alert=alert, normalized=normalized)

        if alert.host and alert.host in assets:
            ea.asset = assets[alert.host]

        sight_count = 0
        for t, v in _ioc_candidates(normalized):
            s = sightings.get((t, v))
            if s:
                sight_count += s.count
        ea.sightings_count = sight_count

        verdicts: List[IntelVerdict] = []
        async with sem:
            tasks = [enrich_ioc(cache, providers, t, v) for t, v in _ioc_candidates(normalized)]
            results = await asyncio.gather(*tasks)
            for r in results:
                verdicts.extend(r)

        ea.intel = verdicts
        ea = score_alert(ea, scoring_cfg)
        return ea

    with Progress() as progress:
        task_id = progress.add_task("[cyan]Enriching alerts...", total=len(alerts))
        enriched = []

        async def wrapped(alert: Alert):
            ea = await enrich_one(alert)
            progress.advance(task_id, 1)
            return ea

        enriched = await asyncio.gather(*[wrapped(a) for a in alerts])

    out_dir = cfg["output"]["dir"]
    enriched_csv_path = os.path.join(out_dir, cfg["output"]["enriched_csv"])
    cases_json_path = os.path.join(out_dir, cfg["output"]["cases_json"])
    case_md_path = os.path.join(out_dir, cfg["output"]["case_report_md"])

    with open(enriched_csv_path, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "timestamp",
            "alert_id",
            "event_type",
            "host",
            "user",
            "src_ip",
            "dst_ip",
            "domain",
            "hash",
            "asset_criticality",
            "sightings_count",
            "risk_score",
            "risk_level",
            "best_intel_verdicts",
        ]
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for ea in enriched:
            best = ",".join(sorted({f"{v.provider}:{v.verdict}" for v in ea.intel})) if ea.intel else ""
            w.writerow(
                {
                    "timestamp": ea.alert.timestamp.isoformat(),
                    "alert_id": ea.alert.alert_id,
                    "event_type": ea.alert.event_type,
                    "host": ea.alert.host,
                    "user": ea.alert.user,
                    "src_ip": ea.normalized.get("src_ip"),
                    "dst_ip": ea.normalized.get("dst_ip"),
                    "domain": ea.normalized.get("domain"),
                    "hash": ea.normalized.get("hash"),
                    "asset_criticality": ea.asset.criticality if ea.asset else "unknown",
                    "sightings_count": ea.sightings_count,
                    "risk_score": ea.risk_score,
                    "risk_level": ea.risk_level,
                    "best_intel_verdicts": best,
                }
            )

    cases = build_cases(enriched)
    with open(cases_json_path, "w", encoding="utf-8") as f:
        json.dump([c.model_dump() for c in cases], f, indent=2, default=str)

    with open(case_md_path, "w", encoding="utf-8") as f:
        f.write(render_case_report_md(cases))

    console.print(f"[green]Wrote[/green] {enriched_csv_path}")
    console.print(f"[green]Wrote[/green] {cases_json_path}")
    console.print(f"[green]Wrote[/green] {case_md_path}")

