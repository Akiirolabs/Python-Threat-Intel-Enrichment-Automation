# Advanced Python Automation SOC Lab

This lab builds a realistic SOC automation pipeline:

- Ingest alerts from `data/alerts.csv`

- Normalize and validate indicators (IP / domain / hash)

- Enrich indicators via threat intel providers (offline mock by default; optional online OTX/VT)

- Cache intel results (SQLite) with TTL to control cost/rate limits

- Score risk with explainable weighting (`config/scoring.yaml`)

- Generate case artifacts:

  - `output/enriched_alerts.csv`

  - `output/cases.json`

  - `output/case_report.md`

## Quickstart

TERMINAL:

```bash

python -m venv .venv

source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -e .

soc-auto run --config config/config.yaml

```

## Enable Online Enrichment (Optional)

1. Copy env template:

TERMINAL:

```bash

cp .env.example .env

```

2. Put API keys in `.env`, then set `mode: "online"` in `config/config.yaml`.

## What to Look For

* Caching prevents repeated hits for the same IOC

* Concurrency speeds enrichment

* Scoring explains *why* an alert is high/critical

* Case report provides analyst-ready narrative and next actions

