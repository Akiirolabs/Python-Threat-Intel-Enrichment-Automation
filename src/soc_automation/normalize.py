from __future__ import annotations

import ipaddress
import re
from typing import Optional, Dict

HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

def normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = d.replace("[.]", ".").replace("(.)", ".")
    d = d.replace("hxxp://", "http://").replace("hxxps://", "https://")
    d = d.replace("http://", "").replace("https://", "")
    d = d.strip(".")
    return d

def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except Exception:
        return False

def is_valid_domain(value: str) -> bool:
    v = normalize_domain(value)
    if len(v) < 3 or len(v) > 253:
        return False
    if ".." in v:
        return False
    labels = v.split(".")
    if any(len(x) == 0 or len(x) > 63 for x in labels):
        return False
    for lab in labels:
        if lab.startswith("-") or lab.endswith("-"):
            return False
        if not re.fullmatch(r"[a-z0-9-]+", lab):
            return False
    return True

def normalize_hash(value: str) -> str:
    return value.strip().lower()

def is_valid_hash(value: str) -> bool:
    return bool(HASH_RE.fullmatch(value.strip()))

def normalize_alert_iocs(src_ip: Optional[str], dst_ip: Optional[str], domain: Optional[str], h: Optional[str]) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {"src_ip": None, "dst_ip": None, "domain": None, "hash": None}
    if src_ip and is_valid_ip(src_ip):
        out["src_ip"] = src_ip.strip()
    if dst_ip and is_valid_ip(dst_ip):
        out["dst_ip"] = dst_ip.strip()
    if domain and is_valid_domain(domain):
        out["domain"] = normalize_domain(domain)
    if h and is_valid_hash(h):
        out["hash"] = normalize_hash(h)
    return out

