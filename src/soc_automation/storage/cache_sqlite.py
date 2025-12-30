from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

class SQLiteCache:
    def __init__(self, path: str, ttl_hours: int) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self.ttl = timedelta(hours=ttl_hours)
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS intel_cache (
                    key TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT created_at, payload FROM intel_cache WHERE key = ?", (key,)).fetchone()
            if not row:
                return None
            created_at = datetime.fromisoformat(row[0])
            if self._now() - created_at > self.ttl:
                conn.execute("DELETE FROM intel_cache WHERE key = ?", (key,))
                conn.commit()
                return None
            return json.loads(row[1])

    def set(self, key: str, payload: Dict[str, Any]) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO intel_cache (key, created_at, payload) VALUES (?, ?, ?)",
                (key, self._now().isoformat(), json.dumps(payload)),
            )
            conn.commit()

