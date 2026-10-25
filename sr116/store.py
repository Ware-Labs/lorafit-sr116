"""Local SQLite store for vitals and recording metadata."""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


def _day_bounds_utc(ts: Optional[int] = None) -> tuple[int, int]:
    if ts is None:
        ts = int(time.time())
    dt = datetime.fromtimestamp(ts, timezone.utc)
    start = datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc)
    start_ts = int(start.timestamp())
    return start_ts, start_ts + 86400


@dataclass
class VitalStats:
    kind: str
    count: int
    latest: Optional[float]
    min_v: Optional[float]
    max_v: Optional[float]
    avg: Optional[float]


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS vitals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                kind TEXT NOT NULL,
                value REAL NOT NULL,
                source TEXT NOT NULL DEFAULT 'unknown',
                UNIQUE(ts, kind, source, value)
            );
            CREATE INDEX IF NOT EXISTS idx_vitals_kind_ts ON vitals(kind, ts);

            CREATE TABLE IF NOT EXISTS recordings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                saved_at INTEGER NOT NULL,
                path TEXT NOT NULL,
                ogg_path TEXT,
                wav_path TEXT,
                chunks INTEGER,
                duration_s REAL,
                deleted_on_ring INTEGER NOT NULL DEFAULT 0
            );
            """
        )
        self._conn.commit()

    def add_vital(
        self, ts: int, kind: str, value: float, *, source: str = "unknown"
    ) -> None:
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO vitals(ts, kind, value, source) VALUES (?,?,?,?)",
                (ts, kind, value, source),
            )
            self._conn.commit()
        except sqlite3.Error:
            pass

    def stats_today(self, kind: str, now: Optional[int] = None) -> VitalStats:
        start, end = _day_bounds_utc(now)
        rows = self._conn.execute(
            "SELECT value, ts FROM vitals WHERE kind=? AND ts>=? AND ts<? ORDER BY ts",
            (kind, start, end),
        ).fetchall()
        if not rows:
            return VitalStats(kind, 0, None, None, None, None)
        values = [r[0] for r in rows]
        return VitalStats(
            kind=kind,
            count=len(values),
            latest=values[-1],
            min_v=min(values),
            max_v=max(values),
            avg=sum(values) / len(values),
        )

    def add_recording(
        self,
        path: str,
        *,
        ogg_path: Optional[str] = None,
        wav_path: Optional[str] = None,
        chunks: int = 0,
        duration_s: float = 0.0,
        deleted_on_ring: bool = False,
    ) -> None:
        self._conn.execute(
            """INSERT INTO recordings(saved_at, path, ogg_path, wav_path, chunks, duration_s, deleted_on_ring)
               VALUES (?,?,?,?,?,?,?)""",
            (
                int(time.time()),
                path,
                ogg_path,
                wav_path,
                chunks,
                duration_s,
                1 if deleted_on_ring else 0,
            ),
        )
        self._conn.commit()

    def list_recordings(self, limit: int = 50) -> list[dict]:
        cur = self._conn.execute(
            "SELECT id, saved_at, path, ogg_path, wav_path, chunks, duration_s, deleted_on_ring "
            "FROM recordings ORDER BY id DESC LIMIT ?",
            (limit,),
        )
        cols = [
            "id",
            "saved_at",
            "path",
            "ogg_path",
            "wav_path",
            "chunks",
            "duration_s",
            "deleted_on_ring",
        ]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def close(self) -> None:
        self._conn.close()
