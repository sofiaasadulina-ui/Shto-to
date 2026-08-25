"""История проверок в SQLite.

Соединение создаётся внутри каждой функции: проверки идут в отдельном потоке,
а sqlite3-соединение нельзя разделять между потоками.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .models import Verdict

DEFAULT_DB = Path(__file__).resolve().parent.parent / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS checks (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    url           TEXT    NOT NULL,
    score         INTEGER NOT NULL,
    level         TEXT    NOT NULL,
    heuristic     INTEGER NOT NULL DEFAULT 0,
    ml_probability REAL,
    used_network  INTEGER NOT NULL DEFAULT 0,
    signals_json  TEXT    NOT NULL DEFAULT '[]',
    network_json  TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_checks_ts ON checks(ts DESC);
"""


@dataclass
class HistoryRow:
    id: int
    ts: str
    url: str
    score: int
    level: str
    heuristic: int
    ml_probability: float | None
    used_network: bool

    @property
    def ts_short(self) -> str:
        """ts в виде ДД.ММ ЧЧ:ММ для таблицы в интерфейсе."""
        try:
            return datetime.fromisoformat(self.ts).strftime("%d.%m %H:%M")
        except ValueError:
            return self.ts[:16]


def _connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    path = Path(db_path) if db_path is not None else DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def save(verdict: Verdict, db_path: Path | str | None = None) -> int:
    """Сохраняет вердикт и возвращает id записи."""
    with _connect(db_path) as conn:
        cur = conn.execute(
            """INSERT INTO checks
               (ts, url, score, level, heuristic, ml_probability, used_network,
                signals_json, network_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now().isoformat(timespec="seconds"),
                verdict.url,
                verdict.score,
                verdict.level,
                verdict.heuristic_score,
                verdict.ml_probability,
                int(verdict.network.enabled),
                json.dumps([s.as_dict() for s in verdict.signals], ensure_ascii=False),
                json.dumps(verdict.network.as_dict(), ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid or 0)


def recent(limit: int = 100, db_path: Path | str | None = None) -> list[HistoryRow]:
    """Последние проверки, новые сверху."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """SELECT id, ts, url, score, level, heuristic, ml_probability, used_network
               FROM checks ORDER BY id DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    return [
        HistoryRow(
            id=r["id"],
            ts=r["ts"],
            url=r["url"],
            score=r["score"],
            level=r["level"],
            heuristic=r["heuristic"],
            ml_probability=r["ml_probability"],
            used_network=bool(r["used_network"]),
        )
        for r in rows
    ]


def stats(db_path: Path | str | None = None) -> dict[str, int]:
    """Сводка по истории: сколько проверок какого уровня."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT level, COUNT(*) AS n FROM checks GROUP BY level"
        ).fetchall()
    result = {"SAFE": 0, "SUSPICIOUS": 0, "DANGEROUS": 0}
    for r in rows:
        result[r["level"]] = r["n"]
    result["TOTAL"] = sum(result.values())
    return result


def clear(db_path: Path | str | None = None) -> None:
    with _connect(db_path) as conn:
        conn.execute("DELETE FROM checks")
