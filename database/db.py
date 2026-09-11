"""SQLite alert storage."""

import sqlite3
import threading
from pathlib import Path


SCHEMA = """

CREATE TABLE IF NOT EXISTS alerts (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    timestamp TEXT NOT NULL,

    rule TEXT NOT NULL,

    severity TEXT NOT NULL,

    description TEXT NOT NULL,

    src_ip TEXT,

    dst_ip TEXT,

    src_port INTEGER,

    dst_port INTEGER,

    proto TEXT,

    confidence REAL
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts
ON alerts(timestamp);

"""


class AlertStore:

    def __init__(self, path):

        Path(path).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self._lock = threading.Lock()

        self._conn = sqlite3.connect(
            path,
            check_same_thread=False
        )

        self._conn.executescript(SCHEMA)

        self._conn.commit()

    def save(self, alert):

        with self._lock:

            self._conn.execute(
                """
                INSERT INTO alerts
                (
                    timestamp,
                    rule,
                    severity,
                    description,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    proto,
                    confidence
                )
                VALUES (
                    datetime('now'),
                    ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,

                (
                    alert["rule"],
                    alert["severity"],
                    alert["description"],
                    alert["src_ip"],
                    alert["dst_ip"],
                    alert["src_port"],
                    alert["dst_port"],
                    alert["proto"],
                    alert["confidence"],
                )
            )

            self._conn.commit()

    def recent(self, limit=100):

        with self._lock:

            cursor = self._conn.execute(
                """
                SELECT *
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            )

            rows = cursor.fetchall()

            columns = [
                description[0]
                for description
                in cursor.description
            ]

        return [
            dict(zip(columns, row))
            for row in rows
        ]

    def stats(self):

        with self._lock:

            total = self._conn.execute(
                "SELECT COUNT(*) FROM alerts"
            ).fetchone()[0]

            by_rule = self._conn.execute(
                """
                SELECT rule, COUNT(*)
                FROM alerts
                GROUP BY rule
                ORDER BY COUNT(*) DESC
                """
            ).fetchall()

            by_severity = self._conn.execute(
                """
                SELECT severity, COUNT(*)
                FROM alerts
                GROUP BY severity
                """
            ).fetchall()

        return {
            "total": total,
            "by_rule": dict(by_rule),
            "by_severity": dict(by_severity),
        }

    def clear(self):
        """Delete all stored security events."""
        with self._lock:
            self._conn.execute("DELETE FROM alerts")
            self._conn.commit()

    def close(self):

        self._conn.close()
