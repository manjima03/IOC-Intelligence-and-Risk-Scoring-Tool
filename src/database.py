import json
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "ioc_history.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                assessment TEXT NOT NULL,
                reasons TEXT NOT NULL,
                intelligence TEXT NOT NULL
            )
        """)

def save_result(result):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO analyses
            (timestamp, ioc, ioc_type, risk_score, severity, confidence, assessment, reasons, intelligence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.get("timestamp", ""), result.get("ioc", ""), result.get("ioc_type", ""),
            result.get("risk_score", 0), result.get("severity", ""), result.get("confidence", ""),
            result.get("assessment", ""), json.dumps(result.get("reasons", [])),
            json.dumps(result.get("intelligence", {}))
        ))

def get_history(limit=500):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT timestamp, ioc, ioc_type, risk_score, severity, confidence, assessment
            FROM analyses ORDER BY id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]
