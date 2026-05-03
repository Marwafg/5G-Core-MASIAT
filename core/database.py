from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from core.models import AuditEvent, Finding, RunSummary

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "core_security_lab.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                profile_name TEXT NOT NULL,
                mode TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                findings_count INTEGER NOT NULL,
                severity_breakdown TEXT NOT NULL,
                modules TEXT NOT NULL,
                target_scope TEXT NOT NULL,
                aborted INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                nf TEXT NOT NULL,
                module TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                cvss_score REAL NOT NULL,
                response_status INTEGER,
                evidence TEXT NOT NULL,
                remediation TEXT NOT NULL,
                standard_reference TEXT NOT NULL,
                created_at TEXT NOT NULL,
                indicators TEXT NOT NULL,
                dry_run INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(run_id) REFERENCES runs(run_id)
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata TEXT NOT NULL
            );
            """
        )


def save_run(summary: RunSummary) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO runs (
                run_id, profile_name, mode, started_at, completed_at, findings_count,
                severity_breakdown, modules, target_scope, aborted
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                completed_at = excluded.completed_at,
                findings_count = excluded.findings_count,
                severity_breakdown = excluded.severity_breakdown,
                modules = excluded.modules,
                target_scope = excluded.target_scope,
                aborted = excluded.aborted
            """,
            (
                summary.run_id,
                summary.profile_name,
                summary.mode.value,
                summary.started_at.isoformat(),
                summary.completed_at.isoformat() if summary.completed_at else None,
                summary.findings_count,
                json.dumps(summary.severity_breakdown),
                json.dumps(summary.modules),
                summary.target_scope,
                int(summary.aborted),
            ),
        )


def save_findings(findings: Iterable[Finding]) -> None:
    with get_connection() as connection:
        connection.executemany(
            """
            INSERT OR REPLACE INTO findings (
                id, run_id, nf, module, attack_type, endpoint, severity, title, summary,
                cvss_score, response_status, evidence, remediation, standard_reference,
                created_at, indicators, dry_run
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    finding.id,
                    finding.run_id,
                    finding.nf,
                    finding.module,
                    finding.attack_type,
                    finding.endpoint,
                    finding.severity.value,
                    finding.title,
                    finding.summary,
                    finding.cvss_score,
                    finding.response_status,
                    json.dumps(finding.to_dict()["evidence"]),
                    finding.remediation,
                    finding.standard_reference,
                    finding.created_at.isoformat(),
                    json.dumps(finding.indicators),
                    int(finding.dry_run),
                )
                for finding in findings
            ],
        )


def append_audit_event(event: AuditEvent) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO audit_log (run_id, level, message, timestamp, metadata)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                event.run_id,
                event.level,
                event.message,
                event.timestamp.isoformat(),
                json.dumps(event.metadata),
            ),
        )


def get_recent_runs(limit: int = 10) -> list[dict[str, object]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT run_id, profile_name, mode, started_at, completed_at, findings_count,
                   severity_breakdown, modules, target_scope, aborted
            FROM runs
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_findings_for_run(run_id: str) -> list[dict[str, object]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, run_id, nf, module, attack_type, endpoint, severity, title, summary,
                   cvss_score, response_status, evidence, remediation, standard_reference,
                   created_at, indicators, dry_run
            FROM findings
            WHERE run_id = ?
            ORDER BY created_at DESC
            """,
            (run_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_recent_audit(limit: int = 50) -> list[dict[str, object]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT run_id, level, message, timestamp, metadata
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
