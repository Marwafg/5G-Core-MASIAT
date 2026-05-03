from __future__ import annotations

import sqlite3
from typing import Any

from app.config import settings

SUBSCRIBER_SEED = [
    ("imsi-001010000000001", "Amina Haddad", "eMBB", "ACTIVE", "gold"),
    ("imsi-001010000000002", "Yacine Merabet", "URLLC", "ACTIVE", "platinum"),
    ("imsi-001010000000003", "Salma Bensalem", "mMTC", "SUSPENDED", "silver"),
    ("imsi-001010000000004", "Nassim Khelifi", "eMBB", "ACTIVE", "gold"),
]

SERVICE_SEED = [
    ("nrf", "registry.core.local", "UP"),
    ("udm", "subscriber.core.local", "UP"),
    ("nef", "exposure.core.local", "DEGRADED"),
    ("pcf", "policy.core.local", "UP"),
]


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(settings.db_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL;")
    connection.execute("PRAGMA foreign_keys=ON;")
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS subscribers (
                supi TEXT PRIMARY KEY,
                ue_name TEXT NOT NULL,
                network_slice TEXT NOT NULL,
                status TEXT NOT NULL,
                trust_tier TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS service_registry (
                service_name TEXT PRIMARY KEY,
                endpoint TEXT NOT NULL,
                health TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_vector TEXT NOT NULL,
                payload TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                vulnerable_outcome TEXT NOT NULL,
                secure_outcome TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS simulator_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                stored_path TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )

        subscriber_count = connection.execute(
            "SELECT COUNT(*) AS count FROM subscribers"
        ).fetchone()["count"]
        if subscriber_count == 0:
            connection.executemany(
                """
                INSERT INTO subscribers (supi, ue_name, network_slice, status, trust_tier)
                VALUES (?, ?, ?, ?, ?)
                """,
                SUBSCRIBER_SEED,
            )

        service_count = connection.execute(
            "SELECT COUNT(*) AS count FROM service_registry"
        ).fetchone()["count"]
        if service_count == 0:
            connection.executemany(
                """
                INSERT INTO service_registry (service_name, endpoint, health)
                VALUES (?, ?, ?)
                """,
                SERVICE_SEED,
            )


def list_services() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT service_name, endpoint, health FROM service_registry ORDER BY service_name"
        ).fetchall()
    return [dict(row) for row in rows]


def search_subscribers_vulnerable(query: str) -> list[dict[str, Any]]:
    statement = (
        "SELECT supi, ue_name, network_slice, status, trust_tier "
        f"FROM subscribers WHERE supi LIKE '%{query}%' "
        f"OR network_slice = '{query}' OR status = '{query}'"
    )
    with get_connection() as connection:
        rows = connection.execute(statement).fetchall()
    return [dict(row) for row in rows]


def search_subscribers_secure(query: str) -> list[dict[str, Any]]:
    like_query = f"%{query}%"
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT supi, ue_name, network_slice, status, trust_tier
            FROM subscribers
            WHERE supi LIKE ?
            OR network_slice = ?
            OR status = ?
            """,
            (like_query, query, query),
        ).fetchall()
    return [dict(row) for row in rows]


def log_attack(
    attack_vector: str,
    payload: str,
    risk_score: int,
    vulnerable_outcome: str,
    secure_outcome: str,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO attack_logs (
                attack_vector, payload, risk_score, vulnerable_outcome, secure_outcome
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (attack_vector, payload, risk_score, vulnerable_outcome, secure_outcome),
        )


def get_recent_attack_logs(limit: int = 10) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT attack_vector, payload, risk_score, vulnerable_outcome, secure_outcome, created_at
            FROM attack_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_overview_metrics() -> dict[str, Any]:
    with get_connection() as connection:
        services = connection.execute(
            "SELECT COUNT(*) AS count FROM service_registry"
        ).fetchone()["count"]
        subscribers = connection.execute(
            "SELECT COUNT(*) AS count FROM subscribers"
        ).fetchone()["count"]
        attacks = connection.execute(
            "SELECT COUNT(*) AS count FROM attack_logs"
        ).fetchone()["count"]
        uploads = connection.execute(
            "SELECT COUNT(*) AS count FROM simulator_uploads"
        ).fetchone()["count"]
        runs = connection.execute(
            "SELECT COUNT(*) AS count FROM runs"
        ).fetchone()["count"] if _table_exists(connection, "runs") else 0
        findings = connection.execute(
            "SELECT COUNT(*) AS count FROM findings"
        ).fetchone()["count"] if _table_exists(connection, "findings") else 0
    return {
        "services": services,
        "subscribers": subscribers,
        "attack_runs": attacks,
        "uploads": uploads,
        "scan_runs": runs,
        "findings": findings,
    }


def save_upload_metadata(
    filename: str,
    content_type: str,
    size_bytes: int,
    stored_path: str,
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO simulator_uploads (filename, content_type, size_bytes, stored_path)
            VALUES (?, ?, ?, ?)
            """,
            (filename, content_type, size_bytes, stored_path),
        )


def get_recent_uploads(limit: int = 10) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT filename, content_type, size_bytes, stored_path, created_at
            FROM simulator_uploads
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None
