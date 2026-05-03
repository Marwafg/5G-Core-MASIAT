from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanMode(str, Enum):
    DRY_RUN = "dry-run"
    ACTIVE = "active"


@dataclass(slots=True)
class TargetEndpoint:
    nf: str
    method: str
    path: str
    description: str
    scopes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TargetProfile:
    name: str
    base_url: str
    description: str
    scope: str
    simulate: bool
    rate_limit_per_second: float
    timeout_seconds: float
    concurrency: int
    headers: dict[str, str] = field(default_factory=dict)
    endpoints: list[TargetEndpoint] = field(default_factory=list)
    client_cert: str | None = None
    client_key: str | None = None
    proxy: str | None = None


@dataclass(slots=True)
class AttackCase:
    module: str
    attack_type: str
    nf: str
    endpoint: str
    method: str
    payload: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ResponseEvidence:
    status_code: int | None
    elapsed_ms: float
    request_headers: dict[str, str]
    request_body: str | None
    response_headers: dict[str, str]
    response_body: str | None
    error: str | None = None


@dataclass(slots=True)
class Finding:
    id: str
    run_id: str
    nf: str
    module: str
    attack_type: str
    endpoint: str
    severity: Severity
    title: str
    summary: str
    cvss_score: float
    response_status: int | None
    evidence: ResponseEvidence
    remediation: str
    standard_reference: str
    created_at: datetime
    indicators: list[str] = field(default_factory=list)
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "nf": self.nf,
            "module": self.module,
            "attack_type": self.attack_type,
            "endpoint": self.endpoint,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "cvss_score": self.cvss_score,
            "response_status": self.response_status,
            "evidence": {
                "status_code": self.evidence.status_code,
                "elapsed_ms": self.evidence.elapsed_ms,
                "request_headers": self.evidence.request_headers,
                "request_body": self.evidence.request_body,
                "response_headers": self.evidence.response_headers,
                "response_body": self.evidence.response_body,
                "error": self.evidence.error,
            },
            "remediation": self.remediation,
            "standard_reference": self.standard_reference,
            "created_at": self.created_at.isoformat(),
            "indicators": self.indicators,
            "dry_run": self.dry_run,
        }


@dataclass(slots=True)
class AuditEvent:
    run_id: str
    level: str
    message: str
    timestamp: datetime
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RunSummary:
    run_id: str
    profile_name: str
    mode: ScanMode
    started_at: datetime
    completed_at: datetime | None
    findings_count: int
    severity_breakdown: dict[str, int]
    modules: list[str]
    target_scope: str
    aborted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "profile_name": self.profile_name,
            "mode": self.mode.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "findings_count": self.findings_count,
            "severity_breakdown": self.severity_breakdown,
            "modules": self.modules,
            "target_scope": self.target_scope,
            "aborted": self.aborted,
        }


@dataclass(slots=True)
class EngineOptions:
    mode: ScanMode = ScanMode.DRY_RUN
    concurrency: int = 4
    rate_limit_per_second: float = 2.0
    confirmation_phrase: str | None = None
    export_formats: list[str] = field(default_factory=lambda: ["json"])
    selected_modules: list[str] = field(default_factory=list)
    selected_nfs: list[str] = field(default_factory=list)

