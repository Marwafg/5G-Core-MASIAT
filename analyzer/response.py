from __future__ import annotations

from typing import Any

from core.models import AttackCase, ResponseEvidence, Severity

STACK_TRACE_HINTS = [
    "traceback",
    "exception",
    "stack trace",
    "sql syntax",
    "sqlite",
    "jwt",
    "nullreference",
]


def analyze_response(case: AttackCase, evidence: ResponseEvidence, dry_run: bool) -> dict[str, Any]:
    body = (evidence.response_body or "").lower()
    indicators: list[str] = []
    severity = Severity.LOW
    cvss = 3.4

    if dry_run:
        indicators.append("dry-run payload prepared")
        return {
            "severity": Severity.INFO,
            "cvss": 0.0,
            "summary": "Payload staged in dry-run mode without transmitting traffic.",
            "indicators": indicators,
        }

    if evidence.error:
        indicators.append("transport error observed")
        severity = Severity.MEDIUM
        cvss = 5.9

    if evidence.status_code and evidence.status_code >= 500:
        indicators.append("server error")
        severity = Severity.HIGH
        cvss = max(cvss, 7.5)

    if any(hint in body for hint in STACK_TRACE_HINTS):
        indicators.append("error leakage")
        severity = Severity.HIGH
        cvss = max(cvss, 8.2)

    if evidence.elapsed_ms > 4_000:
        indicators.append("timing anomaly")
        severity = max(severity, Severity.MEDIUM, key=_severity_rank)
        cvss = max(cvss, 5.2)

    if case.attack_type in {
        "oauth2_token_injection",
        "scope_escalation",
        "nf_type_spoofing",
        "pdu_session_hijacking",
    } and evidence.status_code in {200, 201, 202, 204}:
        indicators.append("unexpected authorization success")
        severity = Severity.CRITICAL
        cvss = 9.3

    if case.attack_type in {
        "path_traversal",
        "json_injection",
        "header_injection",
        "supi_suci_injection",
        "nf_instance_id_injection",
    } and evidence.status_code in {200, 201}:
        indicators.append("payload accepted")
        severity = max(severity, Severity.HIGH, key=_severity_rank)
        cvss = max(cvss, 7.8)

    if not indicators:
        indicators.append("no high-risk anomaly detected")

    return {
        "severity": severity,
        "cvss": round(cvss, 1),
        "summary": _summarize(case.attack_type, indicators),
        "indicators": indicators,
    }


def _summarize(attack_type: str, indicators: list[str]) -> str:
    return f"{attack_type.replace('_', ' ').title()} analysis completed with indicators: {', '.join(indicators)}."


def _severity_rank(severity: Severity) -> int:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return order[severity]
