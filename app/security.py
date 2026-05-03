from __future__ import annotations

import re
from typing import Any

from fastapi import Header, HTTPException, status

from app.config import settings

PAYLOAD_PATTERNS: dict[str, str] = {
    "sql_union": r"\bunion\b",
    "sql_or_true": r"('|%27)\s*or\s*('|%27)?1('|%27)?\s*=\s*('|%27)?1",
    "sql_comment": r"--|/\*|\*/|#",
    "command_chain": r";|&&|\|\|",
    "command_subshell": r"`|\$\(",
    "path_traversal": r"\.\./",
}


def require_api_key(x_api_key: str = Header(default="")) -> None:
    if x_api_key != settings.demo_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Missing or invalid demo API key. Use x-api-key: {settings.demo_api_key}",
        )


def evaluate_payload(payload: str) -> dict[str, Any]:
    lowered = payload.lower()
    hits = [
        name
        for name, pattern in PAYLOAD_PATTERNS.items()
        if re.search(pattern, lowered, flags=re.IGNORECASE)
    ]
    risk_score = min(100, 20 + len(hits) * 20 + min(len(payload) // 10, 20))
    if risk_score >= 80:
        severity = "critical"
    elif risk_score >= 60:
        severity = "high"
    elif risk_score >= 40:
        severity = "medium"
    else:
        severity = "low"
    return {
        "payload": payload,
        "risk_score": risk_score,
        "severity": severity,
        "indicators": hits or ["none"],
        "recommended_control": (
            "Use allowlists, parameterized queries, strict input validation, and API authentication."
        ),
    }


def assert_safe_input(payload: str) -> None:
    evaluation = evaluate_payload(payload)
    if evaluation["indicators"] != ["none"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Potential injection payload blocked by secure policy.",
                "evaluation": evaluation,
            },
        )
