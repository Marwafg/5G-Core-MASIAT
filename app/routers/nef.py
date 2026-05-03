from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.security import evaluate_payload, require_api_key

router = APIRouter(prefix="/api/nef", tags=["NEF"])


def simulate_vulnerable_command(target: str) -> dict:
    assembled = f"ping -n 1 {target}"
    suspicious = re.findall(r"(;|&&|\|\||`|\$\()", target)
    return {
        "mode": "vulnerable",
        "target": target,
        "command_plan": assembled,
        "injected_segments": suspicious or ["none"],
        "impact": (
            "Input is concatenated directly into an operating-system command."
            if suspicious
            else "Normal diagnostic execution."
        ),
    }


def simulate_secure_command(target: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,64}", target):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Secure NEF policy rejected the target. Only hostnames and IPv4-like tokens are allowed.",
        )
    return {
        "mode": "secure",
        "target": target,
        "command_plan": ["ping", "-n", "1", target],
        "impact": "Validated input accepted.",
    }


@router.get("/vulnerable/diagnostics")
def vulnerable_diagnostics(target: str = Query(min_length=1, max_length=120)) -> dict:
    return {
        **simulate_vulnerable_command(target),
        "evaluation": evaluate_payload(target),
    }


@router.get("/secure/diagnostics", dependencies=[Depends(require_api_key)])
def secure_diagnostics(target: str = Query(min_length=1, max_length=120)) -> dict:
    secure_result = simulate_secure_command(target)
    return {
        **secure_result,
        "evaluation": evaluate_payload(target),
    }
