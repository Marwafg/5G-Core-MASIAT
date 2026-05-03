from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.schemas import ScanRunRequest
from core.database import get_findings_for_run, get_recent_audit, get_recent_runs
from core.scanner_engine import execute_run, list_modules, list_profiles

router = APIRouter(prefix="/api/scanner", tags=["Scanner"])


@router.get("/profiles")
def profiles() -> dict:
    return {"profiles": list_profiles()}


@router.get("/modules")
def modules() -> dict:
    return {"modules": list_modules()}


@router.get("/runs")
def runs() -> dict:
    return {"runs": get_recent_runs()}


@router.get("/runs/{run_id}")
def run_details(run_id: str) -> dict:
    findings = get_findings_for_run(run_id)
    if not findings:
        raise HTTPException(status_code=404, detail="Run not found.")
    return {"run_id": run_id, "findings": findings}


@router.get("/audit")
def audit() -> dict:
    return {"events": get_recent_audit()}


@router.post("/run")
def launch_scan(request: ScanRunRequest) -> dict:
    return execute_run(
        profile_name=request.profile_name,
        mode=request.mode,
        selected_modules=request.selected_modules or None,
    )
