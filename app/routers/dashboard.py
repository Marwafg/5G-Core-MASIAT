from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.database import get_overview_metrics, get_recent_attack_logs, list_services
from app.telecom_security import (
    generate_fuzz_payloads,
    get_attack_catalog,
    get_implementation_playbook,
    get_lab_blueprint,
    get_reference_sources,
    get_stride_matrix,
)
from core.database import get_recent_runs
from core.scanner_engine import list_modules, list_profiles

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    context = {
        "request": request,
        "metrics": get_overview_metrics(),
        "services": list_services(),
        "logs": get_recent_attack_logs(),
        "stride_items": get_stride_matrix(),
        "fuzz_payloads": generate_fuzz_payloads(limit=4),
        "lab_blueprint": get_lab_blueprint(),
        "attack_catalog": get_attack_catalog(),
        "playbook_sections": get_implementation_playbook(),
        "reference_sources": get_reference_sources(),
        "scanner_profiles": list_profiles(),
        "scanner_modules": list_modules(),
        "recent_runs": get_recent_runs(limit=6),
    }
    return templates.TemplateResponse(request, "index.html", context)


@router.get("/api/overview")
def overview() -> dict:
    return {
        "metrics": get_overview_metrics(),
        "services": list_services(),
        "logs": get_recent_attack_logs(),
        "stride_items": get_stride_matrix(),
        "fuzz_payloads": generate_fuzz_payloads(limit=4),
        "attack_catalog": get_attack_catalog(),
        "playbook_sections": get_implementation_playbook(),
        "reference_sources": get_reference_sources(),
        "scanner_profiles": list_profiles(),
        "scanner_modules": list_modules(),
        "recent_runs": get_recent_runs(limit=6),
    }
