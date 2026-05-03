from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from config import NRF_URL

REPORT_DIR = Path(__file__).resolve().parent


def save_scan_report(results: Iterable) -> Path:
    output_path = REPORT_DIR / "report.json"
    payload = {
        "tool": "5G Scanner",
        "mode": "scan",
        "target": NRF_URL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "check_id": item.check_id,
                "name": item.name,
                "status": item.status,
                "severity": item.severity,
                "affected_nf": item.affected_nf,
                "endpoint": item.endpoint,
                "request": item.request,
                "response": item.response,
                "evidence": item.evidence,
                "conclusion": item.conclusion,
            }
            for item in results
        ],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def save_attack_report(results: Iterable) -> Path:
    output_path = REPORT_DIR / "attack_report.json"
    payload = {
        "tool": "5G Scanner",
        "mode": "attack",
        "target": NRF_URL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "attack_id": item.attack_id,
                "name": item.name,
                "affected_nf": item.affected_nf,
                "endpoint": item.endpoint,
                "success": item.success,
                "data": item.data,
                "evidence": item.evidence,
                "conclusion": item.conclusion,
            }
            for item in results
        ],
    }
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path
