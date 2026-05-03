from __future__ import annotations

import json
from pathlib import Path

REPORT_DIR = Path(__file__).resolve().parent


def generate(output_path: str = "report/network_map.html") -> str:
    report_path = REPORT_DIR / "report.json"
    findings = []
    if report_path.exists():
        findings = json.loads(report_path.read_text(encoding="utf-8")).get("findings", [])

    statuses = {item["affected_nf"]: item["status"] for item in findings}
    nodes = [
        {"id": "NRF", "label": "NRF", "status": statuses.get("NRF", "UNKNOWN")},
        {"id": "UDM", "label": "UDM", "status": statuses.get("UDM", "UNKNOWN")},
        {"id": "AUSF", "label": "AUSF", "status": statuses.get("AUSF", "UNKNOWN")},
        {"id": "PCF", "label": "PCF", "status": statuses.get("PCF", "UNKNOWN")},
        {"id": "ROGUE_AMF", "label": "ROGUE AMF", "status": "ATTACKER"},
    ]

    lines = [
        "<!DOCTYPE html>",
        "<html><head><meta charset='utf-8'><title>5G Scanner Network Map</title></head><body>",
        "<h1>5G Scanner Network Map</h1>",
        "<ul>",
    ]
    for node in nodes:
        lines.append(f"<li><strong>{node['label']}</strong>: {node['status']}</li>")
    lines.extend(["</ul>", "</body></html>"])

    target = Path(output_path)
    target.write_text("".join(lines), encoding="utf-8")
    return str(target)
