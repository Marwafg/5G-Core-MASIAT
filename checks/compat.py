from __future__ import annotations

import json

from app.database import search_subscribers_secure, search_subscribers_vulnerable
from app.routers.nef import simulate_secure_command, simulate_vulnerable_command
from app.telecom_security import create_sample_jwt, tamper_jwt_role, verify_nf_token


def vulnerable_subscriber_probe(query: str) -> tuple[dict, str]:
    rows = search_subscribers_vulnerable(query)
    response = {
        "status_code": 200 if rows else 404,
        "body": json.dumps({"records_returned": len(rows), "records": rows}),
    }
    evidence = f"Vulnerable UDM flow returned {len(rows)} records for query `{query}`."
    return response, evidence


def secure_subscriber_probe(query: str) -> tuple[dict, str]:
    rows = search_subscribers_secure(query)
    response = {
        "status_code": 200 if rows else 404,
        "body": json.dumps({"records_returned": len(rows), "records": rows}),
    }
    evidence = f"Secure UDM flow returned {len(rows)} records after parameterized lookup."
    return response, evidence


def jwt_probe(role: str = "admin") -> tuple[dict, str]:
    tampered = tamper_jwt_role(create_sample_jwt(), role=role)
    verification = verify_nf_token(tampered)
    response = {"status_code": 401 if verification["status"] == "blocked" else 200, "body": json.dumps(verification)}
    evidence = verification["message"]
    return response, evidence


def command_probe(target: str) -> tuple[dict, str]:
    vulnerable = simulate_vulnerable_command(target)
    try:
        secure = simulate_secure_command(target)
        secure_status = 200
    except Exception as exc:  # FastAPI HTTPException is enough here
        secure = {"detail": getattr(exc, "detail", str(exc))}
        secure_status = getattr(exc, "status_code", 400)
    response = {
        "status_code": 200,
        "body": json.dumps({"vulnerable": vulnerable, "secure": secure, "secure_status": secure_status}),
    }
    evidence = "Vulnerable NEF command concatenated the target directly into a shell-like string."
    return response, evidence
