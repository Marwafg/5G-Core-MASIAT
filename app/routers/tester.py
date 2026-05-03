from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, File, HTTPException, UploadFile

from app.database import (
    get_overview_metrics,
    get_recent_attack_logs,
    get_recent_uploads,
    log_attack,
    save_upload_metadata,
    search_subscribers_secure,
    search_subscribers_vulnerable,
)
from app.routers.nef import simulate_secure_command, simulate_vulnerable_command
from app.schemas import AttackTestRequest
from app.security import evaluate_payload
from app.telecom_security import UPLOADS_DIR, create_sample_jwt, tamper_jwt_role, verify_nf_token

router = APIRouter(prefix="/api/tester", tags=["Attack Tester"])


@router.get("/payloads")
def sample_payloads() -> dict:
    return {
        "samples": [
            {
                "attack_vector": "sql_injection",
                "payload": "' OR '1'='1' --",
                "goal": "Bypass filters and dump subscriber records from the vulnerable UDM query.",
            },
            {
                "attack_vector": "command_injection",
                "payload": "8.8.8.8 && whoami",
                "goal": "Append unauthorized shell operations to a diagnostic command.",
            },
            {
                "attack_vector": "nrf_spoofing",
                "payload": '{"nfType":"AMF","nfInstanceId":"fake-amf-01","priority":1}',
                "goal": "Try to register or impersonate a forged NF profile in NRF.",
            },
            {
                "attack_vector": "bola",
                "payload": "imsi-001010000000002",
                "goal": "Request a different subscriber object by changing the direct identifier.",
            },
        ]
    }


@router.post("/run")
def run_attack_test(request: AttackTestRequest) -> dict:
    evaluation = evaluate_payload(request.payload)

    if request.attack_vector == "sql_injection":
        vulnerable_rows = search_subscribers_vulnerable(request.payload)
        secure_rows = search_subscribers_secure(request.payload)
        vulnerable_outcome = f"Returned {len(vulnerable_rows)} records from vulnerable SQL statement."
        secure_outcome = f"Returned {len(secure_rows)} records after parameterized lookup."
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {
                "records_returned": len(vulnerable_rows),
                "records": vulnerable_rows,
                "outcome": vulnerable_outcome,
            },
            "secure": {
                "records_returned": len(secure_rows),
                "records": secure_rows,
                "outcome": secure_outcome,
            },
        }
    elif request.attack_vector == "nosql_injection":
        is_operator_payload = "$" in request.payload or "regex" in request.payload.lower()
        vulnerable_outcome = (
            "Mongo-style operator payload accepted by a vulnerable query mapper."
            if is_operator_payload
            else "Query treated as a normal lookup value."
        )
        secure_outcome = (
            "Secure validation blocked JSON operator injection before database execution."
            if is_operator_payload
            else "Secure validation accepted the non-operator payload."
        )
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {
                "accepted_operator": is_operator_payload,
                "outcome": vulnerable_outcome,
            },
            "secure": {
                "blocked_operator": is_operator_payload,
                "outcome": secure_outcome,
            },
        }
    elif request.attack_vector == "command_injection":
        vulnerable = simulate_vulnerable_command(request.payload)
        try:
            secure = simulate_secure_command(request.payload)
            secure_outcome = "Secure command validation accepted the payload."
        except HTTPException as exc:
            secure = {"mode": "secure", "blocked": True, "detail": exc.detail}
            secure_outcome = "Secure command validation blocked the payload."
        vulnerable_outcome = vulnerable["impact"]
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {**vulnerable, "outcome": vulnerable_outcome},
            "secure": {**secure, "outcome": secure_outcome},
        }
    elif request.attack_vector == "jwt_manipulation":
        original_token = create_sample_jwt()
        tampered_token = tamper_jwt_role(original_token, role="admin")
        verification = verify_nf_token(tampered_token)
        vulnerable_outcome = (
            "A vulnerable NF that only decodes claims would trust the tampered admin role."
        )
        secure_outcome = verification["message"]
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {
                "role_seen": "admin",
                "token": tampered_token,
                "outcome": vulnerable_outcome,
            },
            "secure": {
                "verification": verification,
                "outcome": secure_outcome,
            },
        }
    elif request.attack_vector == "jwt_attack":
        original_token = create_sample_jwt()
        tampered_token = tamper_jwt_role(original_token, role="admin")
        verification = verify_nf_token(tampered_token)
        vulnerable_outcome = "A weak NF accepts the modified token and treats the caller as a privileged peer."
        secure_outcome = verification["message"]
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {
                "accepted_role": "admin",
                "token_preview": tampered_token[:60] + "...",
                "outcome": vulnerable_outcome,
            },
            "secure": {
                "verification": verification,
                "outcome": secure_outcome,
            },
        }
    elif request.attack_vector == "nrf_spoofing":
        forged = "fake-amf" in request.payload.lower() or "nfinstanceid" in request.payload.lower()
        vulnerable_outcome = (
            "Forged NF profile accepted into discovery registry without strong caller validation."
            if forged
            else "Payload resembled a normal NRF registration."
        )
        secure_outcome = (
            "Secure NRF flow rejects spoofed NF registration unless the JWT and caller identity are trusted."
            if forged
            else "Secure NRF validation accepted the shape but still requires trusted identity."
        )
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {"spoofed_nf_registered": forged, "outcome": vulnerable_outcome},
            "secure": {"blocked_spoofing": forged, "outcome": secure_outcome},
        }
    elif request.attack_vector == "bola":
        object_switch = request.payload.startswith("imsi-")
        vulnerable_rows = search_subscribers_secure(request.payload)
        vulnerable_outcome = (
            "Direct object reference changed and another subscriber record became accessible."
            if object_switch and vulnerable_rows
            else "Requested object was not found."
        )
        secure_outcome = (
            "Secure BOLA policy would require ownership or scope verification before returning subscriber data."
        )
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {
                "records_returned": len(vulnerable_rows),
                "records": vulnerable_rows,
                "outcome": vulnerable_outcome,
            },
            "secure": {
                "authorization_required": True,
                "outcome": secure_outcome,
            },
        }
    elif request.attack_vector == "json_injection":
        is_nested = "{" in request.payload and "}" in request.payload
        vulnerable_outcome = (
            "Untrusted JSON body merged into backend query construction without sanitization."
            if is_nested
            else "Payload treated as plain content."
        )
        secure_outcome = (
            "Schema validation and property allowlisting blocked unsafe JSON structure."
            if is_nested
            else "Secure parser accepted safe JSON."
        )
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {"json_merged": is_nested, "outcome": vulnerable_outcome},
            "secure": {"blocked_nested_json": is_nested, "outcome": secure_outcome},
        }
    elif request.attack_vector == "supi_manipulation":
        altered = request.payload.startswith("imsi-") or "'" in request.payload
        rows = search_subscribers_vulnerable(request.payload)
        vulnerable_outcome = (
            "Manipulated SUPI changed the subscriber lookup scope and exposed unintended records."
            if altered and rows
            else "Manipulated SUPI did not match records."
        )
        secure_outcome = "Secure SUPI validation normalizes format and enforces ownership before lookup."
        result = {
            "vector": request.attack_vector,
            "payload": request.payload,
            "evaluation": evaluation,
            "vulnerable": {
                "records_returned": len(rows),
                "records": rows,
                "outcome": vulnerable_outcome,
            },
            "secure": {
                "format_validated": True,
                "outcome": secure_outcome,
            },
        }
    else:  # pragma: no cover
        raise HTTPException(status_code=400, detail="Unsupported attack vector.")

    log_attack(
        attack_vector=request.attack_vector,
        payload=request.payload,
        risk_score=evaluation["risk_score"],
        vulnerable_outcome=vulnerable_outcome,
        secure_outcome=secure_outcome,
    )
    return result


@router.get("/report")
def export_report() -> dict:
    logs = get_recent_attack_logs(limit=50)
    blocked_count = sum(
        1
        for item in logs
        if "blocked" in item["secure_outcome"].lower()
        or "safely" in item["secure_outcome"].lower()
    )
    return {
        "project": "5G Core Microservice API Security and Injection Attack Tester",
        "summary": {
            **get_overview_metrics(),
            "blocked_or_safe_secure_outcomes": blocked_count,
        },
        "attack_history": logs,
        "success_criteria": {
            "attack_succeeds_when": "The vulnerable path exposes more records or shows an injected command plan.",
            "attack_blocked_when": "The secure path returns a 400-class response or reports blocked validation.",
        },
    }


@router.post("/upload")
async def upload_simulator_file(file: UploadFile = File(...)) -> dict:
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    content = await file.read()
    safe_name = Path(file.filename or "scenario.bin").name
    stored_path = UPLOADS_DIR / safe_name
    stored_path.write_bytes(content)
    save_upload_metadata(
        filename=safe_name,
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(content),
        stored_path=str(stored_path),
    )
    return {
        "status": "uploaded",
        "filename": safe_name,
        "content_type": file.content_type or "application/octet-stream",
        "size_bytes": len(content),
        "stored_path": str(stored_path),
        "recent_uploads": get_recent_uploads(),
    }
