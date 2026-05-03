from __future__ import annotations

import json
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from analyzer.response import analyze_response
from app.database import search_subscribers_secure, search_subscribers_vulnerable
from app.routers.nef import simulate_secure_command, simulate_vulnerable_command
from app.security import evaluate_payload
from app.telecom_security import create_sample_jwt, parse_openapi_spec, tamper_jwt_role, verify_nf_token
from core.database import append_audit_event, save_findings, save_run
from core.models import (
    AttackCase,
    AuditEvent,
    EngineOptions,
    Finding,
    ResponseEvidence,
    RunSummary,
    ScanMode,
    Severity,
    TargetEndpoint,
    TargetProfile,
)
from core.payload_loader import load_profile

PROFILE_DIR = Path(__file__).resolve().parent.parent / "config" / "profiles"

MODULE_CATALOG = {
    "json_injection": {
        "label": "Injection Testing Module",
        "nf": "udm",
        "attack_type": "json_injection",
        "payloads": ['{"supi":{"$ne": null}}', '{"filters":{"$regex":".*"}}'],
        "remediation": "Validate JSON schemas strictly and reject nested operator injection.",
        "standard_reference": "OWASP API8 / STRIDE Tampering",
    },
    "supi_injection": {
        "label": "Subscriber Identity Injection Tester",
        "nf": "udm",
        "attack_type": "supi_manipulation",
        "payloads": ["imsi-001010000000001' OR '1'='1", "' OR 1=1 --"],
        "remediation": "Normalize SUPI format and use parameterized queries with ownership checks.",
        "standard_reference": "OWASP API8 / STRIDE Tampering",
    },
    "openapi_fuzzing": {
        "label": "OpenAPI Input Fuzzing Engine",
        "nf": "nrf",
        "attack_type": "nosql_injection",
        "payloads": ['{"$regex":".*"}', "A" * 180],
        "remediation": "Bound request sizes and validate every discovered input from the OpenAPI contract.",
        "standard_reference": "OWASP API4 / STRIDE Denial of Service",
    },
    "api_auth_validation": {
        "label": "API Authentication Validation Tester",
        "nf": "oauth",
        "attack_type": "jwt_attack",
        "payloads": ['{"role":"admin"}'],
        "remediation": "Enforce JWT signature, issuer, audience, and scope validation for every NF token.",
        "standard_reference": "OWASP API2 / STRIDE Spoofing",
    },
    "object_level_authorization": {
        "label": "Object-Level Authorization Tester",
        "nf": "udm",
        "attack_type": "bola",
        "payloads": ["imsi-001010000000002"],
        "remediation": "Bind every subscriber object read to explicit ownership or service scope validation.",
        "standard_reference": "OWASP API1 / STRIDE Elevation of Privilege",
    },
    "service_registration_abuse": {
        "label": "Service Registration API Abuse",
        "nf": "nrf",
        "attack_type": "nrf_spoofing",
        "payloads": ['{"nfType":"AMF","nfInstanceId":"fake-amf-01","priority":1}'],
        "remediation": "Require trusted NF registration tokens and reject forged service identities.",
        "standard_reference": "OWASP API2 / STRIDE Spoofing",
    },
}


def list_profile_names() -> list[str]:
    return sorted(path.stem for path in PROFILE_DIR.glob("*.yaml"))


def list_profiles() -> list[dict]:
    return [asdict(load_target_profile(name)) for name in list_profile_names()]


def list_modules() -> list[dict]:
    return [
        {
            "id": module_id,
            **module,
        }
        for module_id, module in MODULE_CATALOG.items()
    ]


def load_target_profile(name: str) -> TargetProfile:
    profile = load_profile(name)
    endpoints = [
        TargetEndpoint(
            nf=item["nf"],
            method=item["method"],
            path=item["path"],
            description=item["description"],
            scopes=item.get("scopes", []),
        )
        for item in profile.get("endpoints", [])
    ]
    return TargetProfile(
        name=profile["name"],
        base_url=profile["base_url"],
        description=profile["description"],
        scope=profile["scope"],
        simulate=profile["simulate"],
        rate_limit_per_second=profile["rate_limit_per_second"],
        timeout_seconds=profile["timeout_seconds"],
        concurrency=profile["concurrency"],
        headers=profile.get("headers", {}),
        endpoints=endpoints,
        client_cert=profile.get("client_cert"),
        client_key=profile.get("client_key"),
        proxy=profile.get("proxy"),
    )


def build_attack_cases(profile: TargetProfile, module_ids: list[str] | None = None) -> list[AttackCase]:
    selected = module_ids or list(MODULE_CATALOG.keys())
    parsed_spec = parse_openapi_spec()
    cases: list[AttackCase] = []
    for module_id in selected:
        module = MODULE_CATALOG[module_id]
        endpoint = _match_endpoint(profile, module["nf"], parsed_spec["endpoints"])
        for payload in module["payloads"]:
            cases.append(
                AttackCase(
                    module=module_id,
                    attack_type=module["attack_type"],
                    nf=module["nf"],
                    endpoint=endpoint.path,
                    method=endpoint.method,
                    payload={"payload": payload},
                    metadata={"label": module["label"], "profile": profile.name},
                )
            )
    return cases


def execute_run(profile_name: str, mode: str = "dry-run", selected_modules: list[str] | None = None) -> dict:
    profile = load_target_profile(profile_name)
    scan_mode = ScanMode.ACTIVE if mode == "active" else ScanMode.DRY_RUN
    options = EngineOptions(mode=scan_mode, selected_modules=selected_modules or list(MODULE_CATALOG.keys()))
    run_id = str(uuid4())
    started_at = datetime.now(UTC)
    cases = build_attack_cases(profile, options.selected_modules)
    findings: list[Finding] = []

    append_audit_event(
        AuditEvent(
            run_id=run_id,
            level="info",
            message=f"Scan started for profile {profile.name}",
            timestamp=started_at,
            metadata={"mode": options.mode.value, "modules": options.selected_modules},
        )
    )

    for case in cases:
        evidence = execute_case(case, options.mode == ScanMode.DRY_RUN)
        analysis = analyze_response(case, evidence, dry_run=options.mode == ScanMode.DRY_RUN)
        finding = Finding(
            id=str(uuid4()),
            run_id=run_id,
            nf=case.nf,
            module=case.module,
            attack_type=case.attack_type,
            endpoint=case.endpoint,
            severity=Severity(analysis["severity"]),
            title=f"{case.metadata.get('label', case.module)} on {case.nf.upper()}",
            summary=analysis["summary"],
            cvss_score=analysis["cvss"],
            response_status=evidence.status_code,
            evidence=evidence,
            remediation=MODULE_CATALOG[case.module]["remediation"],
            standard_reference=MODULE_CATALOG[case.module]["standard_reference"],
            created_at=datetime.now(UTC),
            indicators=analysis["indicators"],
            dry_run=options.mode == ScanMode.DRY_RUN,
        )
        findings.append(finding)

    completed_at = datetime.now(UTC)
    severity_breakdown = _severity_breakdown(findings)
    summary = RunSummary(
        run_id=run_id,
        profile_name=profile.name,
        mode=options.mode,
        started_at=started_at,
        completed_at=completed_at,
        findings_count=len(findings),
        severity_breakdown=severity_breakdown,
        modules=options.selected_modules,
        target_scope=profile.scope,
        aborted=False,
    )
    save_run(summary)
    save_findings(findings)
    append_audit_event(
        AuditEvent(
            run_id=run_id,
            level="info",
            message=f"Scan completed with {len(findings)} findings",
            timestamp=completed_at,
            metadata={"severity_breakdown": severity_breakdown},
        )
    )
    return {
        "run_summary": summary.to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }


def execute_case(case: AttackCase, dry_run: bool) -> ResponseEvidence:
    payload = case.payload["payload"]
    if dry_run:
        return ResponseEvidence(
            status_code=None,
            elapsed_ms=0.0,
            request_headers={},
            request_body=json.dumps(case.payload),
            response_headers={},
            response_body=None,
            error=None,
        )

    if case.attack_type == "supi_manipulation":
        vulnerable_rows = search_subscribers_vulnerable(payload)
        secure_rows = search_subscribers_secure(payload)
        body = json.dumps({"vulnerable_rows": vulnerable_rows, "secure_rows": secure_rows})
        status = 200 if vulnerable_rows else 404
    elif case.attack_type == "json_injection":
        accepted = "{" in payload and "}" in payload
        body = json.dumps({"accepted": accepted, "payload": payload})
        status = 200 if accepted else 400
    elif case.attack_type == "nosql_injection":
        accepted = "$" in payload or "regex" in payload.lower()
        body = json.dumps({"accepted_operator": accepted, "payload": payload})
        status = 200 if accepted else 400
    elif case.attack_type == "jwt_attack":
        token = tamper_jwt_role(create_sample_jwt(), role="admin")
        verification = verify_nf_token(token)
        body = json.dumps({"token_preview": token[:60], "verification": verification})
        status = 401 if verification["status"] == "blocked" else 200
    elif case.attack_type == "bola":
        rows = search_subscribers_secure(payload)
        body = json.dumps({"records": rows, "authorization_missing": bool(rows)})
        status = 200 if rows else 404
    elif case.attack_type == "nrf_spoofing":
        accepted = "fake-amf" in payload.lower()
        body = json.dumps({"spoofed_nf_registered": accepted, "payload": payload})
        status = 201 if accepted else 400
    elif case.attack_type == "command_injection":
        body = json.dumps(simulate_vulnerable_command(payload))
        status = 200
    else:
        body = json.dumps({"evaluation": evaluate_payload(payload)})
        status = 200

    return ResponseEvidence(
        status_code=status,
        elapsed_ms=120.0,
        request_headers={"content-type": "application/json"},
        request_body=json.dumps(case.payload),
        response_headers={"content-type": "application/json"},
        response_body=body,
        error=None,
    )


def _match_endpoint(profile: TargetProfile, nf: str, spec_endpoints: list[dict]) -> TargetEndpoint:
    for endpoint in profile.endpoints:
        if endpoint.nf == nf:
            return endpoint
    for endpoint in spec_endpoints:
        if nf in endpoint["path"]:
            return TargetEndpoint(
                nf=nf,
                method=endpoint["method"],
                path=endpoint["path"],
                description=endpoint["summary"],
                scopes=[],
            )
    return TargetEndpoint(nf=nf, method="POST", path=f"/{nf}", description=f"{nf} endpoint")


def _severity_breakdown(findings: list[Finding]) -> dict[str, int]:
    breakdown = {severity.value: 0 for severity in Severity}
    for finding in findings:
        breakdown[finding.severity.value] += 1
    return breakdown
