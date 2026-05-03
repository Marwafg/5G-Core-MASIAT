from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import jwt
import yaml
from openapi_spec_validator import validate_spec

from app.config import settings
from app.security import evaluate_payload

BASE_DIR = Path(__file__).resolve().parent.parent
SPEC_PATH = BASE_DIR / "app" / "data" / "3gpp_nrf_mock.yaml"
UPLOADS_DIR = BASE_DIR / "uploads"
JWT_SECRET = "5gc-lab-jwt-secret"
JWT_ISSUER = "nrf.security.lab"
JWT_AUDIENCE = "5gc-core"

STRIDE_MODEL = [
    {
        "category": "Spoofing",
        "target": "API authentication and NRF service identity",
        "vector": "JWT misuse, fake NF identity, or spoofed service registration on NRF APIs.",
        "control": "Mutual trust, OAuth 2.0 JWT validation, issuer and audience checks.",
    },
    {
        "category": "Tampering",
        "target": "JSON request bodies and subscriber identity inputs",
        "vector": "JSON injection, SUPI injection, and NoSQL-style tampering in request bodies and parameters.",
        "control": "Schema validation, input allowlists, signature verification, immutable logs.",
    },
    {
        "category": "Repudiation",
        "target": "Inter-service API calls",
        "vector": "Caller denies sending malicious SBI requests.",
        "control": "Request IDs, signed tokens, audit logs, proxy traces.",
    },
    {
        "category": "Information Disclosure",
        "target": "Subscriber and microservice API data",
        "vector": "Unauthorized 200 OK responses, leaked subscriber objects, and excessive API data exposure.",
        "control": "Least privilege, strict filtering, gateway policy, and object-level authorization checks.",
    },
    {
        "category": "Denial of Service",
        "target": "5G core API availability",
        "vector": "Malformed JSON fuzzing, oversized payloads, and schema-driven abnormal inputs.",
        "control": "Rate limiting, body limits, circuit breakers, health verification.",
    },
    {
        "category": "Elevation of Privilege",
        "target": "Object-level access and protected SBI operations",
        "vector": "BOLA against subscriber or session objects, or scope escalation through manipulated claims.",
        "control": "Role-based authorization, scope enforcement, signature validation.",
    },
]

MANUAL_TOOLS = [
    "Burp Suite",
    "Postman",
    "Mitmproxy",
]

AUTOMATION_TOOLS = [
    "UERANSIM",
    "Boofuzz",
    "Atheist",
    "5Greplay",
]

ATTACK_CATALOG = [
    "nrf_spoofing",
    "jwt_attack",
    "bola",
    "json_injection",
    "supi_manipulation",
]


def get_lab_blueprint() -> dict[str, Any]:
    return {
        "environment": {
            "core": ["Open5GS", "free5GC"],
            "traffic_generator": "UERANSIM",
            "deployment": ["Docker", "Kubernetes", "Single Linux VM"],
            "interception": "Mitmproxy between simulated network functions",
        },
        "standards": [
            "3GPP TS 33.501",
            "OWASP API Security Top 10",
        ],
        "focus": "Protect SBI exchanges and validate JWT-based trust between NFs.",
        "recommended_stack": {
            "language": "Python",
            "security": MANUAL_TOOLS,
            "fuzzing": AUTOMATION_TOOLS,
        },
    }


def get_attack_catalog() -> list[dict[str, str]]:
    return [
        {
            "id": "nrf_spoofing",
            "title": "Service Registration API Abuse",
            "goal": "Test whether NRF registration APIs accept fake NF identities or untrusted service profiles.",
        },
        {
            "id": "jwt_attack",
            "title": "API Authentication Validation Tester",
            "goal": "Test JWT claim tampering, scope misuse, replay, and invalid audience or issuer combinations.",
        },
        {
            "id": "bola",
            "title": "Object-Level Authorization Tester",
            "goal": "Test whether changing a subscriber or NF object identifier exposes unauthorized resources.",
        },
        {
            "id": "json_injection",
            "title": "Injection Testing Module",
            "goal": "Inject nested JSON operators, malformed structures, and schema-breaking data into SBI request bodies.",
        },
        {
            "id": "supi_manipulation",
            "title": "Subscriber Identity Injection Tester",
            "goal": "Tamper with SUPI values to test filtering, authorization, and injection resistance in subscriber APIs.",
        },
    ]


def get_implementation_playbook() -> list[dict[str, Any]]:
    return [
        {
            "id": "lab_setup",
            "title": "Lab Environment Setup",
            "summary": "Deploy free5GC or Open5GS in Docker or Kubernetes and use UERANSIM to generate real SBA traffic safely.",
            "items": [
                "Run the 5G core in an isolated Docker Compose, Kubernetes, or VM lab rather than on a live network.",
                "Use free5GC or Open5GS control-plane functions such as AMF, SMF, NRF, UDM, UDR, AUSF, PCF, NSSF, and related services.",
                "Use UERANSIM to simulate gNB and UE behavior so the core produces real NAS, NGAP, and SBI exchanges.",
                "Treat the resulting SBI traffic as ground truth for interception and replay.",
                "Keep the lab contained in Docker, Kubernetes, or a VM and never run these tests on a live production mobile core.",
            ],
        },
        {
            "id": "api_discovery",
            "title": "API Discovery & Interception",
            "summary": "Parse 3GPP OpenAPI specs and capture live NF-to-NF traffic through an interception proxy.",
            "items": [
                "Use an OpenAPI parser such as prance or openapi-spec-validator to enumerate endpoints, parameters, and schemas.",
                "Identify user-controlled inputs such as SUPI, session identifiers, and registration payloads.",
                "Deploy Mitmproxy or a transparent HTTP/2 proxy between network functions to observe headers, JWT claims, and JSON bodies.",
                "Register a test NF with the NRF using Nnrf_NFManagement_NFRegister and a client identity aligned with its NFInstanceID.",
                "Use the captured headers, tokens, URLs, and JSON examples to build realistic malicious payloads rather than synthetic guesses.",
            ],
        },
        {
            "id": "attack_engine",
            "title": "Attack Engine & Payload Generation",
            "summary": "Drive SQL, NoSQL, JWT, command, JSON, and object-level attacks using schema-aware payloads.",
            "items": [
                "Inject SQL or NoSQL payloads into identifiers such as SUPI, tracking area IDs, and NRF discovery filters.",
                "Tamper with JWT claims, scopes, issuer, audience, or signatures to test NF token validation and cross-service token abuse.",
                "Generate malformed or extreme JSON from OpenAPI schemas using fuzzers such as Boofuzz, Atheris, or FivGeeFuzz-like approaches.",
                "Replay forged NF registrations to model NRF spoofing and fake service discovery behavior.",
                "Add OS command payloads anywhere a network function could pass user-controlled input into scripts or shell commands.",
            ],
        },
        {
            "id": "automation_reporting",
            "title": "Automation, Monitoring & Reporting",
            "summary": "Automate the attacks and verify availability, authorization, and data exposure after each run.",
            "items": [
                "Check for service crashes, panics, timeouts, or signs of denial of service after each injection attempt.",
                "Detect unauthorized 200 OK responses and unexpected data disclosure such as another subscriber profile.",
                "Record response codes, error messages, and affected threat categories using STRIDE labels.",
                "Produce structured evidence showing whether the vulnerable flow succeeded and the secure flow blocked it.",
                "Tie each finding to a concise statement such as JSON injection in a Nudm path causing information disclosure or BOLA on a subscriber object.",
            ],
        },
        {
            "id": "critical_attacks",
            "title": "Critical 5G Attack Focus",
            "summary": "Emphasize NRF spoofing, JWT abuse, BOLA, JSON injection, and SUPI manipulation.",
            "items": [
                "NRF Spoofing: attempt fake NF registration and malicious service discovery injection.",
                "JWT Attacks: modify roles or scopes and test whether producer NFs verify signature and audience.",
                "BOLA: swap object identifiers such as subscriber IDs or session IDs to access unauthorized records.",
                "JSON Injection and SUPI Manipulation: test malformed nested JSON and specially crafted subscriber identities.",
                "Tooling Inspiration: borrow stateful fuzzing ideas from research tools such as 5GC-Fuzz and CORECRISIS while staying focused on service-level SBI APIs.",
            ],
        },
        {
            "id": "standards_tools",
            "title": "Standards & Tools",
            "summary": "Anchor the project in 3GPP TS 33.501, OWASP API Security Top 10, and Python-based telecom testing workflows.",
            "items": [
                "Use 3GPP TS 33.501 as the reference for SBA authentication, authorization, and transport security expectations.",
                "Map findings to OWASP API Security Top 10, especially BOLA, Broken Authentication, Injection, and Excessive Data Exposure.",
                "Use Python with httpx, jwt libraries, parsers, and fuzzers for rapid experimentation.",
                "Use Postman, Burp Suite, Mitmproxy, Docker, Kubernetes, and UERANSIM for manual and automated validation.",
                "Remember that the centralized NRF and cloud-native trust model make token validation and fake-NF prevention especially critical.",
            ],
        },
    ]


def get_reference_sources() -> list[dict[str, str]]:
    return [
        {
            "title": "3GPP TS 33.501",
            "category": "Specification",
            "summary": "Primary security architecture reference for 5G SBA, including NF authentication and transport protection.",
        },
        {
            "title": "3GPP OpenAPI YAML Definitions",
            "category": "Specification",
            "summary": "OpenAPI contracts used to enumerate endpoints, schemas, and attackable parameters across network functions.",
        },
        {
            "title": "free5GC and Open5GS Deployment Guides",
            "category": "Open Source Docs",
            "summary": "Used to build the isolated lab core in Docker, Kubernetes, or VM-based environments.",
        },
        {
            "title": "UERANSIM Setup Documentation",
            "category": "Open Source Docs",
            "summary": "Used to simulate gNB and UE traffic that triggers real API interactions between control-plane services.",
        },
        {
            "title": "OWASP API Security Top 10",
            "category": "Security Guidance",
            "summary": "Maps well to 5G SBI risks including BOLA, broken authentication, injection, and excessive data exposure.",
        },
        {
            "title": "STRIDE-based 5G Core Penetration Research",
            "category": "Research",
            "summary": "Supports using STRIDE to structure telecom threat scenarios such as spoofing, tampering, and information disclosure.",
        },
        {
            "title": "Grammar-based 5G API Fuzzing Research",
            "category": "Research",
            "summary": "Demonstrates that 3GPP OpenAPI-driven fuzzing can uncover real faults across free5GC-style SBI implementations.",
        },
        {
            "title": "OAuth2 and Cross-Service Token Analyses for 5G",
            "category": "Research",
            "summary": "Highlights token misuse, replay, and audience-validation failures between network functions.",
        },
    ]


def get_stride_matrix() -> list[dict[str, str]]:
    return STRIDE_MODEL


def parse_openapi_spec(spec_path: Path | None = None) -> dict[str, Any]:
    path = spec_path or SPEC_PATH
    with path.open("r", encoding="utf-8") as handle:
        spec = yaml.safe_load(handle)

    validate_spec(spec)

    endpoints: list[dict[str, Any]] = []
    for route, methods in spec.get("paths", {}).items():
        for method, details in methods.items():
            parameters = details.get("parameters", [])
            request_body = details.get("requestBody", {})
            vulnerable_inputs = []
            for parameter in parameters:
                location = parameter.get("in", "unknown")
                name = parameter.get("name", "unnamed")
                vulnerable_inputs.append(
                    {
                        "name": name,
                        "location": location,
                        "risk": "high" if location in {"query", "path"} else "medium",
                    }
                )
            if request_body:
                vulnerable_inputs.append(
                    {
                        "name": "requestBody",
                        "location": "body",
                        "risk": "high",
                    }
                )
            endpoints.append(
                {
                    "path": route,
                    "method": method.upper(),
                    "operation_id": details.get("operationId", f"{method}_{route}"),
                    "summary": details.get("summary", ""),
                    "candidate_inputs": vulnerable_inputs,
                }
            )
    return {
        "spec_title": spec.get("info", {}).get("title", "Unknown"),
        "spec_version": spec.get("info", {}).get("version", "unknown"),
        "endpoints": endpoints,
    }


def generate_fuzz_payloads(limit: int = 8) -> list[dict[str, Any]]:
    parsed = parse_openapi_spec()
    seeds = [
        {"type": "sql_injection", "payload": "' OR 1=1 --"},
        {"type": "nosql_injection", "payload": '{"$ne": null}'},
        {"type": "nosql_regex", "payload": '{"$regex": ".*"}'},
        {"type": "command_injection", "payload": "8.8.8.8 && cat /etc/passwd"},
        {"type": "jwt_claim_tamper", "payload": '{"role":"admin"}'},
        {"type": "json_fuzz", "payload": '{"nfType":"' + ("A" * 64) + '"}'},
        {"type": "path_traversal", "payload": "../../etc/passwd"},
        {"type": "oversized_body", "payload": "A" * 256},
    ]
    payloads = []
    for endpoint in parsed["endpoints"]:
        for seed in seeds:
            payloads.append(
                {
                    "operation_id": endpoint["operation_id"],
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "attack_type": seed["type"],
                    "payload": seed["payload"],
                    "evaluation": evaluate_payload(seed["payload"]),
                }
            )
    return payloads[:limit]


def create_sample_jwt(role: str = "nf-service") -> str:
    claims = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "sub": "nrf-consumer",
        "role": role,
        "scope": "nnrf-disc nnrf-nfm",
    }
    return jwt.encode(claims, JWT_SECRET, algorithm="HS256")


def tamper_jwt_role(token: str, role: str = "admin") -> str:
    header_b64, payload_b64, signature = token.split(".")
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    payload["role"] = role
    tampered_payload = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8").rstrip("=")
    return ".".join([header_b64, tampered_payload, signature])


def verify_nf_token(token: str) -> dict[str, Any]:
    try:
        claims = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            audience=JWT_AUDIENCE,
            issuer=JWT_ISSUER,
        )
        return {
            "valid": True,
            "status": "accepted",
            "claims": claims,
            "message": "JWT signature, issuer, and audience are valid.",
        }
    except jwt.PyJWTError as exc:
        return {
            "valid": False,
            "status": "blocked",
            "claims": None,
            "message": f"JWT verification failed: {exc}",
        }
