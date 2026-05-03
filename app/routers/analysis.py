from __future__ import annotations

from fastapi import APIRouter

from app.schemas import JwtVerificationRequest
from app.telecom_security import (
    get_attack_catalog,
    create_sample_jwt,
    generate_fuzz_payloads,
    get_implementation_playbook,
    get_lab_blueprint,
    get_reference_sources,
    get_stride_matrix,
    parse_openapi_spec,
    tamper_jwt_role,
    verify_nf_token,
)

router = APIRouter(prefix="/api/analysis", tags=["Security Analysis"])


@router.get("/lab")
def get_lab() -> dict:
    return get_lab_blueprint()


@router.get("/catalog")
def get_catalog() -> dict:
    return {"attacks": get_attack_catalog()}


@router.get("/playbook")
def get_playbook() -> dict:
    return {"sections": get_implementation_playbook()}


@router.get("/sources")
def get_sources() -> dict:
    return {"sources": get_reference_sources()}


@router.get("/stride")
def get_stride() -> dict:
    return {"model": get_stride_matrix()}


@router.get("/openapi")
def get_openapi_analysis() -> dict:
    return parse_openapi_spec()


@router.get("/fuzz")
def get_fuzz_payloads() -> dict:
    return {"payloads": generate_fuzz_payloads()}


@router.get("/oauth/sample")
def get_oauth_samples() -> dict:
    valid = create_sample_jwt()
    tampered = tamper_jwt_role(valid)
    return {
        "valid_token": valid,
        "tampered_token": tampered,
        "expected_validation": {
            "valid_token": "accepted",
            "tampered_token": "blocked",
        },
    }


@router.post("/oauth/verify")
def verify_oauth_token(request: JwtVerificationRequest) -> dict:
    return verify_nf_token(request.token)
