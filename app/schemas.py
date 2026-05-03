from __future__ import annotations

from pydantic import BaseModel, Field


class AttackTestRequest(BaseModel):
    attack_vector: str = Field(
        pattern="^(sql_injection|nosql_injection|command_injection|jwt_manipulation|nrf_spoofing|jwt_attack|bola|json_injection|supi_manipulation)$"
    )
    payload: str = Field(min_length=1, max_length=200)


class ServiceRegistration(BaseModel):
    service_name: str = Field(min_length=2, max_length=20)
    endpoint: str = Field(min_length=3, max_length=120)
    health: str = Field(pattern="^(UP|DEGRADED|DOWN)$")


class JwtVerificationRequest(BaseModel):
    token: str = Field(min_length=20)


class ScanRunRequest(BaseModel):
    profile_name: str = Field(default="mock-local-lab", min_length=3)
    mode: str = Field(default="dry-run", pattern="^(dry-run|active)$")
    selected_modules: list[str] = Field(default_factory=list)
