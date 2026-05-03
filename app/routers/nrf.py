from __future__ import annotations

from fastapi import APIRouter, Depends

from app.database import get_connection, list_services
from app.schemas import ServiceRegistration
from app.security import require_api_key

router = APIRouter(prefix="/api/nrf", tags=["NRF"])


@router.get("/services")
def get_services() -> dict:
    return {"services": list_services()}


@router.post("/services", dependencies=[Depends(require_api_key)])
def register_service(service: ServiceRegistration) -> dict:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO service_registry (service_name, endpoint, health)
            VALUES (?, ?, ?)
            ON CONFLICT(service_name) DO UPDATE SET
                endpoint = excluded.endpoint,
                health = excluded.health
            """,
            (service.service_name, service.endpoint, service.health),
        )
    return {"message": "Service registered securely.", "service": service.model_dump()}
