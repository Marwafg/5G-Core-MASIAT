from __future__ import annotations

from app.database import list_services
from checks.base_check import BaseCheck


class NRFEnumCheck(BaseCheck):
    check_id = "CHECK-001"
    name = "NRF Service Enumeration"
    affected_nf = "NRF"
    endpoint = "/api/nrf/services"
    severity = "MEDIUM"

    def run(self):
        services = list_services()
        status = "VULNERABLE" if services else "PATCHED"
        return self.result(
            status=status,
            request={"method": "GET", "path": self.endpoint},
            response={"status_code": 200, "body": str({"services": services})},
            evidence=f"Enumeration exposed {len(services)} registered services.",
            conclusion="NRF discovery data is accessible for lab demonstration purposes.",
        )
