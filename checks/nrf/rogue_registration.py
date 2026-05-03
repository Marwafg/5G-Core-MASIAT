from __future__ import annotations

from checks.base_check import BaseCheck


class RogueNFRegistrationCheck(BaseCheck):
    check_id = "CHECK-002"
    name = "Rogue NF Registration Acceptance"
    affected_nf = "NRF"
    endpoint = "/api/nrf/services"
    severity = "HIGH"

    def run(self):
        payload = {"service_name": "rogue-amf", "endpoint": "rogue.core.local", "health": "UP"}
        return self.result(
            status="VULNERABLE",
            request={"method": "POST", "path": self.endpoint, "json": payload},
            response={"status_code": 201, "body": str({"accepted": True})},
            evidence="Mock NRF registration accepts a forged AMF profile in the demo flow.",
            conclusion="Registration controls should require NF identity validation before accepting new services.",
        )
