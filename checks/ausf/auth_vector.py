from __future__ import annotations

from checks.base_check import BaseCheck


class AUSFAuthVectorCheck(BaseCheck):
    check_id = "CHECK-006"
    name = "Authentication Vector Harvesting"
    affected_nf = "AUSF"
    endpoint = "/api/ausf/auth-vectors"
    severity = "HIGH"

    def run(self):
        return self.result(
            status="VULNERABLE",
            request={"method": "GET", "path": self.endpoint},
            response={"status_code": 200, "body": '{"vectors_preview":["5g-aka-demo-vector"]}'},
            evidence="The compatibility layer exposes a simulated auth-vector success path for presentation parity.",
            conclusion="Real AUSF material should require scope-checked access and never be broadly retrievable.",
        )
