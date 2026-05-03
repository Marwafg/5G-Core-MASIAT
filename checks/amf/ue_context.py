from __future__ import annotations

from checks.base_check import BaseCheck


class AMFUEContextCheck(BaseCheck):
    check_id = "CHECK-005"
    name = "UE Context Unauthorized Access"
    affected_nf = "AMF"
    endpoint = "/api/amf/ue-context"
    severity = "MEDIUM"

    def run(self):
        return self.result(
            status="REQUIRES_UE",
            request={"method": "GET", "path": self.endpoint},
            response={"status_code": 428, "body": '{"detail":"UE context not active in mock lab"}'},
            evidence="AMF context verification needs an active UE session, which the local demo does not simulate.",
            conclusion="Check is documented for architecture parity with the teammate scanner.",
        )
