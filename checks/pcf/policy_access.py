from __future__ import annotations

from checks.base_check import BaseCheck


class PCFPolicyAccessCheck(BaseCheck):
    check_id = "CHECK-008"
    name = "Policy Context Unauthorized Access"
    affected_nf = "PCF"
    endpoint = "/api/pcf/policies"
    severity = "HIGH"

    def run(self):
        return self.result(
            status="VULNERABLE",
            request={"method": "POST", "path": self.endpoint},
            response={"status_code": 201, "body": '{"policy_created":true,"subscriber":"imsi-001010000000002"}'},
            evidence="Mock policy creation succeeds without proving subscriber ownership.",
            conclusion="Policy creation should bind decisions to authorized consumers and verified scopes.",
        )
