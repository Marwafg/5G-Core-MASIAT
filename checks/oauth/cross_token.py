from __future__ import annotations

from checks.base_check import BaseCheck
from checks.compat import jwt_probe


class CrossTokenCheck(BaseCheck):
    check_id = "CHECK-003"
    name = "Cross-Service Token Abuse"
    affected_nf = "OAUTH"
    endpoint = "/api/analysis/oauth/verify"
    severity = "HIGH"

    def run(self):
        response, evidence = jwt_probe()
        status = "PATCHED" if response["status_code"] == 401 else "VULNERABLE"
        return self.result(
            status=status,
            request={"method": "POST", "path": self.endpoint},
            response=response,
            evidence=evidence,
            conclusion="Tampered tokens should be rejected across every NF-to-NF trust boundary.",
        )
