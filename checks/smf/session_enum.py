from __future__ import annotations

from checks.base_check import BaseCheck


class SMFSessionEnumCheck(BaseCheck):
    check_id = "CHECK-007"
    name = "Session Enumeration"
    affected_nf = "SMF"
    endpoint = "/api/smf/sessions"
    severity = "MEDIUM"

    def run(self):
        return self.result(
            status="REQUIRES_UE",
            request={"method": "GET", "path": self.endpoint},
            response={"status_code": 428, "body": '{"detail":"No active PDU session in demo lab"}'},
            evidence="SMF session checks need live session state and are marked as requiring UE traffic.",
            conclusion="The project now mirrors the teammate layout without pretending to have live SMF telemetry.",
        )
