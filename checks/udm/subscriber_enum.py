from __future__ import annotations

from checks.base_check import BaseCheck
from checks.compat import vulnerable_subscriber_probe


class UDMSubscriberEnumCheck(BaseCheck):
    check_id = "CHECK-004"
    name = "Subscriber Enumeration"
    affected_nf = "UDM"
    endpoint = "/api/udm/vulnerable/subscribers"
    severity = "CRITICAL"

    def run(self):
        query = "' OR '1'='1' --"
        response, evidence = vulnerable_subscriber_probe(query)
        status = "VULNERABLE" if response["status_code"] == 200 else "PATCHED"
        return self.result(
            status=status,
            request={"method": "GET", "path": self.endpoint, "params": {"q": query}},
            response=response,
            evidence=evidence,
            conclusion="Subscriber lookups should not leak unrelated records through crafted SUPI input.",
        )
