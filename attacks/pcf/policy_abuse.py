from __future__ import annotations

from attacks.base_attack import BaseAttack


class PCFPolicyAbuseAttack(BaseAttack):
    attack_id = "ATTACK-004"
    name = "Policy Abuse"
    affected_nf = "PCF"
    endpoint = "/api/pcf/policies"

    def run(self):
        data = {"subscriber": "imsi-001010000000002", "policy_created": True}
        return self.result(
            success=True,
            data=data,
            evidence="Policy context was created in the mock flow without ownership proof.",
            conclusion="PCF should enforce caller-to-subscriber authorization checks before provisioning policy state.",
        )
