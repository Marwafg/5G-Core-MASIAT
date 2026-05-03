from __future__ import annotations

from attacks.base_attack import BaseAttack


class AUSFAuthVectorAttack(BaseAttack):
    attack_id = "ATTACK-003"
    name = "Auth Vector Harvest"
    affected_nf = "AUSF"
    endpoint = "/api/ausf/auth-vectors"

    def run(self):
        data = {"vectors": ["5g-aka-demo-vector"], "count": 1}
        return self.result(
            success=True,
            data=data,
            evidence="Compatibility mode returns a sample auth vector artifact for the demo.",
            conclusion="AUSF material should only be retrievable by authorized consumers with validated scopes.",
        )
