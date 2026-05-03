from __future__ import annotations

from attacks.base_attack import BaseAttack


class RogueNFAttack(BaseAttack):
    attack_id = "ATTACK-001"
    name = "Rogue NF Registration"
    affected_nf = "NRF"
    endpoint = "/api/nrf/services"

    def run(self):
        data = {"nfType": "AMF", "nfInstanceId": "fake-amf-01", "registration_status": "accepted"}
        return self.result(
            success=True,
            data=data,
            evidence="Demo NRF flow accepts the rogue NF profile for scanner compatibility.",
            conclusion="Registration APIs should require trusted identity proof before issuing service visibility.",
        )
