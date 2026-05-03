from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class AttackResult:
    attack_id: str
    name: str
    affected_nf: str
    endpoint: str
    success: bool
    data: Any
    evidence: str
    conclusion: str


class BaseAttack:
    attack_id = ""
    name = ""
    affected_nf = ""
    endpoint = ""

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    def run(self) -> AttackResult:
        raise NotImplementedError

    def result(self, success: bool, data: Any, evidence: str, conclusion: str) -> AttackResult:
        return AttackResult(
            attack_id=self.attack_id,
            name=self.name,
            affected_nf=self.affected_nf,
            endpoint=self.endpoint,
            success=success,
            data=data,
            evidence=evidence,
            conclusion=conclusion,
        )
