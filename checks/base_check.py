from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class CheckResult:
    check_id: str
    name: str
    status: str
    affected_nf: str
    endpoint: str
    request: dict
    response: dict
    severity: str
    evidence: str
    conclusion: str


class BaseCheck:
    check_id = ""
    name = ""
    affected_nf = ""
    endpoint = ""
    severity = "MEDIUM"

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    def run(self) -> CheckResult:
        raise NotImplementedError

    def result(
        self,
        status: str,
        request: dict,
        response: dict,
        evidence: str,
        conclusion: str,
    ) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=status,
            affected_nf=self.affected_nf,
            endpoint=self.endpoint,
            request=request,
            response=response,
            severity=self.severity,
            evidence=evidence,
            conclusion=conclusion,
        )
