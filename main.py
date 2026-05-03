from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from attacks.ausf.auth_vector import AUSFAuthVectorAttack
from attacks.nrf.rogue_nf import RogueNFAttack
from attacks.pcf.policy_abuse import PCFPolicyAbuseAttack
from attacks.udm.subscriber_dump import UDMSubscriberDumpAttack
from checks.amf.ue_context import AMFUEContextCheck
from checks.ausf.auth_vector import AUSFAuthVectorCheck
from checks.nrf.enum import NRFEnumCheck
from checks.nrf.rogue_registration import RogueNFRegistrationCheck
from checks.oauth.cross_token import CrossTokenCheck
from checks.pcf.policy_access import PCFPolicyAccessCheck
from checks.smf.session_enum import SMFSessionEnumCheck
from checks.udm.subscriber_enum import UDMSubscriberEnumCheck
from config import NRF_URL
from core.database import init_db as init_scanner_db
from report.reporter import save_attack_report, save_scan_report
from report.visualizer import generate as generate_map
from app.database import init_db as init_app_db

console = Console()

ALL_CHECKS = [
    NRFEnumCheck,
    RogueNFRegistrationCheck,
    CrossTokenCheck,
    UDMSubscriberEnumCheck,
    AMFUEContextCheck,
    AUSFAuthVectorCheck,
    SMFSessionEnumCheck,
    PCFPolicyAccessCheck,
]

ALL_ATTACKS = {
    "nrf": RogueNFAttack,
    "udm": UDMSubscriberDumpAttack,
    "ausf": AUSFAuthVectorAttack,
    "pcf": PCFPolicyAbuseAttack,
}


def print_banner() -> None:
    console.print("[bold cyan]5G Core SBI Security Scanner[/bold cyan]")
    console.print(f"[dim]Targeting: {NRF_URL}[/dim]\n")


def run_scan(check_id: str | None = None, nf: str | None = None) -> None:
    print_banner()
    checks_to_run = ALL_CHECKS
    if check_id:
        checks_to_run = [item for item in checks_to_run if item.check_id == check_id]
    if nf:
        checks_to_run = [item for item in checks_to_run if item.affected_nf.upper() == nf.upper()]

    results = [check({}).run() for check in checks_to_run]
    table = Table(show_header=True, header_style="bold white")
    table.add_column("Check")
    table.add_column("NF")
    table.add_column("Severity")
    table.add_column("Status")
    for item in results:
        table.add_row(item.check_id, item.affected_nf, item.severity, item.status)
    console.print(table)

    report_path = save_scan_report(results)
    map_path = generate_map()
    console.print(f"\n[dim]Report saved to {report_path}[/dim]")
    console.print(f"[dim]Network map saved to {map_path}[/dim]")


def run_attack(module: str) -> None:
    print_banner()
    attacks_to_run = list(ALL_ATTACKS.values()) if module == "all" else [ALL_ATTACKS[module]]
    results = [attack({}).run() for attack in attacks_to_run]

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Attack")
    table.add_column("NF")
    table.add_column("Result")
    for item in results:
        table.add_row(item.attack_id, item.affected_nf, "SUCCESS" if item.success else "FAILED")
    console.print(table)

    report_path = save_attack_report(results)
    console.print(f"\n[dim]Attack report saved to {report_path}[/dim]")
    console.print(json.dumps({"results": [asdict(item) for item in results]}, indent=2, default=str))


def main() -> None:
    init_app_db()
    init_scanner_db()
    parser = argparse.ArgumentParser(description="5G Scanner - compatibility CLI")
    parser.add_argument("--mode", choices=["scan", "attack"], default="scan")
    parser.add_argument("--check", default=None)
    parser.add_argument("--nf", default=None)
    parser.add_argument("--module", default="all", choices=["nrf", "udm", "ausf", "pcf", "all"])
    args = parser.parse_args()

    if args.mode == "scan":
        run_scan(check_id=args.check, nf=args.nf)
    else:
        run_attack(module=args.module)


if __name__ == "__main__":
    main()
