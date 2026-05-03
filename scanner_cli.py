from __future__ import annotations

import argparse
import json

from core.database import get_findings_for_run, get_recent_runs
from core.scanner_engine import execute_run, list_modules, list_profiles


def main() -> None:
    parser = argparse.ArgumentParser(prog="scan", description="5G Core API scanner CLI")
    subparsers = parser.add_subparsers(dest="entity", required=True)

    profiles_parser = subparsers.add_parser("profiles")
    profiles_parser.add_argument("action", choices=["list"])

    modules_parser = subparsers.add_parser("modules")
    modules_parser.add_argument("action", choices=["list"])

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--profile", default="mock-local-lab")
    run_parser.add_argument("--mode", choices=["dry-run", "active"], default="dry-run")
    run_parser.add_argument("--modules", nargs="*", default=None)

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("action", choices=["export", "list"])
    report_parser.add_argument("--run-id")

    args = parser.parse_args()

    if args.entity == "profiles":
        print(json.dumps({"profiles": list_profiles()}, indent=2))
    elif args.entity == "modules":
        print(json.dumps({"modules": list_modules()}, indent=2))
    elif args.entity == "run":
        print(json.dumps(execute_run(args.profile, args.mode, args.modules), indent=2))
    elif args.entity == "report" and args.action == "list":
        print(json.dumps({"runs": get_recent_runs()}, indent=2))
    elif args.entity == "report" and args.action == "export":
        if not args.run_id:
            raise SystemExit("--run-id is required for report export")
        print(json.dumps({"run_id": args.run_id, "findings": get_findings_for_run(args.run_id)}, indent=2))


if __name__ == "__main__":
    main()
