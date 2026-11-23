"""Guardian CLI (project.md §9.5).  Owner: Role C.

Contract release subset: ``doctor``, ``validate-run``, ``export-schemas``.
Works with no network, no API key and ``LLM_MODE=disabled``.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_INVALID = 1  # validate-run integrity failure / doctor critical prerequisite missing
EXIT_USAGE = 2  # argparse
EXIT_PARTIAL = 10
EXIT_FAILED = 11
EXIT_BLOCKED = 12
EXIT_UNAVAILABLE = 13

REPO_ROOT = Path(__file__).resolve().parents[1]
OPTIONAL_TOOLS = {
    "git": ["git", "--version"],
    "syft": ["syft", "version"],
    "grype": ["grype", "version"],
    "trivy": ["trivy", "--version"],
    "osv-scanner": ["osv-scanner", "--version"],
    "docker": ["docker", "--version"],
}
ROLE_MODULES = {
    "A intake": "guardian.intake",
    "A module index": "guardian.module_index",
    "B graph_build": "guardian.analysis.graph_build",
    "B paths": "guardian.analysis.paths",
    "E vulns": "guardian.adapters.vulns",
    "E detectors": "guardian.detectors",
    "D reporter": "guardian.reporter",
}


def _tool_version(argv: list[str]) -> str | None:
    exe = shutil.which(argv[0])
    if exe is None:
        return None
    try:
        out = subprocess.run([exe, *argv[1:]], capture_output=True, text=True, timeout=15,
                             shell=False, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (out.stdout or out.stderr).strip().splitlines()
    return text[0][:200] if out.returncode == 0 and text else None


def cmd_doctor(_: argparse.Namespace) -> int:
    critical: list[str] = []
    lines = [f"python: {platform.python_version()}"]
    if sys.version_info < (3, 11):
        critical.append("Python >= 3.11 required")
    try:
        import pydantic

        lines.append(f"pydantic: {pydantic.VERSION}")
        if not pydantic.VERSION.startswith("2."):
            critical.append("pydantic v2 required")
    except ImportError:
        critical.append("pydantic not installed")
    try:
        import yaml

        policy = yaml.safe_load((REPO_ROOT / "config" / "policy.yaml").read_text(encoding="utf-8"))
        lines.append(f"policy: config/policy.yaml version {policy.get('policy_version')}")
    except Exception as exc:  # noqa: BLE001 - report any policy failure
        critical.append(f"policy unreadable: {type(exc).__name__}")
    try:
        from guardian import schemas

        lines.append(f"schemas: guardian.schemas {schemas.SCHEMA_VERSION}")
    except Exception as exc:  # noqa: BLE001
        critical.append(f"guardian.schemas import failed: {exc}")
    for name, argv in OPTIONAL_TOOLS.items():
        version = _tool_version(argv)
        lines.append(f"tool {name}: {version or 'UNAVAILABLE'}")
    for label, module in ROLE_MODULES.items():
        try:
            importlib.import_module(module)
            state = "importable"
        except Exception as exc:  # noqa: BLE001
            state = f"UNAVAILABLE ({type(exc).__name__})"
        lines.append(f"module {label}: {state}")
    lines.append(f"LLM_MODE: {os.environ.get('LLM_MODE', 'disabled')}")
    for line in lines:
        print(line)
    for problem in critical:
        print(f"CRITICAL: {problem}")
    print("doctor:", "OK" if not critical else "MISSING CRITICAL PREREQUISITES")
    return EXIT_OK if not critical else EXIT_INVALID


def cmd_validate_run(args: argparse.Namespace) -> int:
    from guardian.state import validate_run_dir

    result = validate_run_dir(args.run_dir)
    if args.json:
        print(json.dumps({"run_dir": Path(args.run_dir).as_posix(), "ok": result.ok,
                          "checked": result.checked, "errors": result.errors,
                          "warnings": result.warnings}, indent=2))
    else:
        print(f"run: {Path(args.run_dir).as_posix()}")
        print(f"checked: {', '.join(result.checked) or '(none)'}")
        for w in result.warnings:
            print(f"WARNING: {w}")
        for e in result.errors:
            print(f"ERROR: {e}")
        print("validate-run:", "PASS" if result.ok else f"FAIL ({len(result.errors)} errors)")
    return EXIT_OK if result.ok else EXIT_INVALID


def cmd_export_schemas(args: argparse.Namespace) -> int:
    from guardian.schemas import export_json_schemas

    for path in export_json_schemas(args.out):
        print(path.as_posix())
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m guardian.cli", description="Bosch Guardian")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check prerequisites").set_defaults(func=cmd_doctor)
    p = sub.add_parser("validate-run", help="schema + referential integrity of a run folder")
    p.add_argument("run_dir")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_validate_run)
    p = sub.add_parser("export-schemas", help="write JSON Schema files")
    p.add_argument("--out", default="docs/contracts")
    p.set_defaults(func=cmd_export_schemas)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
