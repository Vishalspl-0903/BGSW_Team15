"""Record a Syft SBOM + Grype report for a fixture directory as an offline test fixture.

The recording is how E's tests replay a *real* advisory match without network access
(PROJECT.md 21.1: "External API fixtures can be replayed offline but must have a snapshot
origin, checksum and as_of timestamp").  Host paths are removed before hashing.

Usage
    python -m eval.record_grype_fixture --fixture tests/fixtures/e_advisory/real-npm \
        --out tests/fixtures/e_advisory/recorded/real-npm --syft <syft> --grype <grype>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from guardian.adapters.vulns import redact_host_paths


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _dump(path: Path, data) -> None:
    path.write_bytes((json.dumps(data, indent=1, ensure_ascii=False) + "\n").encode("utf-8"))


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({"SYFT_CHECK_FOR_APP_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                "GRYPE_DB_AUTO_UPDATE": "false"})
    return env


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--syft", default=os.environ.get("GUARDIAN_SYFT", "syft"))
    parser.add_argument("--grype", default=os.environ.get("GUARDIAN_GRYPE", "grype"))
    args = parser.parse_args(argv)
    fixture, out = Path(args.fixture).resolve(), Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    env = _env()

    with tempfile.TemporaryDirectory() as tmp:
        sbom_tmp, grype_tmp = Path(tmp) / "sbom.cdx.json", Path(tmp) / "grype.json"
        subprocess.run([args.syft, "scan", f"dir:{fixture}", "-o", f"cyclonedx-json={sbom_tmp}", "-q"],
                       check=True, env=env, timeout=600)
        subprocess.run([args.grype, f"sbom:{sbom_tmp}", "-o", "json", "--file", str(grype_tmp), "-q"],
                       check=True, env=env, timeout=600)
        db = json.loads(subprocess.run([args.grype, "db", "status", "-o", "json"], check=True, env=env,
                                       capture_output=True, timeout=120).stdout or b"{}")
        syft_v = json.loads(subprocess.run([args.syft, "version", "-o", "json"], env=env, capture_output=True,
                                           timeout=60).stdout or b"{}").get("version")
        grype_v = json.loads(subprocess.run([args.grype, "version", "-o", "json"], env=env, capture_output=True,
                                            timeout=60).stdout or b"{}").get("version")
        replacements = [(str(fixture), "<fixture-dir>"), (tmp, "<record-dir>"),
                        (str(Path(db.get("path", "")).parent) if db.get("path") else "", "<grype-db-dir>"),
                        (str(Path(db.get("path", "")).parent.parent) if db.get("path") else "", "<grype-db-cache>"),
                        (str(Path.home()), "<home>")]
        _dump(out / "sbom.cdx.json", redact_host_paths(json.loads(sbom_tmp.read_text(encoding="utf-8")), replacements))
        _dump(out / "grype.json", redact_host_paths(json.loads(grype_tmp.read_text(encoding="utf-8")), replacements))
        _dump(out / "grype-db-status.json", redact_host_paths(db, replacements))

    manifest = {
        "kind": "recorded-scanner-fixture",
        "fixture_input": Path(args.fixture).as_posix(),
        "recorded_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "tools": {"syft": syft_v, "grype": grype_v},
        "advisory_database": {"schema": db.get("schemaVersion"), "built": db.get("built")},
        "commands": [
            "syft scan dir:<fixture-dir> -o cyclonedx-json=<record-dir>/sbom.cdx.json -q",
            "grype sbom:<record-dir>/sbom.cdx.json -o json --file <record-dir>/grype.json -q",
            "grype db status -o json",
        ],
        "environment": {"GRYPE_DB_AUTO_UPDATE": "false", "GRYPE_CHECK_FOR_APP_UPDATE": "false",
                        "SYFT_CHECK_FOR_APP_UPDATE": "false"},
        "sanitisation": "absolute host paths replaced by <fixture-dir>, <record-dir>, <grype-db-dir>, <home> or "
                        "<host-path>/<name> before hashing; sha256 values below are of the stored files",
        "files": {name: _sha(out / name) for name in ("sbom.cdx.json", "grype.json", "grype-db-status.json")},
    }
    _dump(out / "MANIFEST.json", manifest)
    print(json.dumps(manifest, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
