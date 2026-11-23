from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "c_cli"))

import c_fakes  # noqa: E402


@pytest.fixture()
def analyzed_run(tmp_path, monkeypatch) -> tuple[Path, str]:
    """A scanned + ANALYZED run (role doubles) and its CONFIRMED_ADVISORY finding id."""
    c_fakes.install(monkeypatch)
    out = tmp_path / "run"
    assert c_fakes.scan(out) == 0
    findings = json.loads((out / "findings.json").read_text())["findings"]
    fid = next(f["finding_id"] for f in findings if f["classification"] == "CONFIRMED_ADVISORY")
    return out, fid


HUMAN_OVERRIDE = {"strategy": "OVERRIDE", "relative_path": "package.json", "proposed_version": "2.0.1",
                  "change_description": "set overrides.fixture-transitive to 2.0.1",
                  "rationale": "lowest version said to fix SIM-ADV-0001 (SIMULATED)"}
