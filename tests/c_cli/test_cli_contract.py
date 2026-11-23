from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _cli(*args: str, env: dict | None = None) -> subprocess.CompletedProcess[str]:
    full_env = {**os.environ, "LLM_MODE": "disabled", **(env or {})}
    return subprocess.run([sys.executable, "-m", "guardian.cli", *args], cwd=ROOT, capture_output=True,
                          text=True, env=full_env, check=False, timeout=120)


def test_validate_run_fixture_passes_offline() -> None:
    out = _cli("validate-run", "tests/fixtures/contract_m1")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "validate-run: PASS" in out.stdout


def test_validate_run_missing_dir_fails(tmp_path: Path) -> None:
    out = _cli("validate-run", str(tmp_path / "nope"))
    assert out.returncode == 1


def test_doctor_runs_without_llm_or_network() -> None:
    out = _cli("doctor", env={"GROQ_API_KEY": "", "MODEL_API_KEY": ""})
    assert out.returncode == 0, out.stdout + out.stderr
    assert "LLM_MODE: disabled" in out.stdout
    assert "schemas: guardian.schemas 1.0" in out.stdout
