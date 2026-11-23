from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from guardian import schemas as s
from guardian.state import validate_run_dir

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "contract_m1"
EXAMPLES = ROOT / "docs" / "contracts" / "examples"


def _load(name: str):
    return json.loads((FIXTURE / name).read_text(encoding="utf-8"))


@pytest.fixture()
def run_copy(tmp_path: Path) -> Path:
    dst = tmp_path / "run"
    shutil.copytree(FIXTURE, dst)
    return dst


# ---------------------------------------------------------------- enums ----

def test_enums_match_section_9_1_verbatim() -> None:
    expected = {
        s.Coverage: "RESOLVED PARTIAL DECLARED_ONLY UNSUPPORTED FAILED NOT_RUN",
        s.RunStatus: "QUEUED RUNNING COMPLETE PARTIAL FAILED BLOCKED",
        s.StageStatus: "NOT_RUN RUNNING COMPLETE PARTIAL FAILED UNAVAILABLE BLOCKED",
        s.FindingClass: "CONFIRMED_ADVISORY SUSPICIOUS_INDICATOR CONFIGURATION_WEAKNESS COVERAGE_LIMITATION",
        s.Resolution: "RESOLVED DECLARED_ONLY UNKNOWN_VERSION CONFLICT",
        s.EvidenceBasis: "TOOL_OBSERVED CORROBORATED RULE_MATCH INFERRED UNKNOWN",
        s.FindingType: "VULNERABILITY SUSPICIOUS_CHANGE CI_POLICY CONTAINER_POLICY COVERAGE_GAP",
        s.Priority: "P0 P1 P2 P3 NEEDS_REVIEW UNASSESSED",
        s.ValidationStatus: "NOT_RUN PASS FAILED BLOCKED INCONCLUSIVE",
        s.ProposalStatus: "PROPOSED AUDITED NEEDS_REVIEW REJECTED APPROVED VALIDATING VERIFIED FAILED BLOCKED",
    }
    for enum, values in expected.items():
        assert [m.value for m in enum] == values.split(), enum.__name__


@pytest.mark.parametrize("bad", ["SAFE", "DONE_SUCCESS", "FULLY_VERIFIED"])
def test_invented_synonyms_rejected(bad: str) -> None:
    meta = _load("metadata.json")
    meta["status"] = bad
    with pytest.raises(ValidationError):
        s.ScanMetadata.model_validate(meta)


# ------------------------------------------------------------ roundtrip ----

@pytest.mark.parametrize("name", list(s.RUN_FILE_MODELS))
def test_fixture_roundtrip(name: str) -> None:
    path = FIXTURE / name
    if not path.exists():
        pytest.skip(f"{name} not part of contract_m1")
    raw = json.loads(path.read_text(encoding="utf-8"))
    model = s.RUN_FILE_MODELS[name].model_validate(raw)
    assert model.to_json_dict() == raw
    assert s.RUN_FILE_MODELS[name].model_validate_json(model.model_dump_json()) == model


def test_evidence_jsonl_roundtrip() -> None:
    for line in (FIXTURE / "evidence.jsonl").read_text(encoding="utf-8").splitlines():
        raw = json.loads(line)
        assert s.Evidence.model_validate(raw).to_json_dict() == raw


@pytest.mark.parametrize("path", sorted(EXAMPLES.glob("*.example.json")), ids=lambda p: p.name)
def test_examples_validate_and_roundtrip(path: Path) -> None:
    model = getattr(s, path.name.split(".")[0])
    raw = json.loads(path.read_text(encoding="utf-8"))
    assert model.model_validate(raw).to_json_dict() == raw


def test_fixture_is_regenerable_byte_exact() -> None:
    out = subprocess.run([sys.executable, str(ROOT / "tests/c_contracts/build_contract_fixture.py"), "--check"],
                         capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr


def test_exported_json_schemas_are_current(tmp_path: Path) -> None:
    s.export_json_schemas(tmp_path)
    committed = ROOT / "docs" / "contracts"
    for generated in tmp_path.glob("*.schema.json"):
        assert (committed / generated.name).read_text(encoding="utf-8") == generated.read_text(encoding="utf-8"), (
            f"{generated.name} drifted: run `python -m guardian.cli export-schemas`"
        )


# ------------------------------------------------- required / nullable -----

@pytest.mark.parametrize("field", list(s.ScanMetadata.model_fields))
def test_metadata_required_fields(field: str) -> None:
    meta = _load("metadata.json")
    if field in s.CONTRACT_ADDITIONS["ScanMetadata"]:
        pytest.skip("optional 1.0 addition")
    meta.pop(field)
    with pytest.raises(ValidationError):
        s.ScanMetadata.model_validate(meta)


def test_nullable_requires_explicit_null() -> None:
    meta = _load("metadata.json")
    del meta["commit_sha"]  # nullable, but must be sent as explicit null
    with pytest.raises(ValidationError, match="commit_sha"):
        s.ScanMetadata.model_validate(meta)


def test_finding_required_fields_all_enforced() -> None:
    base = json.loads((EXAMPLES / "FindingsFile.example.json").read_text())["findings"][0]
    for field in s.Finding.model_fields:
        if field in s.CONTRACT_ADDITIONS["Finding"]:
            continue
        broken = copy.deepcopy(base)
        broken.pop(field)
        with pytest.raises(ValidationError):
            s.Finding.model_validate(broken)


def test_unknown_field_rejected() -> None:
    meta = _load("metadata.json")
    meta["is_safe"] = True
    with pytest.raises(ValidationError, match="is_safe"):
        s.ScanMetadata.model_validate(meta)


def test_unsupported_schema_version_rejected() -> None:
    meta = _load("metadata.json")
    meta["schema_version"] = "2.0"
    with pytest.raises(ValidationError, match="unsupported schema_version"):
        s.ScanMetadata.model_validate(meta)


# --------------------------------------------------- honesty invariants ----

def test_factual_finding_without_evidence_rejected() -> None:
    f = json.loads((EXAMPLES / "FindingsFile.example.json").read_text())["findings"][0]
    f["evidence_ids"] = []
    with pytest.raises(ValidationError, match="requires evidence_ids"):
        s.Finding.model_validate(f)


def test_constraint_cannot_be_resolved_version() -> None:
    comp = _load("graph.json")["components"][1]
    comp["resolved_version"] = "^2.0.0"
    with pytest.raises(ValidationError, match="constraint"):
        s.Component.model_validate(comp)


def test_observed_edge_requires_evidence() -> None:
    edge = _load("graph.json")["edges"][0]
    edge["evidence_ids"] = []
    with pytest.raises(ValidationError, match="OBSERVED"):
        s.DependencyEdge.model_validate(edge)


def test_unavailable_stage_never_zero() -> None:
    rec = json.loads((EXAMPLES / "StageRecord.unavailable.example.json").read_text())
    rec["known_matches"] = 0
    with pytest.raises(ValidationError, match="known_matches"):
        s.StageRecord.model_validate(rec)


def test_validation_pass_requires_gate_evidence() -> None:
    v = json.loads((EXAMPLES / "ValidationResult.blocked.example.json").read_text())
    v["status"] = "PASS"
    with pytest.raises(ValidationError, match="PASS requires gate evidence"):
        s.ValidationResult.model_validate(v)


def test_llm_cannot_record_approval_or_advance() -> None:
    ev = json.loads((EXAMPLES / "Event.approval.example.json").read_text())
    ev["actor_type"] = "LLM"
    with pytest.raises(ValidationError):
        s.Event.model_validate(ev)
    ev["approval"] = None
    with pytest.raises(ValidationError, match="LLM actor cannot advance"):
        s.Event.model_validate(ev)


def test_host_paths_rejected() -> None:
    ev = json.loads((FIXTURE / "evidence.jsonl").read_text().splitlines()[0])
    for bad in ("C:\\Users\\me\\package.json", "/home/me/x", "../outside", "C:/x"):
        ev["source_path"] = bad
        with pytest.raises(ValidationError):
            s.Evidence.model_validate(ev)


def test_timestamps_must_be_utc() -> None:
    ev = json.loads((FIXTURE / "evidence.jsonl").read_text().splitlines()[0])
    ev["recorded_at"] = "2026-11-23T10:00:00+05:30"
    with pytest.raises(ValidationError, match="UTC"):
        s.Evidence.model_validate(ev)
    ev["recorded_at"] = "2026-11-23T10:00:00+00:00"
    assert s.Evidence.model_validate(ev).recorded_at == "2026-11-23T10:00:00Z"


def test_proposal_digest_ignores_status_but_binds_content() -> None:
    raw = json.loads((EXAMPLES / "ProposalsFile.example.json").read_text())["proposals"][0]
    p = s.Proposal.model_validate(raw)
    d1 = s.proposal_digest(p)
    p2 = p.model_copy(update={"status": s.ProposalStatus.NEEDS_REVIEW})
    assert s.proposal_digest(p2) == d1
    p3 = p.model_copy(update={"proposed_version": "9.9.9"})
    assert s.proposal_digest(p3) != d1


def test_stable_id_repeatable_across_processes() -> None:
    code = "from guardian.schemas import stable_id; print(stable_id('mod','scan','.','npm'))"
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=ROOT,
                           check=True).stdout.strip() for _ in range(2)}
    assert outs == {s.stable_id("mod", "scan", ".", "npm")}


# ---------------------------------------------------------- validate-run ---

def test_contract_fixture_validates() -> None:
    result = validate_run_dir(FIXTURE)
    assert result.ok, result.errors


def test_missing_evidence_reference_fails(run_copy: Path) -> None:
    g = json.loads((run_copy / "graph.json").read_text())
    g["edges"][1]["evidence_ids"] = ["ev:does-not-exist"]
    (run_copy / "graph.json").write_text(json.dumps(g))
    result = validate_run_dir(run_copy)
    assert any("unknown evidence ev:does-not-exist" in e for e in result.errors)


def test_conflicting_scan_ids_fail(run_copy: Path) -> None:
    f = json.loads((run_copy / "findings.json").read_text())
    f["scan_id"] = "some-other-scan"
    (run_copy / "findings.json").write_text(json.dumps(f))
    result = validate_run_dir(run_copy)
    assert any("conflicts with metadata scan_id" in e for e in result.errors)


def test_dangling_edge_endpoint_fails(run_copy: Path) -> None:
    g = json.loads((run_copy / "graph.json").read_text())
    g["edges"][1]["target_id"] = "occ:ghost"
    (run_copy / "graph.json").write_text(json.dumps(g))
    assert any("occ:ghost" in e for e in validate_run_dir(run_copy).errors)


def test_tampered_raw_artifact_fails(run_copy: Path) -> None:
    with (run_copy / "repo" / "package-lock.json").open("ab") as fh:
        fh.write(b" ")
    assert any("raw_sha256 does not match" in e for e in validate_run_dir(run_copy).errors)


def test_complete_stage_without_artifact_fails(run_copy: Path) -> None:
    (run_copy / "graph.json").unlink()
    assert any("stage graph COMPLETE but graph.json is missing" in e for e in validate_run_dir(run_copy).errors)


def test_model_output_cannot_back_observed_edge(run_copy: Path) -> None:
    lines = (run_copy / "evidence.jsonl").read_text().splitlines()
    ev = json.loads(lines[1])
    ev["kind"] = "MODEL_OUTPUT"
    lines[1] = json.dumps(ev)
    (run_copy / "evidence.jsonl").write_text("\n".join(lines) + "\n")
    assert any("MODEL_OUTPUT" in e for e in validate_run_dir(run_copy).errors)


def test_coverage_summary_must_match_modules(run_copy: Path) -> None:
    g = json.loads((run_copy / "graph.json").read_text())
    g["coverage_summary"]["resolved_modules"] = 0
    (run_copy / "graph.json").write_text(json.dumps(g))
    assert any("coverage_summary" in e for e in validate_run_dir(run_copy).errors)
