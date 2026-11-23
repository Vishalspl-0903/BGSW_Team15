"""Guardian CLI (project.md §9.5).  Owner: Role C.

Scan workflow (deterministic, no LLM/LangGraph required):
  CREATED -> ACQUIRING -> INDEXING -> INVENTORY_READY -> DETECTING -> FINDINGS_READY
          -> ANALYZING -> ANALYZED
Other roles are called only through their §9.4 public signatures.  A role that
is not merged yet yields an explicit UNAVAILABLE stage — never a fabricated
artifact.  Exit codes (§21.4):

  0  OK / COMPLETE            1  validate-run integrity failure, doctor critical failure
  2  usage error              10 PARTIAL      11 FAILED      12 BLOCKED     13 UNAVAILABLE
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import inspect
import json
import platform
import shutil
import subprocess
import sys
import traceback
import uuid
from pathlib import Path
from typing import Any, Callable

EXIT_OK = 0
EXIT_INVALID = 1
EXIT_USAGE = 2
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
    "A validator": "guardian.validator",
    "B graph_build": "guardian.analysis.graph_build",
    "B paths": "guardian.analysis.paths",
    "B fix audit": "guardian.fixaudit.static_audit",
    "E vulns": "guardian.adapters.vulns",
    "E detectors": "guardian.detectors",
    "D reporter": "guardian.reporter",
}
_SKIP_COPY = {".git", "node_modules", "__pycache__", ".venv", "venv"}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


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


def _optional(module: str, attr: str) -> Callable[..., Any] | None:
    """Import another role's public function, or None if that role is not merged."""
    try:
        mod = importlib.import_module(module)
    except ImportError:
        return None
    fn = getattr(mod, attr, None)
    return fn if callable(fn) else None


def _err(exc: BaseException) -> str:
    from guardian.redact import redact_bounded

    return redact_bounded(f"{type(exc).__name__}: {exc}", 500)


# ---------------------------------------------------------------------------
# doctor / validate-run / export-schemas
# ---------------------------------------------------------------------------


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
        from guardian.guard import load_policy

        policy = load_policy()
        lines.append(f"policy: config/policy.yaml version {policy['policy_version']} (enforced keys OK)")
    except Exception as exc:  # noqa: BLE001 - report any policy failure
        critical.append(f"policy rejected: {_err(exc)}")
    try:
        from guardian import schemas

        lines.append(f"schemas: guardian.schemas {schemas.SCHEMA_VERSION}")
    except Exception as exc:  # noqa: BLE001
        critical.append(f"guardian.schemas import failed: {_err(exc)}")
    for name, argv in OPTIONAL_TOOLS.items():
        lines.append(f"tool {name}: {_tool_version(argv) or 'UNAVAILABLE'}")
    for label, module in ROLE_MODULES.items():
        try:
            importlib.import_module(module)
            state = "importable"
        except Exception as exc:  # noqa: BLE001
            state = f"UNAVAILABLE ({type(exc).__name__})"
        lines.append(f"module {label}: {state}")
    from guardian import llm

    cfg = llm.load_config()
    if not cfg.enabled:
        lines.append("LLM_MODE: disabled (deterministic Analyst templates; Critic not run)")
    else:
        lines.append(f"LLM_MODE: {cfg.mode} model={cfg.model or 'UNSET'} base_url={'set' if cfg.base_url else 'UNSET'} "
                     f"key={'set' if cfg.api_key else 'UNSET'} (optional; not verified without a probe)")
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
        print(json.dumps({"run_dir": Path(args.run_dir).as_posix(), "ok": result.ok, "checked": result.checked,
                          "errors": result.errors, "warnings": result.warnings}, indent=2))
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


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


class ScanRun:
    """Accumulates stage records and persists metadata/events for one scan."""

    def __init__(self, run_dir: Path, scan_id: str, repo_url: str, source_kind: str,
                 commit_sha: str | None = None, started_at: str | None = None):
        from guardian.schemas import utc_now
        from guardian.state import EventLog, scan_workflow_id

        self.run_dir = run_dir
        self.scan_id = scan_id
        self.repo_url = repo_url
        self.source_kind = source_kind
        self.commit_sha = commit_sha
        self.started_at = started_at or utc_now()
        self.snapshot_sha: str | None = None
        self.errors: list[str] = []
        self.records: dict[str, dict] = {}
        self.tool_versions: dict[str, str] = {"python": platform.python_version()}
        self.capabilities: dict[str, str] = {"artifact": "NOT_RUN: no container image analyzed"}
        self.log = EventLog(run_dir, scan_id)
        self.wf = scan_workflow_id(scan_id)
        for stage in ("intake", "inventory", "graph", "advisory", "detectors", "analysis"):
            self.stage(stage, "NOT_RUN", attempted=False)

    def stage(self, name: str, status: str, *, attempted: bool = True, tool: str | None = None,
              tool_version: str | None = None, reason: str | None = None, known_matches: int | None = None,
              evidence_ids: list[str] | None = None) -> None:
        from guardian.schemas import StageRecord, utc_now

        record = StageRecord(stage=name, status=status, attempted=attempted, tool=tool, tool_version=tool_version,
                             reason=reason, completed_at=utc_now() if status in ("COMPLETE", "PARTIAL") else None,
                             known_matches=known_matches, evidence_ids=evidence_ids or [])
        self.records[name] = record.to_json_dict()

    def fail_log(self, stage: str, message: str) -> list[str]:
        """Persist a redacted stage failure log as TOOL_LOG evidence."""
        from guardian.redact import redact_bounded
        from guardian.schemas import SCHEMA_VERSION, Evidence, stable_id, utc_now
        from guardian.state import append_jsonl

        rel = f"raw/stage-{stage}.log"
        data = (redact_bounded(message, 4000) + "\n").encode("utf-8")
        path = self.run_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        stamp = utc_now()
        eid = stable_id("ev", self.scan_id, "stage-log", stage, stamp)
        ev = Evidence(schema_version=SCHEMA_VERSION, scan_id=self.scan_id, evidence_id=eid, kind="TOOL_LOG",
                      tool_name="guardian-cli", tool_version=SCHEMA_VERSION, source_path=None, json_pointer=None,
                      line_start=None, line_end=None, observed_value=None, raw_artifact=rel,
                      raw_sha256=hashlib.sha256(data).hexdigest(),
                      observation=f"stage {stage} did not complete; see redacted log", recorded_at=stamp)
        append_jsonl(self.run_dir / "evidence.jsonl", ev.to_json_dict())
        return [eid]

    def go(self, state: str, message: str, **kw) -> None:
        from guardian.schemas import WorkflowState

        self.log.transition(self.wf, WorkflowState(state), message=message, **kw)

    def overall(self) -> str:
        st = {k: v["status"] for k, v in self.records.items()}
        if st["intake"] == "BLOCKED":
            return "BLOCKED"
        if st["intake"] == "FAILED" or st["inventory"] in ("FAILED", "NOT_RUN"):
            return "FAILED"
        required = ("intake", "inventory", "graph", "advisory", "detectors", "analysis")
        return "COMPLETE" if all(st[s] == "COMPLETE" for s in required) else "PARTIAL"

    def write_metadata(self, status: str, finished: bool) -> None:
        from guardian.schemas import SCHEMA_VERSION, ScanMetadata, utc_now
        from guardian.state import write_json_atomic

        meta = ScanMetadata(
            schema_version=SCHEMA_VERSION, scan_id=self.scan_id, repo_url=self.repo_url,
            commit_sha=self.commit_sha, source_kind=self.source_kind, started_at=self.started_at,
            finished_at=utc_now() if finished else None, status=status, tool_versions=self.tool_versions,
            errors=self.errors, stage_statuses={k: v["status"] for k, v in self.records.items()},
            database_snapshots={}, source_snapshot_sha256=self.snapshot_sha,
            scope_capabilities=self.capabilities, stage_records=self.records,
        )
        write_json_atomic(self.run_dir / "metadata.json", meta.to_json_dict())


def _copy_local_snapshot(src: Path, dst: Path, policy: dict) -> str:
    """Static copy of an allowlisted fixture into the run folder; returns snapshot sha256."""
    limits = policy.get("local_intake", {})
    max_files = int(limits.get("max_files", 5000))
    max_bytes = int(limits.get("max_bytes", 50_000_000))
    digest = hashlib.sha256()
    files = bytes_seen = 0
    for path in sorted(src.rglob("*"), key=lambda p: p.relative_to(src).as_posix()):
        rel = path.relative_to(src)
        if any(part in _SKIP_COPY for part in rel.parts):
            continue
        if path.is_symlink():
            raise PermissionError(f"symlink not allowed in local fixture: {rel.as_posix()}")
        target = dst / rel
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        files += 1
        bytes_seen += path.stat().st_size
        if files > max_files or bytes_seen > max_bytes:
            raise PermissionError("local fixture exceeds policy local_intake limits")
        target.parent.mkdir(parents=True, exist_ok=True)
        data = path.read_bytes()
        target.write_bytes(data)
        name = rel.as_posix().encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(data)
    return digest.hexdigest()


def _restore_evidence(path: Path, earlier: list[str]) -> None:
    """Re-append evidence lines that a producer's rewrite of evidence.jsonl dropped."""
    if not earlier:
        return
    current = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    ids = {json.loads(line).get("evidence_id") for line in current if line.strip()}
    missing = [line for line in earlier if line.strip() and json.loads(line).get("evidence_id") not in ids]
    if missing:
        with path.open("a", encoding="utf-8", newline="
") as fh:
            fh.write("".join(line + "
" for line in missing))


def _prepare_out(out: Path) -> str | None:
    if out.exists() and any(out.iterdir()):
        return f"output folder {out.as_posix()} is not empty; refusing to overwrite a previous run"
    return None


def run_scan_pipeline(run: ScanRun, repo_dir: Path, *, baseline_ref: str | None = None,
                      llm_config=None, llm_transport=None) -> str:
    """INDEXING..ANALYZED.  Returns final RunStatus string.  Never fabricates artifacts."""
    from guardian.schemas import (
        SCHEMA_VERSION, Evidence, Finding, FindingClass, FindingsFile, GraphBundle, ModuleIndex, RiskFile,
        StageRecord,
    )
    from guardian.state import append_jsonl, load_evidence_index, write_json_atomic

    out = run.run_dir
    # ---- INDEXING (A) ----
    run.go("INDEXING", "indexing project modules (A.index_modules)")
    index_modules = _optional("guardian.module_index", "index_modules")
    modules = []
    if index_modules is None:
        run.stage("inventory", "UNAVAILABLE", reason="A's guardian.module_index not importable",
                  evidence_ids=run.fail_log("inventory", "module index unavailable"))
        run.errors.append("inventory: module index unavailable")
        run.go("FAILED", "inventory unavailable")
        return run.overall()
    try:
        modules = list(index_modules(run.scan_id, str(repo_dir)))
        index = ModuleIndex(schema_version=SCHEMA_VERSION, scan_id=run.scan_id, modules=modules)
        write_json_atomic(out / "module_index.json", index.to_json_dict())
        run.stage("inventory", "COMPLETE", tool="guardian.module_index")
    except Exception as exc:  # noqa: BLE001
        msg = _err(exc)
        run.stage("inventory", "FAILED", tool="guardian.module_index", reason=msg,
                  evidence_ids=run.fail_log("inventory", msg))
        run.errors.append(f"inventory: {msg}")
        run.go("FAILED", f"module indexing failed: {msg}")
        return run.overall()
    run.capabilities["ci"] = (f"{sum(len(m.ci_files) for m in modules)} workflow file(s) discovered; "
                              "analysis depends on E's detectors")

    # ---- graph (B) ----
    graph: GraphBundle | None = None
    build_graph = _optional("guardian.analysis.graph_build", "build_graph")
    if build_graph is None:
        reason = "B's guardian.analysis.graph_build not merged; no graph produced (not fabricated)"
        run.stage("graph", "UNAVAILABLE", tool="guardian.analysis.graph_build",
                  reason=reason, evidence_ids=run.fail_log("graph", reason))
        run.capabilities["source"] = "module index only; dependency graph UNAVAILABLE"
    else:
        try:
            kwargs = {"run_dir": str(out)} if "run_dir" in inspect.signature(build_graph).parameters else {}
            ev_path = out / "evidence.jsonl"
            earlier = ev_path.read_text(encoding="utf-8").splitlines() if ev_path.exists() else []
            raw_graph = build_graph(run.scan_id, str(repo_dir), modules, **kwargs)
            _restore_evidence(ev_path, earlier)  # B rewrites evidence.jsonl; keep earlier lines
            graph = GraphBundle.model_validate(raw_graph)
            if graph.scan_id != run.scan_id:
                raise ValueError(f"graph scan_id {graph.scan_id!r} conflicts with {run.scan_id!r}")
            problems = graph.integrity_errors()
            if problems:
                raise ValueError("; ".join(problems[:5]))
            write_json_atomic(out / "graph.json", graph.to_json_dict())
            write_json_atomic(out / "module_index.json", ModuleIndex(
                schema_version=SCHEMA_VERSION, scan_id=run.scan_id, modules=graph.modules).to_json_dict())
            partial = [m.relative_path for m in graph.modules if m.coverage.value != "RESOLVED"]
            if partial:
                run.stage("graph", "PARTIAL", tool="guardian.analysis.graph_build",
                          reason=f"modules not fully resolved: {partial[:10]}")
            else:
                run.stage("graph", "COMPLETE", tool="guardian.analysis.graph_build")
            run.capabilities["source"] = (f"{len(graph.components)} occurrences, {len(graph.edges)} edges "
                                          f"from B's graph builder; coverage {graph.coverage_summary.model_dump()}")
            write_db = _optional("guardian.analysis.graph_build", "write_graph_db")
            if write_db is not None:
                try:
                    write_db(graph, str(out / "graph.sqlite"))
                except Exception as exc:  # noqa: BLE001
                    run.errors.append(f"graph.sqlite: {_err(exc)}")
        except Exception as exc:  # noqa: BLE001
            msg = _err(exc)
            graph = None
            run.stage("graph", "FAILED", tool="guardian.analysis.graph_build", reason=msg,
                      evidence_ids=run.fail_log("graph", msg))
            run.errors.append(f"graph: {msg}")
    run.go("INVENTORY_READY", f"inventory ready; graph stage {run.records['graph']['status']}")

    # ---- DETECTING (E) ----
    run.go("DETECTING", "running known-advisory and non-CVE detectors (E)")
    findings: dict[str, Finding] = {}

    def collect(stage: str, fn: Callable[[], list], tool: str) -> None:
        try:
            produced = [Finding.model_validate(f) for f in fn()]
        except Exception as exc:  # noqa: BLE001
            msg = _err(exc)
            status = "UNAVAILABLE" if "unavailable" in type(exc).__name__.lower() else "FAILED"
            run.stage(stage, status, tool=tool, reason=msg, evidence_ids=run.fail_log(stage, msg))
            run.errors.append(f"{stage}: {msg}")
            return
        kept = 0
        for f in produced:
            if f.scan_id != run.scan_id:
                run.errors.append(f"{stage}: dropped finding {f.finding_id} with conflicting scan_id {f.scan_id!r}")
                continue
            if f.finding_id in findings:
                run.errors.append(f"{stage}: duplicate finding_id {f.finding_id} ignored")
                continue
            findings[f.finding_id] = f
            kept += 1
        matches = sum(1 for f in produced if f.classification == FindingClass.CONFIRMED_ADVISORY)
        status = "COMPLETE" if kept == len(produced) else "PARTIAL"
        run.stage(stage, status, tool=tool, known_matches=matches if stage == "advisory" else kept,
                  reason=None if status == "COMPLETE" else "some findings rejected; see errors")

    def collect_rich(stage: str, fn: Callable[[], dict], tool: str, main_name: str) -> None:
        """E's stage-reporting entry points: E's StageRecord decides the status, so a
        missing scanner can never be recorded as a completed zero-match lookup."""
        try:
            result = fn()
            raw_records = [result["stage"]] if "stage" in result else list(result.get("stages", []))
            records = [StageRecord.model_validate(r) for r in raw_records]
            known = load_evidence_index(out)
            for item in result.get("evidence", []):
                ev = Evidence.model_validate(item)
                if ev.evidence_id not in known:
                    append_jsonl(out / "evidence.jsonl", ev.to_json_dict())
                    known[ev.evidence_id] = ev
        except Exception as exc:  # noqa: BLE001
            msg = _err(exc)
            run.stage(stage, "FAILED", tool=tool, reason=msg, evidence_ids=run.fail_log(stage, msg))
            run.errors.append(f"{stage}: {msg}")
            return
        for rec in records:  # keep E's own records under their own names
            run.records[rec.stage] = rec.to_json_dict()
        main = next((r for r in records if r.stage == main_name), None)
        if main is None:
            run.stage(stage, "FAILED", tool=tool, reason=f"adapter returned no {main_name} stage record")
            return
        if result.get("findings"):
            collect(stage, lambda: result["findings"], tool)
        rejected = run.records.get(stage, {}).get("status") == "PARTIAL"
        mirrored = {**main.to_json_dict(), "stage": stage}
        if rejected and main.status.value == "COMPLETE":
            mirrored.update(status="PARTIAL", reason="some findings rejected; see errors")
        run.records[stage] = mirrored

    rich_vulns = _optional("guardian.adapters.vulns", "run_vulnerability_intelligence")
    vulns = _optional("guardian.adapters.vulns", "scan_known_vulnerabilities")
    if vulns is None and rich_vulns is None:
        run.stage("advisory", "UNAVAILABLE", tool="guardian.adapters.vulns",
                  reason="E's advisory adapter not merged: vulnerability status UNKNOWN (not zero)")
    elif graph is None:
        run.stage("advisory", "BLOCKED", tool="guardian.adapters.vulns",
                  reason="no dependency graph: exact-version advisory matching cannot run")
    elif rich_vulns is not None:
        collect_rich("advisory", lambda: rich_vulns(run.scan_id, graph, str(out)), "guardian.adapters.vulns",
                     "vulnerability_intelligence")
    else:
        collect("advisory", lambda: vulns(run.scan_id, graph, str(out)), "guardian.adapters.vulns")
    rich_detect = _optional("guardian.detectors", "run_detectors")
    detect = _optional("guardian.detectors", "detect_suspicious_changes")
    if detect is None and rich_detect is None:
        run.stage("detectors", "UNAVAILABLE", tool="guardian.detectors",
                  reason="E's non-CVE detectors not merged: indicators UNKNOWN (not none)")
    elif rich_detect is not None:
        collect_rich("detectors", lambda: rich_detect(run.scan_id, str(repo_dir), baseline_ref, str(out)),
                     "guardian.detectors", "ci_workflow_policy")
    else:
        collect("detectors", lambda: detect(run.scan_id, str(repo_dir), baseline_ref, str(out)),
                "guardian.detectors")
    ff = FindingsFile(schema_version=SCHEMA_VERSION, scan_id=run.scan_id, findings=list(findings.values()))
    write_json_atomic(out / "findings.json", ff.to_json_dict())
    run.go("FINDINGS_READY", f"{len(findings)} finding(s); advisory {run.records['advisory']['status']}, "
                             f"detectors {run.records['detectors']['status']}",
           related_ids=list(findings)[:50])

    # ---- ANALYZING (C) ----
    run.go("ANALYZING", "deterministic scoring + bounded Analyst")
    try:
        from guardian import llm
        from guardian.agents.analyst import analyze_finding
        from guardian.analysis.scoring import score_findings
        from guardian.guard import load_policy

        policy = load_policy()
        evidence = load_evidence_index(out)
        assessments = score_findings(list(findings.values()), graph, evidence)
        cfg = llm_config or llm.load_config(policy=policy)
        max_llm = int(policy["agent"].get("max_findings_analyzed", 20))
        final, claims = [], []
        snippet = int(policy["agent"].get("max_untrusted_snippet_chars", 2000))
        for i, (finding, assessment) in enumerate(zip(findings.values(), assessments)):
            use_cfg = cfg if i < max_llm else llm.LLMConfig(mode="disabled", base_url=None, model=None, api_key=None)
            res = analyze_finding(finding, assessment, evidence, run_dir=out, config=use_cfg,
                                  transport=llm_transport, max_snippet=snippet)
            final.append(res.assessment)
            claims.extend(res.claims)
        risk = RiskFile(schema_version=SCHEMA_VERSION, scan_id=run.scan_id, assessments=final, claims=claims)
        write_json_atomic(out / "risk.json", risk.to_json_dict())
        mode = "model" if cfg.enabled else "LLM_MODE=disabled templates"
        run.stage("analysis", "COMPLETE", tool=f"guardian.analysis.scoring + analyst ({mode})")
        run.go("ANALYZED", f"{len(final)} assessment(s), {sum(c.validated for c in claims)}/{len(claims)} "
                           "claim(s) validated")
    except Exception as exc:  # noqa: BLE001
        msg = _err(exc)
        run.stage("analysis", "FAILED", tool="guardian.analysis.scoring", reason=msg,
                  evidence_ids=run.fail_log("analysis", msg + "\n" + traceback.format_exc(limit=3)))
        run.errors.append(f"analysis: {msg}")
        run.go("FAILED", f"analysis failed: {msg}")
    return run.overall()


def _finish(run: ScanRun) -> int:
    status = run.overall()
    run.write_metadata(status, finished=True)
    print(f"scan_id: {run.scan_id}")
    for name, rec in run.records.items():
        print(f"stage {name}: {rec['status']}" + (f" - {rec['reason']}" if rec.get("reason") else ""))
    for e in run.errors:
        print(f"ERROR: {e}")
    print(f"status: {status}")
    print(f"run: {run.run_dir.as_posix()}")
    return {"COMPLETE": EXIT_OK, "PARTIAL": EXIT_PARTIAL, "FAILED": EXIT_FAILED,
            "BLOCKED": EXIT_BLOCKED}.get(status, EXIT_FAILED)


def cmd_scan(args: argparse.Namespace) -> int:
    from guardian.guard import LocalPathRejected, PolicyError, check_local_path, load_policy

    try:
        policy = load_policy()
    except PolicyError as exc:
        print(f"BLOCKED: {exc}")
        return EXIT_BLOCKED

    if args.local:
        out = Path(args.out)
        problem = _prepare_out(out)
        if problem:
            print(f"BLOCKED: {problem}")
            return EXIT_BLOCKED
        out.mkdir(parents=True, exist_ok=True)
        scan_id = f"scan-{uuid.uuid4().hex}"
        try:
            src = check_local_path(args.local, policy)
            rel = src.relative_to(REPO_ROOT).as_posix()
            repo_url = f"local://fixture/{rel}"
        except (LocalPathRejected, ValueError) as exc:
            run = ScanRun(out, scan_id, "local://fixture/rejected", "LOCAL_FIXTURE")
            run.go("CREATED", "scan requested")
            run.stage("intake", "BLOCKED", tool="guardian.cli", reason=str(exc))
            run.errors.append(f"intake: {exc}")
            run.go("BLOCKED", f"local path rejected: {exc}")
            return _finish(run)
        run = ScanRun(out, scan_id, repo_url, "LOCAL_FIXTURE")
        run.go("CREATED", "scan requested (--local)")
        run.write_metadata("RUNNING", finished=False)
        run.go("ACQUIRING", "static copy of allowlisted local fixture; no repository code executed")
        try:
            run.snapshot_sha = _copy_local_snapshot(src, out / "repo", policy)
            run.stage("intake", "COMPLETE", tool="guardian.cli local snapshot")
            run.capabilities["source"] = "static local fixture copy; repository code not executed"
        except (OSError, PermissionError) as exc:
            msg = _err(exc)
            run.stage("intake", "FAILED", tool="guardian.cli local snapshot", reason=msg,
                      evidence_ids=run.fail_log("intake", msg))
            run.errors.append(f"intake: {msg}")
            run.go("FAILED", f"local snapshot failed: {msg}")
            return _finish(run)
        run_scan_pipeline(run, out / "repo", baseline_ref=args.baseline_ref)
        return _finish(run)

    # --repo: A's acquire_repo owns validation, cloning and pinning.
    acquire = _optional("guardian.intake", "acquire_repo")
    if acquire is None:
        print("UNAVAILABLE: A's guardian.intake not importable")
        return EXIT_UNAVAILABLE
    workspace = Path(args.out)
    workspace.mkdir(parents=True, exist_ok=True)
    try:
        meta = acquire(args.repo, args.ref, str(workspace))
    except Exception as exc:  # noqa: BLE001 - A raises IntakeError on rejected URLs
        print(f"BLOCKED: repository rejected: {_err(exc)}")
        return EXIT_BLOCKED
    run_dir = workspace / meta.scan_id
    run = ScanRun(run_dir, meta.scan_id, meta.repo_url, meta.source_kind.value, commit_sha=meta.commit_sha,
                  started_at=meta.started_at)
    run.snapshot_sha = meta.source_snapshot_sha256
    run.tool_versions.update(meta.tool_versions)
    run.go("CREATED", "scan requested (--repo)")
    run.write_metadata("RUNNING", finished=False)
    run.go("ACQUIRING", f"A.acquire_repo {meta.repo_url} -> {meta.commit_sha}")
    if meta.status.value != "COMPLETE":
        run.stage("intake", "FAILED", tool="guardian.intake", reason="; ".join(meta.errors) or "intake failed",
                  evidence_ids=run.fail_log("intake", "; ".join(meta.errors)))
        run.errors.extend(meta.errors)
        run.go("FAILED", "repository intake failed")
        return _finish(run)
    run.stage("intake", "COMPLETE", tool="guardian.intake", tool_version=meta.tool_versions.get("git"))
    run.capabilities.update(meta.scope_capabilities)
    run_scan_pipeline(run, run_dir / "repo", baseline_ref=args.baseline_ref)
    return _finish(run)


# ---------------------------------------------------------------------------
# read-only views: graph / path / findings / report
# ---------------------------------------------------------------------------


def _read(run: Path, name: str) -> Any | None:
    path = run / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _stage_line(meta: dict | None, stage: str) -> str:
    if not meta:
        return f"{stage}: UNKNOWN (no metadata.json)"
    rec = meta.get("stage_records", {}).get(stage)
    status = meta.get("stage_statuses", {}).get(stage, "NOT_RUN")
    reason = f" - {rec['reason']}" if rec and rec.get("reason") else ""
    return f"{stage}: {status}{reason}"


def cmd_graph(args: argparse.Namespace) -> int:
    run = Path(args.run)
    meta = _read(run, "metadata.json")
    graph = _read(run, "graph.json")
    print(_stage_line(meta, "graph"))
    if graph is None:
        print("graph.json not present: no dependency graph for this run")
        return EXIT_UNAVAILABLE
    from guardian.schemas import GraphBundle

    g = GraphBundle.model_validate(graph)
    if args.neighbors:
        fn = _optional("guardian.analysis.paths", "get_neighbors")
        if fn is None:
            print("UNAVAILABLE: B's guardian.analysis.paths not merged")
            return EXIT_UNAVAILABLE
        from guardian.schemas import NeighborhoodResult

        res = NeighborhoodResult.model_validate(fn(str(run / "graph.sqlite"), g.scan_id, args.neighbors,
                                                   args.direction, depth=args.depth, max_nodes=args.max_nodes))
        print(json.dumps(res.to_json_dict(), indent=2))
        return EXIT_OK
    by_dir: dict[str, int] = {}
    for c in g.components:
        by_dir[c.directness.value] = by_dir.get(c.directness.value, 0) + 1
    print(f"scan_id: {g.scan_id}")
    print(f"modules: {len(g.modules)}  occurrences: {len(g.components)}  "
          f"package identities: {len({c.package_key for c in g.components if c.package_key})}  edges: {len(g.edges)}")
    print(f"directness: {json.dumps(by_dir, sort_keys=True)}")
    print(f"coverage: {json.dumps(g.coverage_summary.model_dump())}")
    for m in g.modules:
        print(f"  module {m.module_id} path={m.relative_path} eco={m.ecosystem} coverage={m.coverage.value}"
              + (f" ({m.coverage_reason})" if m.coverage_reason else ""))
    for w in g.warnings:
        print(f"WARNING: {w}")
    if meta and meta.get("stage_statuses", {}).get("graph") == "PARTIAL":
        return EXIT_PARTIAL
    return EXIT_OK


def cmd_path(args: argparse.Namespace) -> int:
    run = Path(args.run)
    meta = _read(run, "metadata.json") or {}
    fn = _optional("guardian.analysis.paths", "get_dependency_path")
    if fn is None:
        print("UNAVAILABLE: B's guardian.analysis.paths not merged")
        return EXIT_UNAVAILABLE
    from guardian.schemas import PathResult

    res = PathResult.model_validate(fn(str(run / "graph.sqlite"), meta.get("scan_id", ""), args.module,
                                       args.component))
    print(json.dumps(res.to_json_dict(), indent=2))
    if res.status.value == "NO_KNOWN_PATH":
        print("NOTE: NO_KNOWN_PATH is not proof of unreachability")
    return EXIT_OK if res.status.value == "FOUND" else EXIT_PARTIAL


def cmd_findings(args: argparse.Namespace) -> int:
    run = Path(args.run)
    meta = _read(run, "metadata.json")
    data = _read(run, "findings.json")
    risk = _read(run, "risk.json") or {"assessments": [], "claims": []}
    print(_stage_line(meta, "advisory"))
    print(_stage_line(meta, "detectors"))
    if data is None:
        print("findings.json not present")
        return EXIT_UNAVAILABLE
    prio = {a["finding_id"]: a for a in risk["assessments"]}
    if args.json:
        print(json.dumps({"findings": data["findings"], "assessments": risk["assessments"]}, indent=2))
    for f in data["findings"]:
        a = prio.get(f["finding_id"])
        print(f"- [{(a or f)['priority']}] {f['classification']} {f['finding_id']}: {f['title']}")
        if a:
            print(f"    rule {a['factors'].get('rule')}: {a['rationale']}")
        print(f"    evidence: {', '.join(f['evidence_ids']) or '(none)'}  basis: {f['evidence_basis']}")
    if not data["findings"]:
        stages = (meta or {}).get("stage_statuses", {})
        if stages.get("advisory") == "COMPLETE" and stages.get("detectors") == "COMPLETE":
            print("no known findings from COMPLETED lookups at scan time (NO_KNOWN_FINDING, not 'safe')")
        else:
            print("no findings recorded, but detection did not complete: status UNKNOWN, not zero")
            return EXIT_PARTIAL
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    fn = _optional("guardian.reporter", "create_report")
    if fn is None:
        print("UNAVAILABLE: D's guardian.reporter not merged; use `findings`/`graph` output as fallback")
        return EXIT_UNAVAILABLE
    json_path, md_path = fn(str(Path(args.run)))
    print(f"report.json: {Path(json_path).as_posix()}")
    print(f"report.md: {Path(md_path).as_posix()}")
    return EXIT_OK


def cmd_benchmark(args: argparse.Namespace) -> int:
    print("UNAVAILABLE: graph benchmark is owned by B (guardian.analysis.graph_store); not implemented in C's CLI")
    return EXIT_UNAVAILABLE


# ---------------------------------------------------------------------------
# remediation workflow (Day 2)
# ---------------------------------------------------------------------------


def _remediation_call(fn: Callable[[], Any]) -> int:
    from guardian.agents.remediation import ApprovalDenied, RemediationError
    from guardian.agents.remediator import UnsafeCandidatePath
    from guardian.state import TransitionError

    try:
        fn()
        return EXIT_OK
    except ApprovalDenied as exc:
        print("BLOCKED: approval denied")
        for r in exc.reasons:
            print(f"  - {r}")
        return EXIT_BLOCKED
    except (RemediationError, TransitionError, UnsafeCandidatePath) as exc:
        print(f"BLOCKED: {exc}")
        return EXIT_BLOCKED


def cmd_propose(args: argparse.Namespace) -> int:
    from guardian.agents import remediation

    human = None
    if args.strategy:
        human = {"strategy": args.strategy, "relative_path": args.file, "proposed_version": args.version,
                 "change_description": args.change, "rationale": args.rationale}

    def go():
        p = remediation.start(args.run, args.finding, human_candidate=human)
        from guardian.schemas import proposal_digest

        print(f"proposal: {p.proposal_id} strategy={p.strategy.value} version={p.proposed_version}")
        print(f"digest: {proposal_digest(p)}")
    return _remediation_call(go)


def cmd_audit(args: argparse.Namespace) -> int:
    from guardian.agents import remediation

    def go():
        res = remediation.audit(args.run, args.proposal)
        if res is None:
            raise remediation.RemediationError("candidate audit unavailable or failed: proposal BLOCKED")
        print(f"audit: {res.audit_result_id} verdict={res.verdict.value} (ALLOW_REVIEW is not 'safe')")
    return _remediation_call(go)


def cmd_review(args: argparse.Namespace) -> int:
    from guardian.agents import remediation

    def go():
        state, reasons = remediation.review(args.run, args.proposal)
        print(f"guard: {state.value}")
        for r in reasons:
            print(f"  - {r}")
        if state.value != "REVIEW_PENDING":
            raise remediation.RemediationError(f"proposal {state.value}")
    return _remediation_call(go)


def cmd_decide(args: argparse.Namespace) -> int:
    from guardian.agents import remediation

    def go():
        rec = remediation.decide(args.run, args.proposal, decision=args.decision, reviewer_label=args.reviewer,
                                 reviewer_role=args.role, confirm_digest=args.confirm_digest)
        print(f"recorded HUMAN {rec.decision.value} for {rec.proposal_id} digest={rec.proposal_sha256[:16]}… "
              f"expires={rec.expires_at}")
        if rec.decision.value == "APPROVE":
            ctx = remediation.load_context(args.run)
            print(f"approval_event_id: {ctx.proposal(args.proposal).approval_event_id}")
    return _remediation_call(go)


def cmd_validate(args: argparse.Namespace) -> int:
    from guardian.agents import remediation

    result_holder: dict = {}

    def go():
        res = remediation.validate(args.run, args.proposal, args.approval)
        result_holder["status"] = res.status.value
        print(f"validation: {res.status.value}")
        for w in res.warnings:
            print(f"  - {w}")
    code = _remediation_call(go)
    if code != EXIT_OK:
        return code
    return {"PASS": EXIT_OK, "FAILED": EXIT_FAILED, "INCONCLUSIVE": EXIT_PARTIAL}.get(
        result_holder.get("status", ""), EXIT_BLOCKED)


def cmd_status(args: argparse.Namespace) -> int:
    from guardian.state import read_jsonl

    path = Path(args.run) / "events.jsonl"
    if not path.exists():
        print("no events.jsonl")
        return EXIT_UNAVAILABLE
    for e in read_jsonl(path):
        print(f"{e['timestamp']} {e.get('workflow_id') or '-'} {e['actor_type']}:{e['actor_label']} "
              f"{e.get('previous_state')} -> {e.get('next_state')} [{e['event_type']}] {e['message']}")
    return EXIT_OK


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m guardian.cli", description="Bosch Guardian")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check prerequisites").set_defaults(func=cmd_doctor)

    p = sub.add_parser("scan", help="scan an approved repository or allowlisted local fixture")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--repo")
    src.add_argument("--local")
    p.add_argument("--ref")
    p.add_argument("--out", required=True)
    p.add_argument("--baseline-ref", default=None)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("graph", help="graph summary or bounded neighborhood (B)")
    p.add_argument("--run", required=True)
    p.add_argument("--summary", action="store_true")
    p.add_argument("--neighbors")
    p.add_argument("--direction", default="dependents", choices=["dependents", "dependencies", "both"])
    p.add_argument("--depth", type=int, default=1)
    p.add_argument("--max-nodes", type=int, default=150)
    p.set_defaults(func=cmd_graph)

    p = sub.add_parser("path", help="root-to-occurrence dependency path (B)")
    p.add_argument("--run", required=True)
    p.add_argument("--module", required=True)
    p.add_argument("--component", required=True)
    p.set_defaults(func=cmd_path)

    p = sub.add_parser("findings", help="findings with deterministic priorities and stage status")
    p.add_argument("--run", required=True)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_findings)

    p = sub.add_parser("validate-run", help="schema + referential integrity of a run folder")
    p.add_argument("run_dir")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_validate_run)

    p = sub.add_parser("report", help="report JSON/MD (D)")
    p.add_argument("--run", required=True)
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("benchmark", help="graph benchmark (B)")
    p.add_argument("--fixture")
    p.set_defaults(func=cmd_benchmark)

    p = sub.add_parser("export-schemas", help="write JSON Schema files")
    p.add_argument("--out", default="docs/contracts")
    p.set_defaults(func=cmd_export_schemas)

    p = sub.add_parser("propose", help="Day 2: create a remediation proposal for one finding")
    p.add_argument("--run", required=True)
    p.add_argument("--finding", required=True)
    p.add_argument("--strategy", choices=["DIRECT_UPGRADE", "PARENT_UPGRADE", "OVERRIDE", "CI_CONFIG", "ESCALATE"],
                   help="human-proposed declarative candidate (otherwise Remediator/ESCALATE)")
    p.add_argument("--file", help="repo-relative manifest/lockfile/CI file to change")
    p.add_argument("--version", help="exact candidate version")
    p.add_argument("--change", help="declarative change description (no commands)")
    p.add_argument("--rationale")
    p.set_defaults(func=cmd_propose)

    p = sub.add_parser("audit", help="Day 2: run B's candidate audit (fail closed if unavailable)")
    p.add_argument("--run", required=True)
    p.add_argument("--proposal", required=True)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("review", help="Day 2: Critic (optional) + deterministic Guard")
    p.add_argument("--run", required=True)
    p.add_argument("--proposal", required=True)
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("decide", help="Day 2: HUMAN approve/reject/revoke bound to proposal digest")
    p.add_argument("--run", required=True)
    p.add_argument("--proposal", required=True)
    p.add_argument("--decision", required=True, choices=["approve", "reject", "revoke"])
    p.add_argument("--reviewer", required=True, help="reviewer label (no secrets)")
    p.add_argument("--role", default="security-reviewer")
    p.add_argument("--confirm-digest", required=True, help=">=12 leading hex chars of the proposal digest")
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("validate", help="Day 2: verify approval, then call A's validator")
    p.add_argument("--run", required=True)
    p.add_argument("--proposal", required=True)
    p.add_argument("--approval", required=True)
    p.set_defaults(func=cmd_validate)

    p = sub.add_parser("status", help="print the event log")
    p.add_argument("--run", required=True)
    p.set_defaults(func=cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
