"""Canonical frozen data contracts for Bosch Guardian (project.md §9).

Schema owner: Role C.  This is the ONLY module that may define ``Finding``,
``Evidence`` or any other cross-branch model.  Every other branch imports from
here.  Changes require a coordinated PR, a ``SCHEMA_VERSION`` bump and updated
consumer tests (see ``docs/contracts/CHANGELOG.md``).

Rules encoded here (not merely documented):

* Fields listed as required in §9.2 have no default.  Nullable fields are typed
  ``X | None`` *without* a default, so producers must send an explicit ``null``.
* Unknown keys are rejected (``extra="forbid"``) so private format drift fails
  loudly instead of being silently dropped.
* Additions beyond the §9.2 tables are optional with conservative defaults and
  are listed in ``CONTRACT_ADDITIONS`` so consumers built against the bare
  tables keep validating.
* Timestamps are RFC3339 UTC; SHA-256 values are lowercase hex; run/repo paths
  are relative POSIX paths that cannot escape their root.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

SCHEMA_VERSION = "1.0"
SUPPORTED_SCHEMA_VERSIONS = frozenset({"1.0"})

# Optional fields added on top of the §9.2 tables in schema 1.0.  Each has a
# default so producers following only the tables still validate.
CONTRACT_ADDITIONS: dict[str, tuple[str, ...]] = {
    "ScanMetadata": ("stage_records",),
    "Evidence": ("supersedes",),
    "Finding": ("disposition",),
    "Event": ("workflow_id", "approval"),
}


# ---------------------------------------------------------------------------
# §9.1 canonical status enums (verbatim)
# ---------------------------------------------------------------------------


class Coverage(str, Enum):
    RESOLVED = "RESOLVED"
    PARTIAL = "PARTIAL"
    DECLARED_ONLY = "DECLARED_ONLY"
    UNSUPPORTED = "UNSUPPORTED"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"


class RunStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class StageStatus(str, Enum):
    NOT_RUN = "NOT_RUN"
    RUNNING = "RUNNING"
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    BLOCKED = "BLOCKED"


class FindingClass(str, Enum):
    CONFIRMED_ADVISORY = "CONFIRMED_ADVISORY"
    SUSPICIOUS_INDICATOR = "SUSPICIOUS_INDICATOR"
    CONFIGURATION_WEAKNESS = "CONFIGURATION_WEAKNESS"
    COVERAGE_LIMITATION = "COVERAGE_LIMITATION"


class Resolution(str, Enum):
    RESOLVED = "RESOLVED"
    DECLARED_ONLY = "DECLARED_ONLY"
    UNKNOWN_VERSION = "UNKNOWN_VERSION"
    CONFLICT = "CONFLICT"


class EvidenceBasis(str, Enum):
    TOOL_OBSERVED = "TOOL_OBSERVED"
    CORROBORATED = "CORROBORATED"
    RULE_MATCH = "RULE_MATCH"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class FindingType(str, Enum):
    VULNERABILITY = "VULNERABILITY"
    SUSPICIOUS_CHANGE = "SUSPICIOUS_CHANGE"
    CI_POLICY = "CI_POLICY"
    CONTAINER_POLICY = "CONTAINER_POLICY"
    COVERAGE_GAP = "COVERAGE_GAP"


class Priority(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    UNASSESSED = "UNASSESSED"


class ValidationStatus(str, Enum):
    NOT_RUN = "NOT_RUN"
    PASS = "PASS"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ProposalStatus(str, Enum):
    PROPOSED = "PROPOSED"
    AUDITED = "AUDITED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"
    VALIDATING = "VALIDATING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


# ---------------------------------------------------------------------------
# Enumerated string fields from the §9.2 tables (values verbatim from tables)
# ---------------------------------------------------------------------------


class SourceKind(str, Enum):
    GIT_PUBLIC = "GIT_PUBLIC"
    LOCAL_FIXTURE = "LOCAL_FIXTURE"
    CACHED_SNAPSHOT = "CACHED_SNAPSHOT"


class EvidenceKind(str, Enum):
    MANIFEST = "MANIFEST"
    LOCKFILE = "LOCKFILE"
    SBOM = "SBOM"
    ADVISORY = "ADVISORY"
    RULE_MATCH = "RULE_MATCH"
    TOOL_LOG = "TOOL_LOG"
    CI_CONFIG = "CI_CONFIG"
    VALIDATION = "VALIDATION"
    MODEL_OUTPUT = "MODEL_OUTPUT"


class DependencyScope(str, Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    OPTIONAL = "optional"
    PEER = "peer"
    BUILD = "build"
    UNKNOWN = "unknown"


class Directness(str, Enum):
    DIRECT = "DIRECT"
    TRANSITIVE = "TRANSITIVE"
    UNRESOLVED = "UNRESOLVED"


class PackageSourceType(str, Enum):
    REGISTRY = "REGISTRY"
    GIT = "GIT"
    TARBALL = "TARBALL"
    WORKSPACE = "WORKSPACE"
    LOCAL = "LOCAL"
    UNKNOWN = "UNKNOWN"


class ComponentSourceScope(str, Enum):
    SOURCE = "SOURCE"
    ARTIFACT = "ARTIFACT"
    BOTH = "BOTH"
    UNKNOWN = "UNKNOWN"


class EdgeSourceScope(str, Enum):
    SOURCE = "SOURCE"
    ARTIFACT = "ARTIFACT"
    UNKNOWN = "UNKNOWN"


class ImagePresence(str, Enum):
    OBSERVED = "OBSERVED"
    NOT_OBSERVED_IN_SCANNED_IMAGE = "NOT_OBSERVED_IN_SCANNED_IMAGE"
    NOT_CHECKED = "NOT_CHECKED"
    UNKNOWN = "UNKNOWN"


class Relationship(str, Enum):
    """Edge types from §7.1."""

    CONTAINS_MODULE = "CONTAINS_MODULE"
    DECLARES = "DECLARES"
    DEPENDS_ON = "DEPENDS_ON"
    BUILDS_FROM = "BUILDS_FROM"
    OBSERVED_IN = "OBSERVED_IN"
    INVOKES_DURING_BUILD = "INVOKES_DURING_BUILD"
    INVOKES_DURING_INSTALL = "INVOKES_DURING_INSTALL"
    MAY_INVOKE = "MAY_INVOKE"


class EdgeResolution(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNRESOLVED = "UNRESOLVED"


class PathStatus(str, Enum):
    """Finding.path_status values (§9.2)."""

    FOUND = "FOUND"
    NO_KNOWN_PATH = "NO_KNOWN_PATH"
    UNRESOLVED = "UNRESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class PathQueryStatus(str, Enum):
    """Graph path query statuses (§7.7)."""

    FOUND = "FOUND"
    NO_KNOWN_PATH = "NO_KNOWN_PATH"
    UNRESOLVED = "UNRESOLVED"
    TRUNCATED = "TRUNCATED"
    NOT_FOUND = "NOT_FOUND"


class ExecutionStage(str, Enum):
    INSTALL = "INSTALL"
    BUILD = "BUILD"
    CI = "CI"
    RUNTIME = "RUNTIME"
    DEV_TEST = "DEV_TEST"
    UNKNOWN = "UNKNOWN"


class ExecutionEvidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    NOT_ANALYZED = "NOT_ANALYZED"


class FirstSeenIn(str, Enum):
    REAL_UPSTREAM = "REAL_UPSTREAM"
    SEEDED_SIMULATION = "SEEDED_SIMULATION"
    LOCAL_FIXTURE = "LOCAL_FIXTURE"


class Disposition(str, Enum):
    """§8.1 disposition (schema 1.0 addition on Finding)."""

    OPEN = "OPEN"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    PROPOSED_FIX = "PROPOSED_FIX"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    RESOLVED_VERIFIED = "RESOLVED_VERIFIED"
    NOT_APPLICABLE_VERIFIED = "NOT_APPLICABLE_VERIFIED"


class ClaimBasis(str, Enum):
    VERIFIED = "VERIFIED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class FixStrategy(str, Enum):
    DIRECT_UPGRADE = "DIRECT_UPGRADE"
    PARENT_UPGRADE = "PARENT_UPGRADE"
    OVERRIDE = "OVERRIDE"
    CI_CONFIG = "CI_CONFIG"
    ESCALATE = "ESCALATE"


class AuditVerdict(str, Enum):
    ALLOW_REVIEW = "ALLOW_REVIEW"  # NOT "safe": may proceed to explicit approval
    REJECT = "REJECT"
    INCONCLUSIVE = "INCONCLUSIVE"


class ActorType(str, Enum):
    SYSTEM = "SYSTEM"
    HUMAN = "HUMAN"
    LLM = "LLM"
    TOOL = "TOOL"


class WorkflowState(str, Enum):
    """§9.6 state machine (+ INCONCLUSIVE from §22.3)."""

    CREATED = "CREATED"
    ACQUIRING = "ACQUIRING"
    INDEXING = "INDEXING"
    INVENTORY_READY = "INVENTORY_READY"
    DETECTING = "DETECTING"
    FINDINGS_READY = "FINDINGS_READY"
    ANALYZING = "ANALYZING"
    ANALYZED = "ANALYZED"
    PROPOSING = "PROPOSING"
    AUDITING = "AUDITING"
    REVIEW_PENDING = "REVIEW_PENDING"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"
    VALIDATING = "VALIDATING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ApprovalDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REVOKE = "REVOKE"


# ---------------------------------------------------------------------------
# Shared validated scalar types
# ---------------------------------------------------------------------------

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABS = re.compile(r"^[A-Za-z]:[\\/]")


def _utc(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an RFC3339 string")
    text = value.strip()
    if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", text):
        raise ValueError("timestamp must be RFC3339 (YYYY-MM-DDTHH:MM:SS...)")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"invalid RFC3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError("timestamp must be UTC (suffix Z or +00:00)")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(value: str) -> str:
    if not _SHA256.fullmatch(value):
        raise ValueError("must be a lowercase 64-character SHA-256 hex digest")
    return value


def _relpath(value: str) -> str:
    if not value:
        raise ValueError("path must be nonempty")
    if "\\" in value or "\x00" in value:
        raise ValueError("path must be POSIX-style without backslashes or NUL")
    if value.startswith("/") or _WINDOWS_ABS.match(value) or value.startswith("~"):
        raise ValueError("path must be relative; host paths are not allowed")
    if any(part == ".." for part in value.split("/")):
        raise ValueError("path must not traverse outside its root")
    return value


def _nonempty(value: str) -> str:
    if not value or not value.strip():
        raise ValueError("must be a nonempty string")
    return value


UtcTimestamp = Annotated[str, AfterValidator(_utc)]
Sha256Hex = Annotated[str, AfterValidator(_sha256)]
RelPath = Annotated[str, AfterValidator(_relpath)]
NonEmptyStr = Annotated[str, AfterValidator(_nonempty)]


def utc_now() -> str:
    """Current time as canonical RFC3339 UTC (``...Z``)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, frozen=False)

    def to_json_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


class VersionedModel(ContractModel):
    schema_version: str

    @field_validator("schema_version")
    @classmethod
    def _supported_version(cls, value: str) -> str:
        if value not in SUPPORTED_SCHEMA_VERSIONS:
            raise ValueError(
                f"unsupported schema_version {value!r}; supported: {sorted(SUPPORTED_SCHEMA_VERSIONS)}"
            )
        return value


# ---------------------------------------------------------------------------
# ScanMetadata (metadata.json)
# ---------------------------------------------------------------------------


class StageRecord(ContractModel):
    """§18.3 explicit per-stage record.  ``null`` means unknown, never zero."""

    stage: NonEmptyStr
    status: StageStatus
    attempted: bool
    tool: str | None
    tool_version: str | None
    reason: str | None
    completed_at: UtcTimestamp | None
    known_matches: int | None = Field(ge=0)
    evidence_ids: list[str]

    @model_validator(mode="after")
    def _honest(self) -> "StageRecord":
        if self.status in {StageStatus.FAILED, StageStatus.UNAVAILABLE, StageStatus.BLOCKED,
                           StageStatus.PARTIAL} and not (self.reason and self.reason.strip()):
            raise ValueError(f"stage {self.stage}: status {self.status.value} requires a reason")
        if self.status == StageStatus.COMPLETE and self.completed_at is None:
            raise ValueError(f"stage {self.stage}: COMPLETE requires completed_at")
        if self.known_matches is not None and self.status not in {StageStatus.COMPLETE, StageStatus.PARTIAL}:
            raise ValueError(
                f"stage {self.stage}: known_matches must be null unless the stage COMPLETE/PARTIAL"
            )
        if self.status == StageStatus.NOT_RUN and self.attempted:
            raise ValueError(f"stage {self.stage}: NOT_RUN cannot be attempted")
        return self


class ScanMetadata(VersionedModel):
    scan_id: NonEmptyStr
    repo_url: NonEmptyStr
    commit_sha: str | None
    source_kind: SourceKind
    started_at: UtcTimestamp | None
    finished_at: UtcTimestamp | None
    status: RunStatus
    tool_versions: dict[str, str]
    errors: list[str]
    stage_statuses: dict[str, StageStatus]
    database_snapshots: dict[str, str | None]
    source_snapshot_sha256: Sha256Hex | None
    scope_capabilities: dict[str, str]
    # --- 1.0 addition ---
    stage_records: dict[str, StageRecord] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _consistent(self) -> "ScanMetadata":
        if self.commit_sha is not None and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", self.commit_sha):
            raise ValueError("commit_sha must be a full lowercase Git commit id")
        if self.source_kind == SourceKind.GIT_PUBLIC:
            if self.status == RunStatus.COMPLETE and self.commit_sha is None:
                raise ValueError("a COMPLETE GIT_PUBLIC scan requires a full commit_sha")
        if self.source_kind == SourceKind.LOCAL_FIXTURE:
            if not self.repo_url.startswith("local://fixture/"):
                raise ValueError("LOCAL_FIXTURE repo_url must be local://fixture/<id>")
            if self.commit_sha is not None:
                raise ValueError("LOCAL_FIXTURE must not carry an invented commit_sha")
        if self.status in {RunStatus.FAILED, RunStatus.BLOCKED} and not self.errors:
            raise ValueError(f"status {self.status.value} requires at least one error message")
        for name, record in self.stage_records.items():
            if record.stage != name:
                raise ValueError(f"stage_records key {name!r} != record.stage {record.stage!r}")
            listed = self.stage_statuses.get(name)
            if listed is not None and listed != record.status:
                raise ValueError(f"stage {name}: stage_statuses and stage_records disagree")
        if self.started_at and self.finished_at and self.finished_at < self.started_at:
            raise ValueError("finished_at precedes started_at")
        return self


# ---------------------------------------------------------------------------
# ProjectModule (module_index.json)
# ---------------------------------------------------------------------------

_ARTIFACT_SBOM_ALLOWED = {
    StageStatus.NOT_RUN, StageStatus.COMPLETE, StageStatus.PARTIAL,
    StageStatus.FAILED, StageStatus.BLOCKED,
}


class ProjectModule(ContractModel):
    module_id: NonEmptyStr
    relative_path: RelPath
    ecosystem: NonEmptyStr
    manifests: list[RelPath]
    lockfiles: list[RelPath]
    ci_files: list[RelPath]
    dockerfiles: list[RelPath]
    coverage: Coverage
    coverage_reason: str
    scanner_names: list[str]
    file_counts: dict[str, Annotated[int, Field(ge=0)]]
    scan_stage: dict[str, StageStatus]
    artifact_sbom_status: StageStatus

    @model_validator(mode="after")
    def _reason(self) -> "ProjectModule":
        if self.coverage != Coverage.RESOLVED and not self.coverage_reason.strip():
            raise ValueError(f"module {self.module_id}: coverage {self.coverage.value} needs a coverage_reason")
        if self.artifact_sbom_status not in _ARTIFACT_SBOM_ALLOWED:
            raise ValueError("artifact_sbom_status must be NOT_RUN, COMPLETE, PARTIAL, FAILED or BLOCKED")
        return self


class ModuleIndex(VersionedModel):
    scan_id: NonEmptyStr
    modules: list[ProjectModule]

    @model_validator(mode="after")
    def _unique(self) -> "ModuleIndex":
        ids = [m.module_id for m in self.modules]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate module_id in module_index")
        return self


# ---------------------------------------------------------------------------
# Component / DependencyEdge / GraphBundle (graph.json)
# ---------------------------------------------------------------------------

# Range operators / wildcards / dist-tags.  Bare "2.0" stays legal: it is an
# exact version in several ecosystems (e.g. PyPI).
_CONSTRAINT_CHARS = re.compile(r"[\^~<>=*|\s]|^latest$|^next$|^x$|\.[xX](\.|$)", re.IGNORECASE)


class Component(ContractModel):
    package_key: str | None
    ecosystem: NonEmptyStr
    name: NonEmptyStr
    resolved_version: str | None
    declared_constraint: str | None
    purl: str | None
    occurrence_id: NonEmptyStr
    module_id: NonEmptyStr
    source_refs: list[str]
    resolution: Resolution
    evidence_ids: list[str]
    install_stage_indicator: str | None
    dependency_scopes: list[DependencyScope]
    directness: Directness
    license: str | None
    artifact_hashes: list[str]
    package_source_type: PackageSourceType
    resolved_source_url: str | None
    registry_host: str | None
    source_scope: ComponentSourceScope
    image_presence: ImagePresence
    manifest_refs: list[RelPath]

    @model_validator(mode="after")
    def _honest_version(self) -> "Component":
        if self.resolved_version is not None and _CONSTRAINT_CHARS.search(self.resolved_version):
            raise ValueError(
                f"{self.occurrence_id}: resolved_version {self.resolved_version!r} looks like a "
                "constraint; store it in declared_constraint"
            )
        if self.resolved_version is None and self.package_key is not None:
            raise ValueError(f"{self.occurrence_id}: package_key must be null without an exact resolved_version")
        if self.resolution == Resolution.RESOLVED and self.resolved_version is None:
            raise ValueError(f"{self.occurrence_id}: RESOLVED requires resolved_version")
        if self.resolution == Resolution.RESOLVED and not self.evidence_ids:
            raise ValueError(f"{self.occurrence_id}: RESOLVED requires inventory evidence_ids")
        return self


class DependencyEdge(ContractModel):
    edge_id: NonEmptyStr
    source_id: NonEmptyStr
    target_id: NonEmptyStr
    relationship: Relationship
    evidence_ids: list[str]
    module_id: str | None
    resolution: EdgeResolution
    dependency_scope: DependencyScope
    declared_constraint: str | None
    source_scope: EdgeSourceScope

    @model_validator(mode="after")
    def _evidence_backed(self) -> "DependencyEdge":
        if self.resolution == EdgeResolution.OBSERVED and not self.evidence_ids:
            raise ValueError(f"{self.edge_id}: an OBSERVED edge requires evidence_ids")
        return self


class CoverageSummary(ContractModel):
    total_modules: int = Field(ge=0)
    resolved_modules: int = Field(ge=0)
    partial_modules: int = Field(ge=0)
    declared_only_modules: int = Field(ge=0)
    unsupported_modules: int = Field(ge=0)
    failed_modules: int = Field(ge=0)

    @classmethod
    def from_modules(cls, modules: list[ProjectModule]) -> "CoverageSummary":
        def count(c: Coverage) -> int:
            return sum(1 for m in modules if m.coverage == c)

        return cls(
            total_modules=len(modules),
            resolved_modules=count(Coverage.RESOLVED),
            partial_modules=count(Coverage.PARTIAL),
            declared_only_modules=count(Coverage.DECLARED_ONLY),
            unsupported_modules=count(Coverage.UNSUPPORTED),
            failed_modules=count(Coverage.FAILED),
        )


class GraphBundle(VersionedModel):
    scan_id: NonEmptyStr
    modules: list[ProjectModule]
    components: list[Component]
    edges: list[DependencyEdge]
    coverage_summary: CoverageSummary
    warnings: list[str]

    def integrity_errors(self) -> list[str]:
        """Self-contained referential checks (no evidence file needed)."""
        errors: list[str] = []
        module_ids = [m.module_id for m in self.modules]
        occ_ids = [c.occurrence_id for c in self.components]
        edge_ids = [e.edge_id for e in self.edges]
        for label, ids in (("module_id", module_ids), ("occurrence_id", occ_ids), ("edge_id", edge_ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            if dupes:
                errors.append(f"graph: duplicate {label}: {dupes}")
        nodes = set(module_ids) | set(occ_ids)
        for comp in self.components:
            if comp.module_id not in module_ids:
                errors.append(f"graph: component {comp.occurrence_id} references unknown module {comp.module_id}")
        for edge in self.edges:
            for end in (edge.source_id, edge.target_id):
                if end not in nodes:
                    errors.append(f"graph: edge {edge.edge_id} endpoint {end} is not a module or occurrence")
            if edge.module_id is not None and edge.module_id not in module_ids:
                errors.append(f"graph: edge {edge.edge_id} references unknown module {edge.module_id}")
        expected = CoverageSummary.from_modules(self.modules)
        if expected != self.coverage_summary:
            errors.append(
                f"graph: coverage_summary {self.coverage_summary.model_dump()} does not match modules "
                f"{expected.model_dump()}"
            )
        return errors


# ---------------------------------------------------------------------------
# Evidence (evidence.jsonl)
# ---------------------------------------------------------------------------

MAX_OBSERVED_VALUE_BYTES = 4096


class Evidence(VersionedModel):
    scan_id: NonEmptyStr
    evidence_id: NonEmptyStr
    kind: EvidenceKind
    tool_name: str | None
    tool_version: str | None
    source_path: RelPath | None
    json_pointer: str | None
    line_start: int | None = Field(ge=1)
    line_end: int | None = Field(ge=1)
    observed_value: JsonValue
    raw_artifact: RelPath | None
    raw_sha256: Sha256Hex | None
    observation: NonEmptyStr
    recorded_at: UtcTimestamp
    # --- 1.0 addition ---
    supersedes: str | None = None

    @model_validator(mode="after")
    def _bounded(self) -> "Evidence":
        size = len(json.dumps(self.observed_value, ensure_ascii=False).encode("utf-8"))
        if size > MAX_OBSERVED_VALUE_BYTES:
            raise ValueError(f"{self.evidence_id}: observed_value exceeds {MAX_OBSERVED_VALUE_BYTES} bytes")
        if self.raw_artifact is not None and self.raw_sha256 is None:
            raise ValueError(f"{self.evidence_id}: raw_artifact requires raw_sha256")
        if (self.line_start is None) != (self.line_end is None):
            raise ValueError(f"{self.evidence_id}: line_start and line_end must both be known or both null")
        if self.line_start is not None and self.line_end is not None and self.line_end < self.line_start:
            raise ValueError(f"{self.evidence_id}: line_end precedes line_start")
        if self.supersedes == self.evidence_id:
            raise ValueError(f"{self.evidence_id}: evidence cannot supersede itself")
        return self


# ---------------------------------------------------------------------------
# Finding (findings.json)
# ---------------------------------------------------------------------------

_FACTUAL_TYPES = {
    FindingType.VULNERABILITY, FindingType.SUSPICIOUS_CHANGE,
    FindingType.CI_POLICY, FindingType.CONTAINER_POLICY,
}
_RULE_TYPES = {FindingType.SUSPICIOUS_CHANGE, FindingType.CI_POLICY, FindingType.CONTAINER_POLICY}


class Finding(VersionedModel):
    scan_id: NonEmptyStr
    finding_id: NonEmptyStr
    finding_type: FindingType
    title: NonEmptyStr
    description: str
    module_ids: list[str]
    occurrence_ids: list[str]
    advisory_ids: list[str]
    advisory_urls: list[str]
    rule_id: str | None
    severity_label: str | None
    cvss_score: float | None = Field(ge=0.0, le=10.0)
    priority: Priority
    evidence_ids: list[str]
    dependency_path_node_ids: list[str]
    path_status: PathStatus
    execution_stage: ExecutionStage
    execution_evidence: ExecutionEvidence
    evidence_basis: EvidenceBasis
    uncertainties: list[str]
    recommendations: list[str]
    classification: FindingClass
    advisory_aliases: list[str]
    first_seen_in: FirstSeenIn
    advisory_as_of: UtcTimestamp | None
    scanner_names: list[str]
    # --- 1.0 addition ---
    disposition: Disposition = Disposition.OPEN

    @model_validator(mode="after")
    def _evidence_first(self) -> "Finding":
        fid = self.finding_id
        if self.finding_type in _FACTUAL_TYPES and not self.evidence_ids:
            raise ValueError(f"{fid}: factual security finding requires evidence_ids")
        if self.finding_type in _RULE_TYPES and not self.rule_id:
            raise ValueError(f"{fid}: {self.finding_type.value} requires rule_id")
        if self.finding_type == FindingType.VULNERABILITY and not self.occurrence_ids:
            raise ValueError(f"{fid}: VULNERABILITY requires occurrence_ids")
        if self.classification == FindingClass.CONFIRMED_ADVISORY:
            if self.finding_type != FindingType.VULNERABILITY:
                raise ValueError(f"{fid}: CONFIRMED_ADVISORY must be finding_type VULNERABILITY")
            if not self.advisory_ids:
                raise ValueError(f"{fid}: CONFIRMED_ADVISORY requires advisory_ids")
        if self.path_status == PathStatus.FOUND and not self.dependency_path_node_ids:
            raise ValueError(f"{fid}: path_status FOUND requires dependency_path_node_ids")
        if self.path_status != PathStatus.FOUND and self.dependency_path_node_ids:
            raise ValueError(f"{fid}: dependency_path_node_ids must be empty unless path_status FOUND")
        if self.disposition in {Disposition.RESOLVED_VERIFIED, Disposition.NOT_APPLICABLE_VERIFIED} \
                and not self.evidence_ids:
            raise ValueError(f"{fid}: verified disposition requires supporting evidence")
        return self


class FindingsFile(VersionedModel):
    scan_id: NonEmptyStr
    findings: list[Finding]

    @model_validator(mode="after")
    def _same_scan(self) -> "FindingsFile":
        ids = [f.finding_id for f in self.findings]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate finding_id in findings.json")
        for f in self.findings:
            if f.scan_id != self.scan_id:
                raise ValueError(f"finding {f.finding_id} has scan_id {f.scan_id!r} != {self.scan_id!r}")
        return self


# ---------------------------------------------------------------------------
# Claim / RiskAssessment (risk.json)
# ---------------------------------------------------------------------------


class Claim(ContractModel):
    claim_id: NonEmptyStr
    scan_id: NonEmptyStr
    text: NonEmptyStr
    claim_type: NonEmptyStr
    evidence_ids: list[str]
    basis: ClaimBasis
    validated: bool
    validation_errors: list[str]

    @model_validator(mode="after")
    def _coherent(self) -> "Claim":
        if self.validated and self.validation_errors:
            raise ValueError(f"{self.claim_id}: a validated claim cannot carry validation_errors")
        if self.validated and self.basis == ClaimBasis.VERIFIED and not self.evidence_ids:
            raise ValueError(f"{self.claim_id}: a validated VERIFIED claim requires evidence_ids")
        return self


class RiskAssessment(VersionedModel):
    scan_id: NonEmptyStr
    finding_id: NonEmptyStr
    priority: Priority
    factors: dict[str, JsonValue]
    rationale: NonEmptyStr
    evidence_ids: list[str]
    unknowns: list[str]
    claim_ids: list[str]


class RiskFile(VersionedModel):
    scan_id: NonEmptyStr
    assessments: list[RiskAssessment]
    claims: list[Claim]

    @model_validator(mode="after")
    def _same_scan(self) -> "RiskFile":
        for item in [*self.assessments, *self.claims]:
            if item.scan_id != self.scan_id:
                raise ValueError(f"risk.json item has scan_id {item.scan_id!r} != {self.scan_id!r}")
        claim_ids = [c.claim_id for c in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("duplicate claim_id in risk.json")
        known = set(claim_ids)
        for a in self.assessments:
            missing = [c for c in a.claim_ids if c not in known]
            if missing:
                raise ValueError(f"assessment {a.finding_id} references unknown claims {missing}")
        return self


# ---------------------------------------------------------------------------
# Proposal / FixAuditResult (proposals.json)
# ---------------------------------------------------------------------------


class CandidateChange(ContractModel):
    relative_path: RelPath
    change_description: NonEmptyStr
    before_hash: Sha256Hex
    after_hash: Sha256Hex | None = None


class Proposal(VersionedModel):
    scan_id: NonEmptyStr
    proposal_id: NonEmptyStr
    finding_ids: list[NonEmptyStr] = Field(min_length=1)
    target_module_id: NonEmptyStr
    strategy: FixStrategy
    candidate_changes: list[CandidateChange]
    proposed_version: str | None
    rationale: NonEmptyStr
    evidence_ids: list[str]
    expected_validation: list[str]
    status: ProposalStatus
    audit_result_id: str | None
    approval_event_id: str | None

    @model_validator(mode="after")
    def _declarative(self) -> "Proposal":
        if self.strategy != FixStrategy.ESCALATE and not self.candidate_changes:
            raise ValueError(f"{self.proposal_id}: non-ESCALATE proposal requires candidate_changes")
        if self.status in {ProposalStatus.APPROVED, ProposalStatus.VALIDATING, ProposalStatus.VERIFIED} \
                and self.approval_event_id is None:
            raise ValueError(f"{self.proposal_id}: status {self.status.value} requires approval_event_id")
        if self.status in {ProposalStatus.AUDITED, ProposalStatus.APPROVED, ProposalStatus.VALIDATING,
                           ProposalStatus.VERIFIED} and self.audit_result_id is None:
            raise ValueError(f"{self.proposal_id}: status {self.status.value} requires audit_result_id")
        return self


# Fields excluded from the approval digest: they change as the proposal moves
# through the state machine, while the digest binds the *content* approved.
_DIGEST_EXCLUDED = frozenset({"status", "audit_result_id", "approval_event_id"})


def canonical_json(value: Any) -> bytes:
    """Deterministic UTF-8 JSON used for all contract hashes and IDs."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def proposal_digest(proposal: Proposal) -> str:
    """SHA-256 binding a human approval to the exact proposal content."""
    payload = {k: v for k, v in proposal.to_json_dict().items() if k not in _DIGEST_EXCLUDED}
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def stable_id(prefix: str, *parts: str, length: int = 20) -> str:
    """§7.2 / §28.2 stable ID: sha256 over a canonical JSON array (never ``hash()``)."""
    digest = hashlib.sha256(canonical_json([str(p) for p in parts])).hexdigest()
    return f"{prefix}:{digest[:length]}"


class FixAuditResult(ContractModel):
    audit_result_id: NonEmptyStr
    proposal_id: NonEmptyStr
    candidate_package_key: str | None
    known_advisories: list[str]
    new_dependency_count: int | None = Field(ge=0)
    install_script_indicators: list[str]
    integrity_indicators: list[str]
    behavior_checks: list[str]
    blocking_issues: list[str]
    evidence_ids: list[str]
    verdict: AuditVerdict

    @model_validator(mode="after")
    def _reasoned(self) -> "FixAuditResult":
        if self.verdict == AuditVerdict.REJECT and not self.blocking_issues:
            raise ValueError(f"{self.audit_result_id}: REJECT requires blocking_issues")
        if self.verdict == AuditVerdict.ALLOW_REVIEW and self.blocking_issues:
            raise ValueError(f"{self.audit_result_id}: ALLOW_REVIEW cannot have blocking_issues")
        return self


class ProposalsFile(VersionedModel):
    scan_id: NonEmptyStr
    proposals: list[Proposal]
    audit_results: list[FixAuditResult]

    @model_validator(mode="after")
    def _linked(self) -> "ProposalsFile":
        pids = [p.proposal_id for p in self.proposals]
        if len(pids) != len(set(pids)):
            raise ValueError("duplicate proposal_id in proposals.json")
        aids = {a.audit_result_id: a for a in self.audit_results}
        for p in self.proposals:
            if p.scan_id != self.scan_id:
                raise ValueError(f"proposal {p.proposal_id} has scan_id {p.scan_id!r} != {self.scan_id!r}")
            if p.audit_result_id is not None:
                audit = aids.get(p.audit_result_id)
                if audit is None:
                    raise ValueError(f"proposal {p.proposal_id} references unknown audit {p.audit_result_id}")
                if audit.proposal_id != p.proposal_id:
                    raise ValueError(f"audit {audit.audit_result_id} belongs to a different proposal")
                if audit.verdict != AuditVerdict.ALLOW_REVIEW and p.status in {
                    ProposalStatus.APPROVED, ProposalStatus.VALIDATING, ProposalStatus.VERIFIED,
                }:
                    raise ValueError(f"proposal {p.proposal_id}: audit {audit.verdict.value} cannot be approved")
        for a in self.audit_results:
            if a.proposal_id not in pids:
                raise ValueError(f"audit {a.audit_result_id} references unknown proposal {a.proposal_id}")
        return self


# ---------------------------------------------------------------------------
# ValidationResult (validation.json)
# ---------------------------------------------------------------------------


class CommandRecord(ContractModel):
    argv: list[NonEmptyStr] = Field(min_length=1)
    exit_code: int | None
    log_evidence_id: str | None
    duration_ms: int | None = Field(ge=0)


class ValidationResult(VersionedModel):
    scan_id: NonEmptyStr
    proposal_id: NonEmptyStr
    worktree_id: str | None
    approval_event_id: str | None
    status: ValidationStatus
    commands: list[CommandRecord]
    build_passed: bool | None
    tests_passed: bool | None
    rescan_completed: bool | None
    before_sbom_path: RelPath | None
    after_sbom_path: RelPath | None
    removed_findings: list[str]
    new_findings: list[str]
    remaining_findings: list[str]
    warnings: list[str]
    started_at: UtcTimestamp | None
    finished_at: UtcTimestamp | None

    @model_validator(mode="after")
    def _gate(self) -> "ValidationResult":
        if self.status == ValidationStatus.PASS:
            problems = []
            if self.approval_event_id is None:
                problems.append("approval_event_id")
            if self.build_passed is not True:
                problems.append("build_passed")
            if self.tests_passed is not True:
                problems.append("tests_passed")
            if self.rescan_completed is not True:
                problems.append("rescan_completed")
            if self.new_findings:
                problems.append("new_findings must be empty")
            if not self.commands:
                problems.append("commands")
            for cmd in self.commands:
                if cmd.exit_code != 0 or cmd.log_evidence_id is None:
                    problems.append(f"command {cmd.argv[0]} lacks exit 0 + log evidence")
            if self.after_sbom_path is None:
                problems.append("after_sbom_path")
            if problems:
                raise ValueError(f"{self.proposal_id}: PASS requires gate evidence: {problems}")
        return self


# ---------------------------------------------------------------------------
# Event (events.jsonl)
# ---------------------------------------------------------------------------


class ApprovalRecord(ContractModel):
    """Human decision bound to an exact proposal digest (§6.12, §22.2)."""

    decision: ApprovalDecision
    reviewer_label: NonEmptyStr
    reviewer_role: NonEmptyStr
    scan_id: NonEmptyStr
    proposal_id: NonEmptyStr
    proposal_sha256: Sha256Hex
    audit_result_id: str | None
    commit_sha: str | None
    lockfile_sha256: Sha256Hex | None
    policy_version: int = Field(ge=1)
    decided_at: UtcTimestamp
    expires_at: UtcTimestamp | None
    revokes_event_id: str | None = None

    @model_validator(mode="after")
    def _approve_needs_audit(self) -> "ApprovalRecord":
        if self.decision == ApprovalDecision.APPROVE and not self.audit_result_id:
            raise ValueError("APPROVE requires the audit_result_id being approved")
        if self.decision == ApprovalDecision.REVOKE and not self.revokes_event_id:
            raise ValueError("REVOKE requires revokes_event_id")
        return self


class Event(VersionedModel):
    scan_id: NonEmptyStr
    event_id: NonEmptyStr
    timestamp: UtcTimestamp
    actor_type: ActorType
    actor_label: NonEmptyStr
    event_type: NonEmptyStr
    previous_state: WorkflowState | None
    next_state: WorkflowState | None
    related_ids: list[str]
    evidence_ids: list[str]
    message: str
    # --- 1.0 additions ---
    workflow_id: str | None = None
    approval: ApprovalRecord | None = None

    @model_validator(mode="after")
    def _authority(self) -> "Event":
        if self.approval is not None:
            if self.actor_type != ActorType.HUMAN:
                raise ValueError(f"{self.event_id}: only a HUMAN actor may record an approval decision")
            if self.approval.scan_id != self.scan_id:
                raise ValueError(f"{self.event_id}: approval scan_id does not match event scan_id")
        if self.actor_type == ActorType.LLM and self.next_state in _LLM_FORBIDDEN_STATES:
            raise ValueError(f"{self.event_id}: an LLM actor cannot advance to {self.next_state.value}")
        return self


# A model can never advance beyond REVIEW_PENDING (§9.6); Guardian is stricter:
# only deterministic SYSTEM code or a HUMAN may enter these states.
_LLM_FORBIDDEN_STATES = frozenset({
    WorkflowState.APPROVED, WorkflowState.VALIDATING, WorkflowState.VERIFIED,
    WorkflowState.REJECTED, WorkflowState.REVIEW_PENDING,
})


# ---------------------------------------------------------------------------
# Report (report.json)
# ---------------------------------------------------------------------------


class Report(VersionedModel):
    scan_id: NonEmptyStr
    metadata: ScanMetadata
    coverage_summary: CoverageSummary
    component_count: int = Field(ge=0)
    occurrence_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    findings_summary: dict[str, JsonValue]
    finding_ids: list[str]
    claim_ids: list[str]
    proposal_ids: list[str]
    validation_status: ValidationStatus
    residual_risks: list[str]
    limitations: list[str]
    artifact_paths: dict[str, RelPath]

    @model_validator(mode="after")
    def _same_scan(self) -> "Report":
        if self.metadata.scan_id != self.scan_id:
            raise ValueError("report metadata.scan_id does not match report scan_id")
        return self


# ---------------------------------------------------------------------------
# Graph query return contracts (§7.7) — B returns these shapes as dicts
# ---------------------------------------------------------------------------


class GraphNodeRef(ContractModel):
    id: NonEmptyStr
    type: Literal["repository", "module", "occurrence", "component_identity", "artifact"]
    label: str


class GraphEdgeRef(ContractModel):
    model_config = ConfigDict(extra="allow")
    id: NonEmptyStr
    source_id: NonEmptyStr
    target_id: NonEmptyStr
    relationship: Relationship


class NeighborhoodResult(ContractModel):
    scan_id: NonEmptyStr
    selected_occurrence_id: NonEmptyStr
    direction: Literal["dependents", "dependencies", "both"]
    nodes: list[GraphNodeRef] = Field(max_length=300)
    edges: list[GraphEdgeRef] = Field(max_length=600)
    truncated: bool
    coverage_notice: str


class PathResult(ContractModel):
    scan_id: NonEmptyStr
    module_id: NonEmptyStr
    target_occurrence_id: NonEmptyStr
    status: PathQueryStatus
    node_ids: list[str]
    edge_ids: list[str]
    edge_evidence_ids: list[str]
    truncated: bool

    @model_validator(mode="after")
    def _shape(self) -> "PathResult":
        if self.status == PathQueryStatus.FOUND:
            if not self.node_ids or self.node_ids[0] != self.module_id \
                    or self.node_ids[-1] != self.target_occurrence_id:
                raise ValueError("FOUND path must start at module_id and end at target_occurrence_id")
            if len(self.edge_ids) != len(self.node_ids) - 1:
                raise ValueError("FOUND path needs exactly one edge per hop")
        return self


# ---------------------------------------------------------------------------
# Export / offline validation helpers
# ---------------------------------------------------------------------------

#: Root document models per run artifact.
RUN_FILE_MODELS: dict[str, type[ContractModel]] = {
    "metadata.json": ScanMetadata,
    "module_index.json": ModuleIndex,
    "graph.json": GraphBundle,
    "findings.json": FindingsFile,
    "risk.json": RiskFile,
    "proposals.json": ProposalsFile,
    "validation.json": ValidationResult,
    "report.json": Report,
}
#: JSON-lines artifacts and their per-line models.
RUN_JSONL_MODELS: dict[str, type[ContractModel]] = {
    "evidence.jsonl": Evidence,
    "events.jsonl": Event,
}

EXPORTED_MODELS: tuple[type[ContractModel], ...] = (
    ScanMetadata, StageRecord, ProjectModule, ModuleIndex, Component, DependencyEdge,
    CoverageSummary, GraphBundle, Evidence, Finding, FindingsFile, Claim, RiskAssessment,
    RiskFile, CandidateChange, Proposal, FixAuditResult, ProposalsFile, CommandRecord,
    ValidationResult, ApprovalRecord, Event, Report, NeighborhoodResult, PathResult,
)


def json_schemas() -> dict[str, dict[str, Any]]:
    """JSON Schema (draft 2020-12) for each exported model, keyed by model name."""
    return {m.__name__: m.model_json_schema(mode="validation") for m in EXPORTED_MODELS}


def export_json_schemas(out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, schema in json_schemas().items():
        schema = {"$schema": "https://json-schema.org/draft/2020-12/schema",
                  "$id": f"guardian/{SCHEMA_VERSION}/{name}.schema.json", **schema}
        path = out / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        written.append(path)
    return written


if __name__ == "__main__":  # pragma: no cover - thin CLI
    target = sys.argv[1] if len(sys.argv) > 1 else "docs/contracts"
    for p in export_json_schemas(target):
        print(p.as_posix())
