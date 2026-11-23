# Guardian data contract — schema 1.0

Canonical source: `guardian/schemas.py` (owner: Role C). JSON Schema files in this folder are
**generated** (`python -m guardian.cli export-schemas`); a test fails if they drift. Examples in
`examples/` are validated by `tests/c_contracts`. `tests/fixtures/contract_m1` is the shared
SYNTHETIC live fixture (§9.3/§28) and passes `python -m guardian.cli validate-run tests/fixtures/contract_m1`.

## How producers use it

```python
from guardian.schemas import Finding, Evidence, GraphBundle, ScanMetadata  # never redefine these
finding = Finding.model_validate(payload)      # raises on missing/invented fields
json_ready = finding.to_json_dict()            # enums -> strings, UTC timestamps "...Z"
```

* Fields required in §9.2 have no default. Nullable fields must be sent as explicit `null`.
* Unknown keys are **rejected** (`extra="forbid"`). Need a new field? Ask C; it is added here.
* Timestamps: RFC3339 UTC, normalised to `...Z`. Use `guardian.schemas.utc_now()`.
* Paths in `source_path`, `raw_artifact`, `relative_path`, `manifests`, etc. must be relative
  POSIX paths: no `C:\`, `/home/...`, `..`.
* IDs: use `guardian.schemas.stable_id(prefix, *parts)` (sha256 over canonical JSON, §7.2).

## Decisions where §9.2 was silent (please object now if they break you)

| Model.field | Decision |
|---|---|
| String enums in tables (`source_kind`, `kind`, `directness`, `relationship`, …) | Strict enums with exactly the listed values; `relationship` uses §7.1 edge types |
| `Proposal.expected_validation` | `list[str]` |
| `FixAuditResult.*` list fields | `list[str]` |
| `ValidationResult.worktree_id`, `approval_event_id`, `before_sbom_path` | nullable (a BLOCKED result has no approval/worktree) |
| `CommandRecord.exit_code` | nullable (timeout/kill has no exit code) |
| `Report.artifact_paths` | `dict[label, run-relative path]`; validate-run checks each exists |
| `Report.findings_summary` | free JSON object (D decides keys; `null` = unknown, never 0) |
| `proposals.json` root | `{schema_version, scan_id, proposals: [], audit_results: []}` |
| `risk.json` root | `{schema_version, scan_id, assessments: [], claims: []}` |
| Graph query returns (§7.7) | `NeighborhoodResult`, `PathResult` models; B may return dicts that validate |
| `Claim.claim_type` | free string; only types in `guardian.claims` policy can be `VERIFIED` |

## Optional 1.0 additions (default values; nothing breaks if omitted)

| Model | Field | Why |
|---|---|---|
| ScanMetadata | `stage_records: {stage: StageRecord}` | §18.3 explicit stage record (attempted/tool/reason/known_matches, null ≠ 0) |
| Evidence | `supersedes: str \| null` | §9.2 evidence immutability note |
| Finding | `disposition` (default `OPEN`) | §8.1 disposition |
| Event | `workflow_id`, `approval: ApprovalRecord` | §9.6 separate scan/remediation workflows; §6.12 approval bound to `proposal_sha256` |

New helper models: `StageRecord`, `ApprovalRecord`, `CandidateChange`, `CommandRecord`,
`CoverageSummary`, `ModuleIndex`, `FindingsFile`, `RiskFile`, `ProposalsFile`, plus
`proposal_digest(proposal)` (what a human approval binds to) and `WorkflowState` (§9.6 + `INCONCLUSIVE` from §22.3).

## Validation invariants enforced in models

* Factual findings (VULNERABILITY/SUSPICIOUS_CHANGE/CI_POLICY/CONTAINER_POLICY) need `evidence_ids`;
  rule types need `rule_id`; `CONFIRMED_ADVISORY` needs `advisory_ids` and type VULNERABILITY.
* `path_status=FOUND` ⇔ nonempty `dependency_path_node_ids`.
* `resolved_version` may not be a constraint (`^`, `~`, `>=`, `*`, `x`, `latest`); no version ⇒ `package_key=null`.
* `OBSERVED` edges need evidence; validate-run also rejects OBSERVED `DEPENDS_ON` backed by `MODEL_OUTPUT`.
* `StageRecord`: FAILED/UNAVAILABLE/BLOCKED/PARTIAL need a reason; `known_matches` must be `null` unless COMPLETE/PARTIAL.
* `ValidationResult.status=PASS` needs approval, build/tests/rescan true, no new findings, logged exit-0 commands.
* Only a `HUMAN` event may carry an approval; an `LLM` event can never enter REVIEW_PENDING or later states.
* FAILED/BLOCKED `ScanMetadata` must list errors; `LOCAL_FIXTURE` must use `local://fixture/<id>` with `commit_sha=null`.
