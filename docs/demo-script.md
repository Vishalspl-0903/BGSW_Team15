# Bosch Guardian — Day 1 Judge Demo

This script matches the current three-view Streamlit application and the saved,
validated OWASP NodeGoat runs. It does not demonstrate Day 2 remediation.

## Before the presentation

From the repository root, run:

```cmd
py -3.11 -m guardian.cli validate-run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m streamlit run ui\app.py
```

Open `http://localhost:8501`. The UI automatically loads the newest committed
NodeGoat run. Do not run `npm install`, build NodeGoat, or execute its scripts.

## Opening statement

> Guardian statically scans a pinned source revision, builds an evidence-backed
> dependency graph, matches exact resolved package versions to a captured advisory
> database, checks CI configuration, and shows what changed between two commits.
> Unknown or unavailable coverage remains visible instead of being reported as safe.

## View 1 — Dependency graph

1. Select **Dependency graph** in the sidebar.
2. Point to the measured totals:
   - 1,479 package occurrences;
   - 2,296 dependency connections; and
   - one resolved npm module.
3. Explain that the graph contains 1,091 package identities. Occurrences are kept
   separately because the same package identity may appear at multiple lockfile
   locations or dependency paths.
4. Search for a package and select it as the center.
5. Change **Depth** and **Node limit** to demonstrate bounded indexed exploration.
   The UI intentionally displays at most 150 nodes instead of drawing the complete
   supply chain at once.
6. Point out the colors:
   - blue is the module root;
   - green is a direct dependency; and
   - purple is a transitive dependency.
7. Show **Dependency path** and expand **Path evidence and coverage**. Explain that
   the path uses actual saved dependency edges. It is not inferred by an LLM.
8. In **Connection Details**, show the lockfile path and JSON pointer supporting an
   edge.
9. Use **Download SBOM** to show the machine-readable Syft result.

Suggested explanation:

> Syft observed 381 packages while the lockfile parser recovered 1,091 identities.
> Guardian preserves that disagreement. The dependency relationships shown here
> come from supported lockfile evidence and do not claim runtime reachability.

## View 2 — Day 1 findings

1. Select **Day 1 findings**.
2. Show the stage table. The current scan completed intake, inventory, graph,
   advisory intelligence, CI policy and deterministic analysis.
3. State the real totals:
   - 91 confirmed advisory findings; and
   - 6 CI configuration findings.
4. Filter to **CONFIRMED_ADVISORY** and select one finding.
5. Show:
   - the exact package and resolved version;
   - published severity and deterministic priority;
   - affected module and occurrence;
   - the known dependency path;
   - advisory source URLs;
   - uncertainty about reachability and exploitability; and
   - the recommendation as advice, not a validated fix.
6. Expand the evidence record. Point to the scanner name and version, raw artifact,
   source pointer and retained hash.
7. Filter to **CONFIGURATION_WEAKNESS** and select a
   `D5-UNPINNED-ACTION` finding. Show the actual workflow path and mutable action
   reference.
8. State clearly:

> This is a configuration indicator requiring review. It is not evidence that the
> workflow, action or repository is malicious.

9. Show the graph warnings and container limitation. CI workflow inspection is the
   required Day 1 non-source surface; a container image was not built or scanned.
10. Under **Export**, download `report.json`, `report.md` or `graph.json`.

## View 3 — Supply Chain Time Machine

1. Select **Time Machine**.
2. Keep these real scans selected:
   - baseline `91d8adb963f5de15ccadc2b15a1b6aa67c624c4e`; and
   - current `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`.
3. Point to the green message confirming that both commits were checked against the
   same Grype database snapshot: `2026-11-23T06:28:32Z`.
4. Show the real comparison totals:
   - 13 added package occurrences;
   - 8 in-place version changes;
   - 20 source or integrity observation changes;
   - 46 added dependency edges;
   - 22 removed dependency edges; and
   - 5 bounded changed paths.
5. Expand **Added packages**, **Upgrades or downgrades**, **Changed origins** and
   **Added dependency relations**.
6. Show **Changed dependency paths**. Explain that Guardian draws only paths tied to
   changed components instead of redrawing all 1,479 occurrences.
7. State the advisory result accurately:

> Both commits have 91 confirmed advisory findings under the same database
> snapshot. This comparison has zero newly observed advisories, so we do not claim
> that this lockfile change introduced a CVE.

8. Download `supply-chain-comparison.json`.

## Closing statement

> Guardian answers three review questions with saved evidence: what the application
> contains, which exact resolved components match known advisories or CI policy
> rules, and what changed between two pinned source revisions. It remains static and
> honest about unsupported ecosystems, scanner disagreement, runtime reachability,
> container coverage and incomplete stages.

## Required limitations

- `D1` lockfile baseline detector is `NOT_RUN` because the current scan did not use
  `--baseline-ref`. The Time Machine is a separate run-to-run structural comparison.
- A dependency path does not establish runtime execution or exploitability.
- The source scan did not inspect a built container image.
- The 6 CI findings are policy indicators, not malware detections.
- The 91 advisory findings are database matches, not proof of exploitation.
- Day 2 remediation is scaffolded but incomplete. A's validator remains fail-closed,
  B's static fix-audit module is absent, and no approved build/test/rescan case has
  been demonstrated.

## CLI fallback

If Streamlit cannot start, use:

```cmd
py -3.11 -m guardian.cli graph --run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --summary
py -3.11 -m guardian.cli findings --run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli report --run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli compare --baseline runs\nodegoat-baseline\cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb --current runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
```
