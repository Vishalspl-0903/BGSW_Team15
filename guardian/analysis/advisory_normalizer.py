"""Advisory normalisation and alias de-duplication (Role E, PROJECT.md 6.6 and 18.1).

Turns raw scanner matches into *observations*, then groups observations that
describe the same issue for the same exact package version.

Grouping rule (no guessing):
    Two advisory ids are joined only when the scanner's own advisory metadata
    links them (Grype ``relatedVulnerabilities``).  Similar titles, similar
    descriptions or equal severities never join anything.  Observations for
    different package identities are never joined.

Every observation is kept inside its group, so no scanner evidence is lost.
This module has no I/O and does not depend on the canonical schemas.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import unquote

# purl type -> ecosystem name used by the graph contract
_PURL_ECOSYSTEM = {"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "go", "cargo": "cargo",
                   "gem": "gem", "nuget": "nuget", "composer": "composer"}
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "moderate": 2, "low": 1, "negligible": 0}


def parse_purl(purl: str | None) -> tuple[str, str, str] | None:
    """``pkg:npm/%40scope/name@1.2.3?q#s`` -> ``("npm", "@scope/name", "1.2.3")``."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body or "@" not in body:
        return None
    ptype, rest = body.split("/", 1)
    name_part, _, version = rest.rpartition("@")
    if not name_part or not version:
        return None
    name = unquote(name_part)
    return _PURL_ECOSYSTEM.get(ptype.lower(), ptype.lower()), name, unquote(version)


def version_key(version: str) -> tuple:
    """Order-only semver-ish key; pre-releases sort before the release."""
    match = re.match(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?", str(version))
    if not match:
        return (0, 0, 0, 0, ())
    pre = match.group(4)
    pre_key = tuple((0, int(p)) if p.isdigit() else (1, p) for p in pre.split(".")) if pre else ()
    return (int(match.group(1)), int(match.group(2) or 0), int(match.group(3) or 0), 0 if pre else 1, pre_key)


def _cvss_base(entries: list[dict[str, Any]] | None) -> tuple[float | None, str | None]:
    """Published CVSS v3.x base score: prefer a 'Primary' record, else the first v3 record."""
    v3 = [e for e in entries or [] if str(e.get("version", "")).startswith("3")]
    if not v3:
        return None, None
    chosen = next((e for e in v3 if str(e.get("type", "")).lower() == "primary"), v3[0])
    score = (chosen.get("metrics") or {}).get("baseScore")
    return (float(score) if score is not None else None), chosen.get("vector")


def observations_from_grype(report: dict[str, Any]) -> list[dict[str, Any]]:
    """One observation per Grype match, with a JSON pointer back into the raw report."""
    observations = []
    for index, match in enumerate(report.get("matches") or []):
        vuln = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        parsed = parse_purl(artifact.get("purl"))
        if parsed is None and artifact.get("name") and artifact.get("version"):
            parsed = (_PURL_ECOSYSTEM.get(str(artifact.get("type")), str(artifact.get("type") or "unknown")),
                      artifact["name"], artifact["version"])
        score, vector = _cvss_base(vuln.get("cvss"))
        fix = vuln.get("fix") or {}
        related = []
        for rel in match.get("relatedVulnerabilities") or []:
            rel_score, rel_vector = _cvss_base(rel.get("cvss"))
            related.append({"id": rel.get("id"), "namespace": rel.get("namespace"), "severity": rel.get("severity"),
                            "cvss_score": rel_score, "cvss_vector": rel_vector, "data_source": rel.get("dataSource")})
        observations.append({
            "pointer": f"/matches/{index}",
            "advisory_id": vuln.get("id"),
            "namespace": vuln.get("namespace"),
            "data_source": vuln.get("dataSource"),
            "severity": vuln.get("severity"),
            "cvss_score": score,
            "cvss_vector": vector,
            "fix_versions": list(fix.get("versions") or []),
            "fix_state": fix.get("state"),
            "description": (vuln.get("description") or "").strip(),
            "related": [r for r in related if r["id"]],
            "package": None if parsed is None else {"ecosystem": parsed[0], "name": parsed[1], "version": parsed[2],
                                                    "purl": artifact.get("purl")},
            "locations": [loc.get("path") for loc in artifact.get("locations") or [] if loc.get("path")],
            "match_types": [d.get("type") for d in match.get("matchDetails") or [] if d.get("type")],
        })
    return observations


def _preferred(ids: list[str]) -> str:
    for prefix in ("CVE-", "GHSA-"):
        hits = sorted(i for i in ids if i.startswith(prefix))
        if hits:
            return hits[0]
    return sorted(ids)[0]


def group_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group observations per exact package identity using verified alias links only."""
    by_package: dict[tuple, list[dict[str, Any]]] = defaultdict(list)
    unmapped = []
    for obs in observations:
        if obs["package"] is None or not obs["advisory_id"]:
            unmapped.append(obs)
            continue
        pkg = obs["package"]
        by_package[(pkg["ecosystem"], pkg["name"], pkg["version"])].append(obs)

    groups = []
    for identity, items in sorted(by_package.items()):
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            parent.setdefault(x, x)
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[max(ra, rb)] = min(ra, rb)

        for obs in items:
            find(obs["advisory_id"])
            for rel in obs["related"]:
                union(obs["advisory_id"], rel["id"])
        members: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for obs in items:
            members[find(obs["advisory_id"])].append(obs)

        for _, group_obs in sorted(members.items()):
            matched_ids = sorted({o["advisory_id"] for o in group_obs})
            alias_ids = sorted({r["id"] for o in group_obs for r in o["related"]} - set(matched_ids))
            primary = group_obs[0]
            severities = {o["advisory_id"]: o["severity"] for o in group_obs if o["severity"]}
            for o in group_obs:
                for r in o["related"]:
                    if r["severity"]:
                        severities.setdefault(r["id"], r["severity"])
            distinct = {str(s).lower() for s in severities.values() if str(s).lower() != "unknown"}
            fixes = sorted({v for o in group_obs if o["fix_state"] == "fixed" for v in o["fix_versions"]}, key=version_key)
            groups.append({
                "package": {"ecosystem": identity[0], "name": identity[1], "version": identity[2],
                            "purl": primary["package"].get("purl")},
                "advisory_ids": matched_ids,
                "aliases": alias_ids,
                "display_id": _preferred(matched_ids + alias_ids),
                "severity_label": None if str(primary["severity"] or "").lower() in {"", "unknown"} else primary["severity"],
                "severity_by_source": severities,
                "severity_conflict": len(distinct) > 1,
                "cvss_score": primary["cvss_score"],
                "cvss_vector": primary["cvss_vector"],
                "fix_versions": fixes,
                "fix_states": sorted({o["fix_state"] for o in group_obs if o["fix_state"]}),
                "urls": sorted({u for o in group_obs for u in [o["data_source"]] + [r["data_source"] for r in o["related"]] if u}),
                "description": primary["description"],
                "match_types": sorted({t for o in group_obs for t in o["match_types"]}),
                "observations": group_obs,
                "alias_basis": "scanner advisory metadata (relatedVulnerabilities)" if alias_ids else None,
            })
    for obs in unmapped:
        groups.append({"package": None, "advisory_ids": [obs["advisory_id"]] if obs["advisory_id"] else [],
                       "aliases": [], "display_id": obs["advisory_id"] or "unknown-advisory",
                       "severity_label": obs["severity"], "severity_by_source": {}, "severity_conflict": False,
                       "cvss_score": obs["cvss_score"], "cvss_vector": obs["cvss_vector"], "fix_versions": [],
                       "fix_states": [], "urls": [obs["data_source"]] if obs["data_source"] else [],
                       "description": obs["description"], "match_types": obs["match_types"],
                       "observations": [obs], "alias_basis": None})
    return groups


def initial_priority(severity_label: str | None) -> str:
    """Day 1 initial priority from the *published* severity only (C re-scores with context).

    P0 is reserved for C's hard escalation rules (KEV, observed behaviour), so a
    scanner severity alone never yields P0.  Missing severity -> NEEDS_REVIEW.
    """
    rank = _SEVERITY_RANK.get(str(severity_label or "").lower())
    if rank is None:
        return "NEEDS_REVIEW"
    if rank >= 3:
        return "P1"
    if rank == 2:
        return "P2"
    return "P3"
