"""Bounded graph queries over graph.sqlite (Role B, §9.4).

All traversals use a visited set and hard caps; they never enumerate all simple
paths. Only resolved ``DEPENDS_ON`` edges count toward a path; UNRESOLVED
``DECLARES`` edges are ignored so unknown parents are never papered over.
"""

from __future__ import annotations

import json
import sqlite3
import time
from collections import deque
from typing import Any

MAX_VISITED = 200_000
_RESOLVED = "relationship='DEPENDS_ON' AND resolution IN ('OBSERVED','INFERRED')"


def _connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def _node_info(con: sqlite3.Connection, scan_id: str, node_id: str) -> dict[str, Any] | None:
    r = con.execute("SELECT node_id,module_id,package_key,name,version,directness FROM node "
                    "WHERE scan_id=? AND node_id=?", (scan_id, node_id)).fetchone()
    if r:
        return {"node_id": r["node_id"], "kind": "occurrence", "module_id": r["module_id"],
                "package_key": r["package_key"], "name": r["name"], "version": r["version"],
                "directness": r["directness"]}
    m = con.execute("SELECT module_id,relative_path,coverage FROM module WHERE scan_id=? AND module_id=?",
                    (scan_id, node_id)).fetchone()
    if m:
        return {"node_id": m["module_id"], "kind": "module", "module_id": m["module_id"],
                "name": m["relative_path"], "coverage": m["coverage"]}
    return None


def _load_incoming(con: sqlite3.Connection, scan_id: str) -> dict[str, list[tuple[str, str]]]:
    """target -> [(source, edge_id)] for resolved edges; one query per call."""
    inc: dict[str, list[tuple[str, str]]] = {}
    for eid, src, tgt in con.execute(
            f"SELECT edge_id,source,target FROM edge WHERE scan_id=? AND {_RESOLVED} ORDER BY edge_id",
            (scan_id,)):
        inc.setdefault(tgt, []).append((src, eid))
    return inc


def _edge_evidence(con: sqlite3.Connection, scan_id: str, edge_ids: list[str]) -> list[str]:
    ev: list[str] = []
    seen: set[str] = set()
    by_id: dict[str, list[str]] = {}
    for i in range(0, len(edge_ids), 500):
        chunk = edge_ids[i:i + 500]
        q = ",".join("?" * len(chunk))
        for row in con.execute(f"SELECT edge_id,data FROM edge WHERE scan_id=? AND edge_id IN ({q})",
                               (scan_id, *chunk)):
            by_id[row["edge_id"]] = json.loads(row["data"])["evidence_ids"]
    for eid in edge_ids:                       # path order, de-duplicated
        for x in by_id.get(eid, []):
            if x not in seen:
                seen.add(x)
                ev.append(x)
    return ev


def get_dependency_path(db_path: str, scan_id: str, module_id: str, occurrence_id: str) -> dict[str, Any]:
    """Shortest known module-root -> occurrence path (backward BFS, bounded).

    Adjacency is loaded once per call (O(E) rows) instead of one SQL query per
    visited node. ``path_status``: FOUND | NO_KNOWN_PATH | UNRESOLVED.
    ``status`` is NOT_FOUND when the module or occurrence is not in the graph.
    """
    t0 = time.perf_counter()
    con = _connect(db_path)
    try:
        base: dict[str, Any] = {"module_id": module_id, "occurrence_id": occurrence_id,
                                "path_node_ids": [], "path_edge_ids": [], "evidence_ids": [],
                                "truncated": False, "status": "OK"}
        if _node_info(con, scan_id, occurrence_id) is None or _node_info(con, scan_id, module_id) is None:
            return {**base, "status": "NOT_FOUND", "path_status": "UNRESOLVED",
                    "reason": "occurrence or module not in graph", "elapsed_ms": 0.0}
        incoming = _load_incoming(con, scan_id)
        modules = {r[0] for r in con.execute("SELECT module_id FROM module WHERE scan_id=?", (scan_id,))}
        prev: dict[str, tuple[str, str]] = {}      # node -> (child toward target, edge_id)
        seen = {occurrence_id}
        queue: deque[str] = deque([occurrence_id])
        parentless = False
        found = occurrence_id == module_id
        while queue and not found:
            cur = queue.popleft()
            rows = incoming.get(cur, [])
            if not rows and cur != module_id and cur not in modules:
                parentless = True
            for s, eid in rows:
                if s in seen:
                    continue
                seen.add(s)
                prev[s] = (cur, eid)
                if s == module_id:
                    found = True
                    break
                queue.append(s)
            if len(seen) > MAX_VISITED:
                base["truncated"] = True
                break
        ms = round((time.perf_counter() - t0) * 1000, 3)
        if not found:
            status = "UNRESOLVED" if (parentless or base["truncated"]) else "NO_KNOWN_PATH"
            return {**base, "path_status": status, "elapsed_ms": ms,
                    "reason": "truncated at visit bound" if base["truncated"] else
                              "a package on the search frontier has no known declaring parent" if parentless
                              else "no resolved edges connect this module to the occurrence"}
        nodes, edge_ids, cur = [module_id], [], module_id
        while cur != occurrence_id:
            cur, eid = prev[cur]
            nodes.append(cur)
            edge_ids.append(eid)
        return {**base, "path_status": "FOUND", "path_node_ids": nodes, "path_edge_ids": edge_ids,
                "evidence_ids": _edge_evidence(con, scan_id, edge_ids), "hops": len(edge_ids),
                "elapsed_ms": ms}
    finally:
        con.close()


def get_neighbors(db_path: str, scan_id: str, node_id: str, direction: str = "both",
                  depth: int = 1, max_nodes: int = 150) -> dict[str, Any]:
    """Bounded neighborhood. ``direction``: out (dependencies), in (dependents), both."""
    if direction not in ("in", "out", "both"):
        raise ValueError("direction must be 'in', 'out' or 'both'")
    depth = max(0, min(int(depth), 10))
    max_nodes = max(1, min(int(max_nodes), 1000))
    t0 = time.perf_counter()
    con = _connect(db_path)
    try:
        if _node_info(con, scan_id, node_id) is None:
            return {"center": node_id, "nodes": [], "edges": [], "truncated": False,
                    "status": "NOT_FOUND", "elapsed_ms": 0.0}
        nodes = {node_id}
        edges: dict[str, dict[str, Any]] = {}
        frontier = [node_id]
        truncated = False
        for _ in range(depth):
            nxt: list[str] = []
            for cur in frontier:
                qs = []
                if direction in ("out", "both"):
                    qs.append(("source", "target"))
                if direction in ("in", "both"):
                    qs.append(("target", "source"))
                for near, far in qs:
                    rows = con.execute(
                        f"SELECT edge_id,source,target,relationship,resolution,scope FROM edge "
                        f"WHERE scan_id=? AND {near}=? LIMIT ?", (scan_id, cur, max_nodes + 1)).fetchall()
                    for r in rows:
                        other = r[far]
                        if other not in nodes:
                            if len(nodes) >= max_nodes:
                                truncated = True
                                continue
                            nodes.add(other)
                            nxt.append(other)
                        edges[r["edge_id"]] = {"edge_id": r["edge_id"], "source": r["source"],
                                               "target": r["target"], "relationship": r["relationship"],
                                               "resolution": r["resolution"], "scope": r["scope"]}
            frontier = nxt
            if not frontier:
                break
        keep = {k: v for k, v in edges.items() if v["source"] in nodes and v["target"] in nodes}
        infos = [i for i in (_node_info(con, scan_id, n) for n in sorted(nodes)) if i]
        return {"center": node_id, "status": "OK", "nodes": infos, "edges": list(keep.values()),
                "truncated": truncated, "max_nodes": max_nodes,
                "elapsed_ms": round((time.perf_counter() - t0) * 1000, 3)}
    finally:
        con.close()


def get_reverse_impact(db_path: str, scan_id: str, occurrence_id: str, max_modules: int = 100) -> dict[str, Any]:
    """Modules that (transitively) depend on this occurrence's package identity.

    Identity-level: every occurrence sharing ``package_key`` is a start point.
    An occurrence without a package_key is queried by itself only.
    """
    t0 = time.perf_counter()
    con = _connect(db_path)
    try:
        r = con.execute("SELECT package_key FROM node WHERE scan_id=? AND node_id=?",
                        (scan_id, occurrence_id)).fetchone()
        if r is None:
            return {"occurrence_id": occurrence_id, "status": "NOT_FOUND", "modules": [],
                    "affected_occurrence_ids": [], "truncated": False, "elapsed_ms": 0.0}
        starts = [occurrence_id]
        if r["package_key"]:
            starts = [x["node_id"] for x in con.execute(
                "SELECT node_id FROM node WHERE scan_id=? AND package_key=?", (scan_id, r["package_key"]))]
        seen = set(starts)
        queue = deque(starts)
        modules: list[str] = []
        truncated = False
        while queue:
            cur = queue.popleft()
            for e in con.execute(f"SELECT source FROM edge WHERE scan_id=? AND target=? AND {_RESOLVED}",
                                 (scan_id, cur)):
                s = e["source"]
                if s in seen:
                    continue
                seen.add(s)
                if con.execute("SELECT 1 FROM module WHERE scan_id=? AND module_id=?", (scan_id, s)).fetchone():
                    if len(modules) >= max_modules:
                        truncated = True
                        continue
                    modules.append(s)
                else:
                    queue.append(s)
            if len(seen) > MAX_VISITED:
                truncated = True
                break
        return {"occurrence_id": occurrence_id, "package_key": r["package_key"], "status": "OK",
                "modules": sorted(modules), "affected_occurrence_ids": sorted(starts),
                "truncated": truncated, "elapsed_ms": round((time.perf_counter() - t0) * 1000, 3)}
    finally:
        con.close()
