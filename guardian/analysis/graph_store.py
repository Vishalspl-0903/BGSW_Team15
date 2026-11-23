"""SQLite persistence + indexes for the dependency graph (Role B)."""

from __future__ import annotations

import json
import os
import sqlite3
from typing import Any

SCHEMA = """
CREATE TABLE meta(scan_id TEXT, schema_version TEXT, coverage_summary TEXT, warnings TEXT);
CREATE TABLE module(scan_id TEXT, module_id TEXT, relative_path TEXT, ecosystem TEXT,
                    coverage TEXT, coverage_reason TEXT, data TEXT, PRIMARY KEY(scan_id, module_id));
CREATE TABLE node(scan_id TEXT, node_id TEXT, module_id TEXT, package_key TEXT, name TEXT,
                  version TEXT, directness TEXT, resolution TEXT, data TEXT,
                  PRIMARY KEY(scan_id, node_id));
CREATE TABLE edge(scan_id TEXT, edge_id TEXT, source TEXT, target TEXT, relationship TEXT,
                  resolution TEXT, scope TEXT, module_id TEXT, data TEXT,
                  PRIMARY KEY(scan_id, edge_id));
CREATE INDEX idx_edge_source ON edge(scan_id, source);
CREATE INDEX idx_edge_target ON edge(scan_id, target);
CREATE INDEX idx_node_pkg ON node(scan_id, package_key);
CREATE INDEX idx_node_name ON node(scan_id, name);
"""


def _d(graph: Any) -> dict[str, Any]:
    return graph if isinstance(graph, dict) else graph.model_dump(mode="json")


def write_graph_db(graph: Any, db_path: str) -> None:
    g = _d(graph)
    sid = g["scan_id"]
    ids = [m["module_id"] for m in g["modules"]] + [c["occurrence_id"] for c in g["components"]]
    if len(ids) != len(set(ids)):
        raise ValueError("graph node IDs are not unique")
    if os.path.exists(db_path):
        os.remove(db_path)  # one immutable db per run; rebuilt, never patched
    con = sqlite3.connect(db_path)
    try:
        con.executescript(SCHEMA)
        con.execute("INSERT INTO meta VALUES(?,?,?,?)", (
            sid, g["schema_version"], json.dumps(g["coverage_summary"]), json.dumps(g["warnings"])))
        con.executemany("INSERT INTO module VALUES(?,?,?,?,?,?,?)", [
            (sid, m["module_id"], m["relative_path"], m["ecosystem"], m["coverage"],
             m.get("coverage_reason", ""), json.dumps(m)) for m in g["modules"]])
        con.executemany("INSERT INTO node VALUES(?,?,?,?,?,?,?,?,?)", [
            (sid, c["occurrence_id"], c["module_id"], c["package_key"], c["name"],
             c["resolved_version"], c["directness"], c["resolution"], json.dumps(c)) for c in g["components"]])
        node_ids = set(ids)
        for e in g["edges"]:
            if e["source_id"] not in node_ids or e["target_id"] not in node_ids:
                raise ValueError(f"edge {e['edge_id']} has a dangling endpoint")
        con.executemany("INSERT INTO edge VALUES(?,?,?,?,?,?,?,?,?)", [
            (sid, e["edge_id"], e["source_id"], e["target_id"], e["relationship"], e["resolution"],
             e["dependency_scope"], e.get("module_id"), json.dumps(e)) for e in g["edges"]])
        con.commit()
    finally:
        con.close()
