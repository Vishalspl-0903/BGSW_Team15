"""Tests for the deterministic synthetic graph generator (Role E)."""

from __future__ import annotations

import json
import unittest
from collections import defaultdict

from eval import contract_checks as cc
from eval import gen_graph


def _has_cycle(graph) -> bool:
    adj = defaultdict(list)
    for e in graph["edges"]:
        adj[e["source_id"]].append(e["target_id"])
    state: dict[str, int] = {}
    for start in list(adj):
        if state.get(start):
            continue
        stack = [(start, iter(adj[start]))]
        state[start] = 1
        while stack:
            node, it = stack[-1]
            nxt = next(it, None)
            if nxt is None:
                state[node] = 2
                stack.pop()
            elif state.get(nxt) == 1:
                return True
            elif not state.get(nxt):
                state[nxt] = 1
                stack.append((nxt, iter(adj[nxt])))
    return False


class GeneratorTests(unittest.TestCase):
    def test_deterministic(self) -> None:
        a = json.dumps(gen_graph.generate(500, seed=3, cycles=2))
        b = json.dumps(gen_graph.generate(500, seed=3, cycles=2))
        c = json.dumps(gen_graph.generate(500, seed=4, cycles=2))
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_contract_valid_and_fully_reachable(self) -> None:
        for size in (100, 1000):
            with self.subTest(size=size):
                graph = gen_graph.generate(size, seed=7, modules=2)
                self.assertEqual(cc.check_graph_bundle(graph, evidence_ids={"ev:syn-lockfile"}), [])
                stats = gen_graph.measure(graph)
                self.assertEqual(stats["nodes"], size)
                self.assertEqual(stats["reached_occurrences"], size)

    def test_cycles_only_when_requested(self) -> None:
        self.assertFalse(_has_cycle(gen_graph.generate(300, seed=7, cycles=0)))
        self.assertTrue(_has_cycle(gen_graph.generate(300, seed=7, cycles=3)))

    def test_ten_thousand_nodes_is_linear_enough(self) -> None:
        graph = gen_graph.generate(10_000, seed=7, cycles=5)
        stats = gen_graph.measure(graph)
        self.assertEqual(stats["reached_occurrences"], 10_000)
        self.assertLess(stats["edges"], 10_000 * 3 + 50)
        self.assertLess(stats["bfs_all_modules_ms"], 5_000)

    def test_shared_identities_exist(self) -> None:
        graph = gen_graph.generate(30, seed=1)
        keys = [c["package_key"] for c in graph["components"]]
        self.assertEqual(len(keys), len(set(keys)))  # every (name, version) distinct here
        names = {c["name"] for c in graph["components"]}
        self.assertLess(len(names), len(keys))       # but names repeat with different versions


if __name__ == "__main__":
    unittest.main()
