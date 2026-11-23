from __future__ import annotations

import unittest
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
from unittest.mock import patch

from guardian.intake import (
    IntakeError,
    _inspect_snapshot,
    _run_git,
    _safe_ref,
    normalize_repo_url,
)


class NormalizeRepoUrlTests(unittest.TestCase):
    def test_accepts_public_github_repository(self) -> None:
        self.assertEqual(
            normalize_repo_url("https://github.com/example/project"),
            "https://github.com/example/project.git",
        )

    def test_rejects_credentials(self) -> None:
        with self.assertRaises(IntakeError):
            normalize_repo_url("https://user:secret@github.com/example/project")

    def test_rejects_non_github_and_http(self) -> None:
        for value in ("https://example.com/a/b", "http://github.com/a/b"):
            with self.subTest(value=value), self.assertRaises(IntakeError):
                normalize_repo_url(value)

    def test_rejects_path_traversal_and_encoded_paths(self) -> None:
        for value in (
            "https://github.com/a/../b", "https://github.com/a/%2e%2e", "https://github.com/a/b/extra"
        ):
            with self.subTest(value=value), self.assertRaises(IntakeError):
                normalize_repo_url(value)

    def test_rejects_unsafe_git_refs(self) -> None:
        for value in ("--upload-pack=bad", "../main", "main..other", "main@{1}", "bad ref", "a//b"):
            with self.subTest(value=value), self.assertRaises(IntakeError):
                _safe_ref(value)

    def test_git_invocation_disables_redirects_hooks_and_shell(self) -> None:
        completed = CompletedProcess(args=[], returncode=0, stdout="git version test\n", stderr="")
        with patch("guardian.intake.subprocess.run", return_value=completed) as run:
            result = _run_git(["--version"])
        self.assertEqual(result.returncode, 0)
        argv = run.call_args.args[0]
        self.assertIn("http.followRedirects=false", argv)
        self.assertIn("protocol.file.allow=never", argv)
        self.assertTrue(any(value.startswith("core.hooksPath=") for value in argv))
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertGreater(run.call_args.kwargs["timeout"], 0)

    def test_snapshot_hash_is_repeatable_and_does_not_modify_source(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "package.json"
            source.write_text('{"name":"fixture"}', encoding="utf-8")
            before = source.read_bytes()
            first = _inspect_snapshot(root)
            second = _inspect_snapshot(root)
            after = source.read_bytes()
        self.assertEqual(first, second)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
