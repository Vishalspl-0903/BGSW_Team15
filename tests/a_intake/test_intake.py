from __future__ import annotations

import unittest

from guardian.intake import IntakeError, normalize_repo_url


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


if __name__ == "__main__":
    unittest.main()
