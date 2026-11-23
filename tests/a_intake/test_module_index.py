from __future__ import annotations

import sys
import hashlib
import tempfile
import types
import unittest
from pathlib import Path

from guardian.module_index import ModuleIndexError, index_modules


class _Model:
    @classmethod
    def model_validate(cls, payload):
        return payload


class ModuleIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.previous = sys.modules.get("guardian.schemas")
        fake = types.ModuleType("guardian.schemas")
        fake.ProjectModule = _Model
        sys.modules["guardian.schemas"] = fake

    def tearDown(self) -> None:
        if self.previous is None:
            sys.modules.pop("guardian.schemas", None)
        else:
            sys.modules["guardian.schemas"] = self.previous

    def test_nested_modules_and_missing_lockfile_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{}", encoding="utf-8")
            nested = root / "services" / "api"
            nested.mkdir(parents=True)
            (nested / "pyproject.toml").write_text("[project]\nname='api'", encoding="utf-8")
            (nested / "poetry.lock").write_text("", encoding="utf-8")
            modules = index_modules("scan-test", str(root))
        self.assertEqual(len(modules), 2)
        npm = next(module for module in modules if module["ecosystem"] == "npm")
        pypi = next(module for module in modules if module["ecosystem"] == "pypi")
        self.assertEqual(npm["coverage"], "DECLARED_ONLY")
        self.assertEqual(pypi["coverage"], "UNSUPPORTED")

    def test_indexing_does_not_modify_source_and_ignores_node_modules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "package.json"
            manifest.write_text('{"name":"root"}', encoding="utf-8")
            ignored = root / "node_modules" / "nested"
            ignored.mkdir(parents=True)
            (ignored / "package.json").write_text('{"name":"ignored"}', encoding="utf-8")
            before = hashlib.sha256(manifest.read_bytes()).hexdigest()
            modules = index_modules("scan-test", str(root))
            after = hashlib.sha256(manifest.read_bytes()).hexdigest()
        self.assertEqual(before, after)
        self.assertEqual(len(modules), 1)
        self.assertEqual(modules[0]["relative_path"], ".")

    @unittest.skipIf(not hasattr(Path, "symlink_to"), "symlinks unavailable")
    def test_symlink_escape_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            (root / "package.json").write_text("{}", encoding="utf-8")
            link = root / "escape"
            try:
                link.symlink_to(Path(outside), target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation not permitted")
            with self.assertRaises(ModuleIndexError):
                index_modules("scan-test", str(root))


if __name__ == "__main__":
    unittest.main()
