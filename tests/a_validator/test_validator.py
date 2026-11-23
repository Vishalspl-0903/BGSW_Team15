from __future__ import annotations

import unittest

from guardian.validator import ValidationBlocked, validate_approved_proposal


class ValidatorFailClosedTests(unittest.TestCase):
    def test_missing_canonical_approval_interface_blocks_without_mutation(self) -> None:
        with self.assertRaisesRegex(ValidationBlocked, "proposal-hash-bound"):
            validate_approved_proposal("scan", "proposal", "event", "unused")


if __name__ == "__main__":
    unittest.main()
