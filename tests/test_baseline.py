"""Durable baseline rules remain separate from approval and expiry state."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from deadbolt.actions import UfwAction
from deadbolt.baseline import BaselineError, ensure, load
from test_deadbolt import FakeUfw


class BaselineTests(unittest.TestCase):
    def test_fixed_rules_and_idempotent_apply(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            path = Path(base) / "baseline.toml"
            path.write_text('[baseline]\ndns_ip="192.168.1.137"\nargus_ip="192.168.1.208"\n')
            # The deployed file must be root-owned; this unit test isolates parsing.
            import unittest.mock
            with unittest.mock.patch("deadbolt.baseline.os.geteuid", return_value=0), \
                 unittest.mock.patch("deadbolt.baseline.Path.lstat") as info, \
                 unittest.mock.patch("deadbolt.baseline.Path.stat") as parent:
                import stat
                info.return_value.st_mode = stat.S_IFREG | 0o600
                info.return_value.st_uid = 0
                parent.return_value.st_mode = stat.S_IFDIR | 0o700
                parent.return_value.st_uid = 0
                rules = load(path)
            self.assertEqual(len(rules), 7)
            fake = FakeUfw()
            action = UfwAction(fake)
            self.assertEqual(len(ensure(rules, apply=False, ufw=action)), 7)
            self.assertEqual(len(ensure(rules, apply=True, ufw=action)), 7)
            self.assertEqual(ensure(rules, apply=True, ufw=action), [])
            self.assertEqual(len(fake.rules), 7)
            self.assertTrue(any("192.168.1.137" in rule and "53" in rule for rule in fake.rules))
            self.assertTrue(any("192.168.1.208" in rule and "3100" in rule for rule in fake.rules))

    def test_rejects_extra_baseline_fields(self) -> None:
        with tempfile.TemporaryDirectory() as base:
            path = Path(base) / "baseline.toml"
            path.write_text('[baseline]\ndns_ip="192.168.1.137"\nargus_ip="192.168.1.208"\nssh=true\n')
            import unittest.mock
            with unittest.mock.patch("deadbolt.baseline.Path.lstat") as info, \
                 unittest.mock.patch("deadbolt.baseline.Path.stat") as parent:
                import stat
                info.return_value.st_mode = stat.S_IFREG | 0o600
                info.return_value.st_uid = 0
                parent.return_value.st_mode = stat.S_IFDIR | 0o700
                parent.return_value.st_uid = 0
                with self.assertRaises(BaselineError):
                    load(path)
