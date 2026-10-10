"""Exercise the versioned helper against private test files and a fake proxy restart."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "scripts/hermes-body-capture"


class ShippedCaptureHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.config = self.base / "evidence.env"
        self.config.write_text("HERMES_CAPTURE_BODIES=false\n"
                               "HERMES_BODY_CAPTURE_MAX_BYTES=4096\n"
                               "HERMES_BODY_CAPTURE_EXPIRES_AT=0\n")
        self.restarts = self.base / "restarts"
        systemctl = self.base / "systemctl"
        systemctl.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{self.restarts}'\n")
        systemctl.chmod(0o700)
        script = SOURCE.read_text().replace(
            "/etc/hermes-inspection-proxy/evidence.env", str(self.config)).replace(
            "/etc/hermes-inspection-proxy/.body-capture.lock", str(self.base / "lock")).replace(
            "/etc/hermes-inspection-proxy/.evidence.env.XXXXXX", str(self.base / ".evidence.env.XXXXXX")).replace(
            "/usr/bin/systemctl", str(systemctl)).replace(
            "/usr/bin/chown root:root", "/usr/bin/true")
        self.helper = self.base / "helper"
        self.helper.write_text(script)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def call(self, *args: str) -> tuple[subprocess.CompletedProcess[str], dict[str, object] | None]:
        result = subprocess.run(["/bin/sh", str(self.helper), *args], capture_output=True,
                                text=True, timeout=5)
        return result, json.loads(result.stdout) if "--json" in args and result.stdout else None

    def test_enable_replaces_expiry_and_status_disable_are_idempotent(self) -> None:
        result, first = self.call("--json", "enable", "2")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(first["outcome"], "enabled")
        self.assertTrue(first["enabled"])
        first_expiry = datetime.strptime(first["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
        self.assertLessEqual(abs(first_expiry - time.time() - 7200), 2)

        _, second = self.call("--json", "enable", "1")
        second_expiry = datetime.strptime(second["expires_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc).timestamp()
        self.assertLess(second_expiry, first_expiry)
        self.assertLessEqual(abs(second_expiry - time.time() - 3600), 2)
        self.assertIn("HERMES_BODY_CAPTURE_MAX_BYTES=4096", self.config.read_text())
        self.assertEqual(self.call("--json", "status")[1]["outcome"], "status")
        self.assertEqual(self.call("--json", "disable")[1]["outcome"], "disabled")
        self.assertEqual(self.call("--json", "disable")[1]["outcome"], "disabled")
        self.assertEqual(self.call("--json", "status")[1],
                         {"enabled": False, "expires_at": None, "outcome": "status"})
        self.assertEqual(len(self.restarts.read_text().splitlines()), 4)

    def test_invalid_ttl_returns_only_fixed_json(self) -> None:
        for hours in ("0", "25", "1.5", "-1", "1;echo", "01", "999999999999999999"):
            with self.subTest(hours=hours):
                result, response = self.call("--json", "enable", hours)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(response, {"enabled": False, "expires_at": None,
                                            "outcome": "invalid_ttl"})
        self.assertEqual(self.config.read_text().splitlines()[0], "HERMES_CAPTURE_BODIES=false")
        self.assertFalse(self.restarts.exists())

    def test_expiry_timer_and_status_disable_due_or_corrupt_state(self) -> None:
        self.config.write_text("HERMES_CAPTURE_BODIES=true\n"
                               "HERMES_BODY_CAPTURE_MAX_BYTES=4096\n"
                               "HERMES_BODY_CAPTURE_EXPIRES_AT=1\n")
        result, _ = self.call("expire-if-due")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("HERMES_CAPTURE_BODIES=false", self.config.read_text())
        self.assertEqual(len(self.restarts.read_text().splitlines()), 1)
        self.call("expire-if-due")
        self.assertEqual(len(self.restarts.read_text().splitlines()), 1)

        self.config.write_text("HERMES_CAPTURE_BODIES=true\n"
                               "HERMES_BODY_CAPTURE_MAX_BYTES=4096\n"
                               "HERMES_BODY_CAPTURE_EXPIRES_AT=corrupt\n")
        result, response = self.call("--json", "status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(response, {"enabled": False, "expires_at": None, "outcome": "expired"})
        self.assertIn("HERMES_CAPTURE_BODIES=false", self.config.read_text())


if __name__ == "__main__":
    unittest.main()
