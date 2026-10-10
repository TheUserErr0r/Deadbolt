"""Verify proxy logs remain writable through a real logrotate cycle."""

from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest


TEMPLATES = Path(__file__).resolve().parents[1] / "logrotate"


@unittest.skipUnless(shutil.which("logrotate"), "logrotate is required")
class RotationTemplateTests(unittest.TestCase):
    def test_open_log_file_continues_receiving_writes(self) -> None:
        user = pwd.getpwuid(os.getuid()).pw_name
        group = grp.getgrgid(os.getgid()).gr_name
        for template, log_name in (("hermes-proxy", "access.jsonl"),
                                   ("hermes-proxy-evidence", "evidence.jsonl")):
            with self.subTest(template=template), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                log = base / log_name
                config = base / "rotation.conf"
                config.write_text((TEMPLATES / template).read_text().replace(
                    f"/var/log/hermes-proxy/{log_name}", str(log)).replace(
                    "tlsproxy tlsproxy", f"{user} {group}"))
                with log.open("a", encoding="utf-8") as proxy_log:
                    proxy_log.write('before rotation\n')
                    proxy_log.flush()
                    inode = log.stat().st_ino
                    result = subprocess.run(
                        ["logrotate", "--force", "--state", str(base / "state"), str(config)],
                        capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    proxy_log.write('after rotation\n')
                    proxy_log.flush()
                self.assertEqual(log.stat().st_ino, inode)
                self.assertEqual(log.read_text(), 'after rotation\n')
                self.assertEqual((base / f"{log_name}.1").read_text(), 'before rotation\n')


if __name__ == "__main__":
    unittest.main()
