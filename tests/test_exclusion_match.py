"""Normative SNI/Host precedence and exact-match contract for proxy integration."""

import unittest
from pathlib import Path

from deadbolt.config import Policy
from deadbolt.exclusion_match import body_excluded


class ProxyMatchContractTests(unittest.TestCase):
    def test_shipped_policy_and_active_file_start_empty(self) -> None:
        root = Path(__file__).resolve().parents[1]
        policy = Policy.load(root / "examples/profiles.toml")
        self.assertEqual(policy.body_exclusion_allowed_hosts, ())
        self.assertEqual(policy.emergency_workload_units, ())
        self.assertEqual((root / "examples/body-capture-exclusions.conf").read_text().splitlines()[1:], [])

    def test_sni_is_authoritative_and_host_is_fallback_only_when_absent(self) -> None:
        approved = {"llm.home.arpa"}
        self.assertTrue(body_excluded("llm.home.arpa", "other.example", approved))
        self.assertFalse(body_excluded("other.example", "llm.home.arpa", approved))
        self.assertFalse(body_excluded("", "llm.home.arpa", approved))
        self.assertTrue(body_excluded(None, "llm.home.arpa:443", approved))

    def test_only_exact_normalized_hostnames_match(self) -> None:
        approved = {"llm.home.arpa"}
        self.assertFalse(body_excluded("chat.llm.home.arpa", None, approved))
        self.assertTrue(body_excluded("LLM.HOME.ARPA.", None, approved))
        self.assertFalse(body_excluded(None, "llm.home.arpa.evil.example", approved))
        self.assertFalse(body_excluded(None, "llm.home.arpa:bad", approved))
        self.assertFalse(body_excluded(None, "https://llm.home.arpa", approved))


if __name__ == "__main__":
    unittest.main()
