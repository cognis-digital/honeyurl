"""Smoke tests for HONEYURL. No network access."""

import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeyurl import (  # noqa: E402
    TOOL_NAME, TOOL_VERSION, mint_canary, verify_token, match_events,
    save_registry,
)
from honeyurl.cli import main  # noqa: E402

SECRET = "unit-test-secret"


class TestCore(unittest.TestCase):
    def test_meta(self):
        self.assertEqual(TOOL_NAME, "honeyurl")
        self.assertTrue(TOOL_VERSION)

    def test_mint_is_unique_and_signed(self):
        a = mint_canary(SECRET, label="x")
        b = mint_canary(SECRET, label="y")
        self.assertNotEqual(a.token_id, b.token_id)
        ok, tid = verify_token(SECRET, a.token)
        self.assertTrue(ok)
        self.assertEqual(tid, a.token_id)

    def test_mint_requires_secret(self):
        with self.assertRaises(ValueError):
            mint_canary("")

    def test_bad_signature_rejected(self):
        c = mint_canary(SECRET)
        forged = c.token_id + ".000000000000"
        ok, _ = verify_token(SECRET, forged)
        self.assertFalse(ok)
        ok2, _ = verify_token("different-secret", c.token)
        self.assertFalse(ok2)

    def test_match_classifies_severities(self):
        c = mint_canary(SECRET, label="real")
        reg = {"secret": SECRET, "canaries": [c.to_dict()]}
        records = [
            {"token": c.token, "source_ip": "1.1.1.1"},            # critical
            {"token": c.token_id + ".000000000000"},                # high tamper
            {"line": "no token here, just /healthz"},               # ignored
            {"token": "ffffffffffffffffff.000000000000"},           # info forged
        ]
        events = match_events(reg, records)
        sev = [e.severity for e in events]
        self.assertEqual(sev.count("critical"), 1)
        self.assertEqual(sev.count("high"), 1)
        self.assertEqual(sev.count("info"), 1)
        self.assertEqual(len(events), 3)  # the no-token line yields nothing

    def test_extract_token_from_logline(self):
        c = mint_canary(SECRET)
        reg = {"secret": SECRET, "canaries": [c.to_dict()]}
        line = f'GET /t/{c.token} HTTP/1.1" 200'
        events = match_events(reg, [{"line": line}])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "critical")


class TestCLI(unittest.TestCase):
    def _capture(self, argv):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            code = main(argv)
        finally:
            sys.stdout = old
        return code, buf.getvalue()

    def test_mint_json(self):
        code, out = self._capture(
            ["--format", "json", "mint", "--secret", SECRET, "--count", "2"]
        )
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(len(data["minted"]), 2)

    def test_scan_nonzero_on_findings(self):
        with tempfile.TemporaryDirectory() as d:
            reg_path = os.path.join(d, "reg.json")
            rec_path = os.path.join(d, "rec.jsonl")
            c = mint_canary(SECRET, label="trip")
            save_registry(reg_path, SECRET, [c])
            with open(rec_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"token": c.token, "source_ip": "9.9.9.9"}) + "\n")
            code, out = self._capture(
                ["--format", "json", "scan", "--registry", reg_path,
                 "--records", rec_path]
            )
            self.assertEqual(code, 1)
            data = json.loads(out)
            self.assertEqual(data["findings"], 1)

    def test_scan_clean_is_zero(self):
        with tempfile.TemporaryDirectory() as d:
            reg_path = os.path.join(d, "reg.json")
            rec_path = os.path.join(d, "rec.jsonl")
            c = mint_canary(SECRET)
            save_registry(reg_path, SECRET, [c])
            with open(rec_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"line": "GET /healthz"}) + "\n")
            code, _ = self._capture(
                ["scan", "--registry", reg_path, "--records", rec_path]
            )
            self.assertEqual(code, 0)

    def test_missing_registry_exit_two(self):
        code, _ = self._capture(
            ["scan", "--registry", "nope_12345.json", "--records", "nope.jsonl"]
        )
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
