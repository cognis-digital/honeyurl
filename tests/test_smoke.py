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


class TestHardening(unittest.TestCase):
    """Edge-case and error-path tests added during hardening pass."""

    # ------------------------------------------------------------------ core

    def test_verify_token_wrong_sig_length(self):
        """A token whose sig is the wrong length must be rejected, not crash."""
        c = mint_canary(SECRET)
        short_sig = c.token_id + ".abc"       # sig too short
        long_sig = c.token_id + ".abc" * 20   # sig too long
        ok_short, _ = verify_token(SECRET, short_sig)
        ok_long, _ = verify_token(SECRET, long_sig)
        self.assertFalse(ok_short)
        self.assertFalse(ok_long)

    def test_verify_token_empty_and_no_dot(self):
        """Empty or dot-free strings return False without raising."""
        ok1, _ = verify_token(SECRET, "")
        ok2, _ = verify_token(SECRET, "nodothere")
        self.assertFalse(ok1)
        self.assertFalse(ok2)

    def test_mint_canary_empty_base_url_raises(self):
        """mint_canary with an empty base_url must raise ValueError."""
        with self.assertRaises(ValueError):
            mint_canary(SECRET, base_url="")

    def test_match_events_malformed_canary_dicts_skipped(self):
        """Canary entries missing 'token_id' are silently skipped; no KeyError."""
        good = mint_canary(SECRET, label="good")
        bad_entry = {"label": "no-id-here"}  # missing token_id
        reg = {"secret": SECRET, "canaries": [good.to_dict(), bad_entry]}
        # Accessing a real token should still work
        events = match_events(reg, [{"token": good.token}])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].severity, "critical")

    def test_match_events_empty_records(self):
        """An empty records iterable returns an empty list."""
        c = mint_canary(SECRET)
        reg = {"secret": SECRET, "canaries": [c.to_dict()]}
        self.assertEqual(match_events(reg, []), [])

    def test_load_registry_invalid_json(self):
        """load_registry on a non-JSON file raises json.JSONDecodeError."""
        import json as _json
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("not json {{{")
            tmp = fh.name
        try:
            with self.assertRaises(_json.JSONDecodeError):
                from honeyurl.core import load_registry
                load_registry(tmp)
        finally:
            os.unlink(tmp)

    def test_load_registry_canaries_not_list(self):
        """load_registry raises ValueError when 'canaries' is not a list."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            json.dump({"secret": "x", "canaries": "not-a-list"}, fh)
            tmp = fh.name
        try:
            with self.assertRaises(ValueError, msg="canaries must be a list"):
                from honeyurl.core import load_registry
                load_registry(tmp)
        finally:
            os.unlink(tmp)

    # ------------------------------------------------------------------ CLI

    def test_scan_missing_records_file_exit_two(self):
        """scan with a missing records file exits with code 2 (not a traceback)."""
        with tempfile.TemporaryDirectory() as d:
            reg_path = os.path.join(d, "reg.json")
            c = mint_canary(SECRET)
            save_registry(reg_path, SECRET, [c])
            buf = io.StringIO()
            old_err = sys.stderr
            sys.stderr = buf
            try:
                code = main(
                    ["scan", "--registry", reg_path,
                     "--records", os.path.join(d, "does_not_exist.jsonl")]
                )
            finally:
                sys.stderr = old_err
            self.assertEqual(code, 2)
            self.assertIn("error:", buf.getvalue())

    def test_scan_malformed_registry_exit_two(self):
        """scan against a malformed registry JSON exits with code 2."""
        with tempfile.TemporaryDirectory() as d:
            reg_path = os.path.join(d, "bad_reg.json")
            rec_path = os.path.join(d, "rec.jsonl")
            with open(reg_path, "w") as f:
                f.write('{"not_secret": true}')
            with open(rec_path, "w") as f:
                f.write("")
            buf = io.StringIO()
            old_err = sys.stderr
            sys.stderr = buf
            try:
                code = main(
                    ["scan", "--registry", reg_path, "--records", rec_path]
                )
            finally:
                sys.stderr = old_err
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
