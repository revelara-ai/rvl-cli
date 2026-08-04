"""Tests for pyindex, mirroring goindex/packet_test.go.

A packet stream must be self-describing and uniquely keyed: those two
properties are what every downstream consumer (index, eval join, factory)
depends on, and neither is recoverable after the fact.

Run from the pyindex dir:  python3 -m unittest   (or python3 test_pyindex.py)
"""

import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PYINDEX = os.path.join(HERE, "pyindex.py")
FIXTURE_ROOT = os.path.join(HERE, "testdata", "fixture")


def _run(*args):
    """Invoke the CLI as a subprocess; return (returncode, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, PYINDEX, *args],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _retrieve_records(*extra):
    code, out, err = _run("--retrieve", "--root", FIXTURE_ROOT, *extra)
    if code != 0:
        raise AssertionError("retrieve failed ({}): {}".format(code, err))
    records = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))  # raises if a line is not valid JSON
    return records


class TestPacketSchema(unittest.TestCase):
    def test_packet_schema_prints_the_v2_version(self):
        code, out, _ = _run("--packet-schema")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "2")


class TestRetrievedPackets(unittest.TestCase):
    def test_emits_records_with_schema_and_site_key(self):
        records = _retrieve_records()
        self.assertGreaterEqual(len(records), 1, "expected at least one site")
        for rec in records:
            self.assertEqual(rec["packet_schema"], 2, "packet_schema must be 2")
            self.assertTrue(rec["site_key"], "site_key must be stamped on every packet")
            self.assertEqual(rec["lang"], "python")

    def test_site_keys_unique_and_well_formed(self):
        records = _retrieve_records()
        keys = [r["site_key"] for r in records]
        # site_key is EXACTLY file:line:client_type:method
        for r in records:
            want = "{}:{}:{}:{}".format(
                r["file_path"], r["line_number"], r["client_type"], r["func"])
            self.assertEqual(r["site_key"], want)
        # a file:line is not unique, but the full site_key must be
        self.assertEqual(len(keys), len(set(keys)),
                         "site_key values must be unique: {}".format(keys))

    def test_known_client_call_resolves(self):
        records = _retrieve_records()
        # a requests.get(...) call must resolve to client_type "requests"
        resolved = [
            r for r in records
            if r["client_type"] == "requests" and r["func"] == "get"
            and r["provenance"]["client_type_resolved"] is True
        ]
        self.assertTrue(resolved, "expected a resolved requests.get site")
        # and the redis client too, via `from redis import Redis` + assignment
        redis_sites = [
            r for r in records
            if r["client_type"] == "redis.Redis"
            and r["provenance"]["client_type_resolved"] is True
        ]
        self.assertTrue(redis_sites, "expected a resolved redis.Redis site")

    def test_timeout_or_construction_is_visible(self):
        records = _retrieve_records()
        # bounded call: timeout= must be visible in the call snippet itself
        bounded = [r for r in records if "timeout=5" in r["snippet"]]
        self.assertTrue(bounded, "expected a site with timeout= in its snippet")

        # unbounded session.get: the construction (with its own timeout config)
        # must be reachable via client_construction[*].source
        session_sites = [
            r for r in records
            if r["client_type"] == "requests.Session" and r["symbol"] == "refresh"
        ]
        self.assertTrue(session_sites, "expected the session.get site")
        ctor_sources = [
            c["source"]
            for r in session_sites for c in r["client_construction"]
        ]
        self.assertTrue(
            any("requests.Session()" in s for s in ctor_sources),
            "construction of the session client must be retrievable")

    def test_noise_calls_are_not_emitted(self):
        # items.append(...) and os.path.join(...) must never be sites
        records = _retrieve_records()
        methods = {r["func"] for r in records}
        self.assertNotIn("append", methods)
        self.assertNotIn("join", methods)

    def test_const_args_and_macro_flag(self):
        """Schema v2 (po-av01j.19): constant-valued arguments are evidence,
        and every site carries the macro flag (false: Python has no macros)."""
        records = _retrieve_records()
        for rec in records:
            self.assertIn("const_args", rec, "const_args must be on every packet")
            self.assertIs(rec["macro_expansion"], False,
                          "Python has no macros; macro_expansion must be False")

        def const_by_name(rec, name):
            return next((a for a in rec["const_args"] if a["name"] == name), None)

        # A keyword literal: requests.get(url, timeout=5).
        bounded = next(r for r in records
                       if r["symbol"] == "fetch_user" and r["func"] == "get")
        lit = const_by_name(bounded, "timeout")
        self.assertIsNotNone(lit, bounded["const_args"])
        self.assertEqual(lit["value"], "5")
        self.assertEqual(lit["how"], "literal")

        # A module-level named constant: requests.get(url, timeout=DEFAULT_TIMEOUT).
        named_rec = next(r for r in records
                         if r["symbol"] == "fetch_status" and r["func"] == "get")
        named = const_by_name(named_rec, "timeout")
        self.assertIsNotNone(named, named_rec["const_args"])
        self.assertEqual(named["value"], "30")
        self.assertEqual(named["how"], "named_constant")

        # A positional string literal is a const arg at its written index.
        health = next(r for r in records
                      if r["symbol"] == "" and r["func"] == "get"
                      and "health" in r["snippet"])
        pos = next((a for a in health["const_args"] if a["index"] == 0), None)
        self.assertIsNotNone(pos, health["const_args"])
        self.assertEqual(pos["how"], "literal")

        # A variable argument must NOT be reported: cache.get(key).
        cached = next(r for r in records if r["symbol"] == "cached_lookup")
        self.assertEqual(cached["const_args"], [])

    def test_files_filter_is_exact_path(self):
        # the incremental path emits only the listed file
        records = _retrieve_records("--files", "svc.py")
        self.assertTrue(records)
        for r in records:
            self.assertEqual(r["file_path"], "svc.py")
        # a non-existent file yields nothing (not an error, not everything)
        code, out, _ = _run("--retrieve", "--root", FIXTURE_ROOT,
                            "--files", "does_not_exist.py")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), "")


class TestEmissionPackets(unittest.TestCase):
    """G4 (po-av01j.5): emission points ride the same stream as AGGREGATES —
    one packet per (enclosing function, framework, category), never one per
    log line — stamped site_kind: "emission_point" with category and count
    riding const_args."""

    def _emissions(self):
        return [r for r in _retrieve_records()
                if r.get("site_kind") == "emission_point"]

    def _const(self, rec, name):
        return next((a["value"] for a in rec["const_args"] if a["name"] == name),
                    None)

    def test_log_statements_aggregate_per_function(self):
        emissions = self._emissions()
        self.assertTrue(emissions, "expected emission packets from the fixture")
        chatty = [r for r in emissions
                  if r["symbol"] == "chatty"
                  and r["client_type"] == "logging.Logger"]
        self.assertEqual(len(chatty), 1,
                         "five log calls in one function must be ONE aggregate: "
                         "{}".format(chatty))
        self.assertEqual(self._const(chatty[0], "emission_category"), "log")
        self.assertEqual(self._const(chatty[0], "emission_count"), "5")
        # Shared packet invariants hold for emission packets too.
        self.assertEqual(chatty[0]["packet_schema"], 2)
        self.assertTrue(chatty[0]["site_key"])
        self.assertEqual(chatty[0]["lang"], "python")

    def test_log_in_except_block_is_error_capture(self):
        emissions = self._emissions()
        guarded = [r for r in emissions if r["symbol"] == "guarded"]
        self.assertEqual(len(guarded), 1, guarded)
        self.assertEqual(guarded[0]["client_type"], "logging.Logger")
        self.assertEqual(self._const(guarded[0], "emission_category"),
                         "error_capture")

    def test_swallowing_except_blocks_aggregate_with_count(self):
        emissions = self._emissions()
        swallows = [r for r in emissions
                    if r["client_type"] == "except_handler"]
        self.assertEqual(len(swallows), 1,
                         "only swallowing() has uninstrumented handlers: "
                         "{}".format(swallows))
        self.assertEqual(swallows[0]["symbol"], "swallowing")
        self.assertEqual(self._const(swallows[0], "emission_category"),
                         "error_capture")
        self.assertEqual(self._const(swallows[0], "emission_count"), "2")

    def test_reraising_and_logging_handlers_are_not_swallows(self):
        emissions = self._emissions()
        for r in emissions:
            if r["client_type"] != "except_handler":
                continue
            self.assertNotIn(r["symbol"], ("guarded", "reraising"),
                             "a handler that logs or re-raises is not a swallow")

    def test_sentry_capture_is_error_capture(self):
        emissions = self._emissions()
        captured = [r for r in emissions if r["symbol"] == "captured"]
        self.assertEqual(len(captured), 1, captured)
        self.assertEqual(captured[0]["client_type"], "sentry_sdk")
        self.assertEqual(self._const(captured[0], "emission_category"),
                         "error_capture")

    def test_g1_sites_carry_no_site_kind(self):
        for r in _retrieve_records():
            if r.get("site_kind") == "emission_point":
                continue
            self.assertFalse(r.get("site_kind"),
                             "G1 packets must not grow a site_kind: {}".format(r))


if __name__ == "__main__":
    unittest.main()
