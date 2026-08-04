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

    def test_background_job_registrations_carry_site_kind(self):
        """G3 (po-av01j.4): scheduler/queue registrations ride the same packet
        stream marked site_kind="background_job"; classic call sites keep an
        empty site_kind. Detection is import-resolution-driven."""
        records = _retrieve_records()
        for r in records:
            self.assertIn("site_kind", r, "site_kind must be on every packet")
            if r["file_path"] == "svc.py":
                self.assertEqual(r["site_kind"], "",
                                 "classic call sites must stay classic")
        jobs = [r for r in records if r["site_kind"] == "background_job"]

        # Celery decorator registrations, both idioms.
        task = next(r for r in jobs if r["func"] == "task")
        self.assertEqual(task["client_type"], "celery.Celery")
        self.assertEqual(task["symbol"], "rebuild_index")
        shared = next(r for r in jobs if r["func"] == "shared_task")
        self.assertEqual(shared["client_type"], "celery")
        self.assertEqual(shared["symbol"], "prune_old")
        # The decorator facts ride chain_roots so the existing Decorator
        # judgment mechanism downstream can see time_limit=120.
        decs = [d for root in shared["provenance"]["chain_roots"]
                for d in root["decorators"]]
        self.assertTrue(any("time_limit" in d for d in decs), decs)

        # apscheduler cron registration + rq dispatcher + rq worker loop.
        cronreg = next(r for r in jobs if r["func"] == "scheduled_job")
        self.assertTrue(cronreg["client_type"].startswith("apscheduler."),
                        cronreg["client_type"])
        enq = next(r for r in jobs if r["func"] == "enqueue")
        self.assertEqual(enq["client_type"], "rq.Queue")
        loop = next(r for r in jobs if r["func"] == "work")
        self.assertEqual(loop["client_type"], "rq.Worker")

    def test_unresolved_job_lookalikes_are_never_guessed(self):
        """`registry.enqueue(...)` on an unresolved receiver must not be
        emitted at all: type-driven means abstain rather than guess."""
        records = _retrieve_records()
        self.assertFalse(
            [r for r in records if r["symbol"] == "not_a_job"],
            "an unresolved enqueue lookalike must not become a site")
    def test_server_entry_registrations_are_inventoried(self):
        """G2 (po-av01j.3): flask/fastapi/django registrations emit as sites
        stamped site_kind server_entry, with the framework identity as
        client_type and the route path riding const_args. They never ALSO
        emit as G1 client calls."""
        records = _retrieve_records()
        entries = [r for r in records if r.get("site_kind") == "server_entry"]
        g1 = [r for r in records if not r.get("site_kind")]
        self.assertTrue(g1, "G1 sites must still be emitted alongside entries")

        by_ct = {}
        for e in entries:
            by_ct.setdefault(e["client_type"], []).append(e)
        # flask app + blueprint routes, decorator form.
        flask_routes = by_ct.get("flask.Flask", [])
        self.assertTrue(any(e["func"] == "route" and e["symbol"] == "healthz"
                            for e in flask_routes),
                        "expected @app.route('/healthz'): {}".format(entries))
        self.assertTrue(any(e["func"] == "route" for e in
                            by_ct.get("flask.Blueprint", [])),
                        "expected @bp.route('/users')")
        # The path literal rides const_args.
        healthz = next(e for e in flask_routes
                       if e["func"] == "route" and e["symbol"] == "healthz")
        self.assertTrue(any(a["value"] == "'/healthz'"
                            for a in healthz["const_args"]),
                        healthz["const_args"])
        # fastapi verb decorator + middleware forms.
        fastapi_entries = by_ct.get("fastapi.FastAPI", [])
        self.assertTrue(any(e["func"] == "get" and e["symbol"] == "orders"
                            for e in fastapi_entries),
                        "expected @api.get('/orders')")
        for mw in ("middleware", "add_middleware", "include_router"):
            self.assertTrue(any(e["func"] == mw for e in fastapi_entries),
                            "expected a fastapi {} registration".format(mw))
        # flask bare-attribute middleware decorator + call-form url rule.
        self.assertTrue(any(e["func"] == "before_request"
                            for e in flask_routes),
                        "expected @app.before_request")
        self.assertTrue(any(e["func"] == "add_url_rule"
                            for e in flask_routes),
                        "expected app.add_url_rule('/legacy')")
        # django path()/re_path() by import-resolved name.
        django = by_ct.get("django.urls", [])
        self.assertTrue(any(e["func"] == "path" for e in django),
                        "expected a django path() registration")
        self.assertTrue(any(e["func"] == "re_path" for e in django),
                        "expected a django re_path() registration")

        # The registrations never leak into the G1 lane: no G1 record calls a
        # route/middleware verb on a server framework type.
        for r in g1:
            self.assertNotIn(r["client_type"],
                             {"flask.Flask", "flask.Blueprint",
                              "fastapi.FastAPI", "fastapi.APIRouter",
                              "django.urls"},
                             "server registration leaked into G1: {}".format(r))


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


if __name__ == "__main__":
    unittest.main()
