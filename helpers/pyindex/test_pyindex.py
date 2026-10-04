"""Tests for pyindex, mirroring goindex/packet_test.go.

A packet stream must be self-describing and uniquely keyed: those two
properties are what every downstream consumer (index, eval join, factory)
depends on, and neither is recoverable after the fact.

Run from the pyindex dir:  python3 -m unittest   (or python3 test_pyindex.py)
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
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


def _parse_stream(out):
    """Split a JSONL stream into (site packets, repo-scoped kind records),
    the same routing rvl_core::parse_stream applies."""
    sites, kinds = [], []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = json.loads(line)  # raises if a line is not valid JSON
        (kinds if rec.get("kind") else sites).append(rec)
    return sites, kinds


def _retrieve_records(*extra):
    code, out, err = _run("--retrieve", "--root", FIXTURE_ROOT, *extra)
    if code != 0:
        raise AssertionError("retrieve failed ({}): {}".format(code, err))
    sites, _ = _parse_stream(out)
    return sites


class TestPacketSchema(unittest.TestCase):
    def test_packet_schema_prints_the_v2_version(self):
        code, out, _ = _run("--packet-schema")
        self.assertEqual(code, 0)
        # Line 1 stays the bare schema integer, so a consumer that reads only
        # the first line of the reply keeps working.
        self.assertEqual(out.splitlines()[0], "2")

    def test_packet_schema_reports_this_files_content_version(self):
        # The handshake (po-8ozxg): rvl compares this value against the copy
        # it ships, and computes it for a script by hashing the file. The two
        # must be the same number or every pyindex reads as drifted.
        _, out, _ = _run("--packet-schema")
        with open(PYINDEX, "rb") as f:
            want = hashlib.sha256(f.read()).hexdigest()[:12]
        self.assertEqual(out.splitlines()[1], "content-version " + want)


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

    def test_chained_attribute_on_constructed_local_resolves(self):
        # po-av01j.133.8: `client = OpenAI(...)` then
        # `client.chat.completions.create(...)`. The receiver's ROOT is a
        # local variable whose type comes from a constructor assignment; the
        # chain must resolve by appending the attribute path to the
        # constructed type. Before the fix this call emitted NO site at all
        # ("create" is ambiguous, so an unresolved receiver is dropped), which
        # made the entire modern LLM SDK surface invisible.
        records = _retrieve_records()
        sites = [
            r for r in records
            if r["client_type"] == "openai.OpenAI.chat.completions"
            and r["func"] == "create"
            and r["provenance"]["client_type_resolved"] is True
        ]
        self.assertTrue(
            sites, "expected resolved openai.OpenAI.chat.completions.create sites")
        # Both spellings of the shape: the local variable and the self attr.
        symbols = {r["symbol"] for r in sites}
        self.assertIn("ask", symbols)

    def test_chained_local_receiver_carries_its_construction(self):
        # The construction (which is where timeout/max_retries live for these
        # SDKs) must be retrievable from the chained call site, exactly as it
        # already is for a bare `session.get`.
        records = _retrieve_records()
        sites = [
            r for r in records
            if r["client_type"] == "openai.OpenAI.chat.completions"
            and r["func"] == "create"
        ]
        self.assertTrue(sites)
        ctor_sources = [
            c["source"] for r in sites for c in r.get("client_construction", [])
        ]
        self.assertTrue(
            any("OpenAI(" in s for s in ctor_sources),
            "construction of the chained client must be retrievable")

    def test_a_local_receiver_carries_only_its_own_functions_construction(self):
        # An assignment inside a function binds a LOCAL, so a same-named
        # variable constructed in another function never reaches this call.
        # Attaching both made `q = queue.Queue()` and `q = queue.Queue(maxsize=10)`
        # indistinguishable at their `q.put` sites (po-av01j.231). A name the
        # function does not assign is the module's, and keeps every
        # construction of it.
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "svc.py"), "w") as f:
                f.write(
                    "import queue\n\n"
                    "shared = queue.Queue(maxsize=3)\n\n\n"
                    "def unbounded(x):\n"
                    "    q = queue.Queue()\n"
                    "    q.put(x)\n\n\n"
                    "def bounded(x):\n"
                    "    q = queue.Queue(maxsize=10)\n"
                    "    q.put(x)\n\n\n"
                    "def module_level(x):\n"
                    "    shared.put(x)\n")
            code, out, err = _run("--retrieve", "--root", root)
            self.assertEqual(code, 0, err)
            sites, _ = _parse_stream(out)
        ctors = {
            r["symbol"]: [c["source"] for c in r["client_construction"]]
            for r in sites if r["func"] == "put"
        }
        self.assertEqual(ctors["unbounded"], ["q = queue.Queue()"])
        self.assertEqual(ctors["bounded"], ["q = queue.Queue(maxsize=10)"])
        self.assertEqual(ctors["module_level"], ["shared = queue.Queue(maxsize=3)"])

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
        # a non-existent file is a loud failure (po-av01j.209): the caller
        # asked for specific files and NONE of them exist here, which must
        # never be recorded as a successful retrieval of zero sites.
        code, out, _ = _run("--retrieve", "--root", FIXTURE_ROOT,
                            "--files", "does_not_exist.py")
        self.assertEqual(code, 2)
        sites, _ = _parse_stream(out)
        self.assertEqual(sites, [], "no site may be invented for a missing file")


class TestRetrievalStatsRecord(unittest.TestCase):
    """The repo-scoped record (po-av01j.209): emitted on EVERY run so rvl's
    silent-zero guard can tell 'ran and found nothing' from 'never ran'."""

    def _stats(self, out):
        _, kinds = _parse_stream(out)
        stats = [r for r in kinds if r["kind"] == "retrieval_stats"]
        self.assertEqual(len(stats), 1,
                         "exactly one retrieval_stats record must ride the "
                         "stream: {}".format(kinds))
        return stats[0]

    def test_stats_record_rides_every_successful_stream(self):
        code, out, err = _run("--retrieve", "--root", FIXTURE_ROOT)
        self.assertEqual(code, 0, err)
        rec = self._stats(out)
        self.assertEqual(rec["packet_schema"], 2)
        self.assertEqual(rec["lang"], "python")
        self.assertGreaterEqual(rec["files_parsed"], 1)
        self.assertEqual(rec["files_total"],
                         rec["files_parsed"] + rec["files_failed"])
        self.assertNotIn("site_key", rec,
                         "the stats record must not count as a site")

    def test_a_tree_with_no_python_files_still_emits_the_record(self):
        # A pyproject.toml-only repo is detected as Python by rvl, and "there
        # is nothing to read" is a real answer -- exit 0, record present.
        import tempfile
        with tempfile.TemporaryDirectory() as empty:
            code, out, err = _run("--retrieve", "--root", empty)
            self.assertEqual(code, 0, err)
            rec = self._stats(out)
            self.assertEqual(rec["files_total"], 0)

    def test_every_file_failing_to_parse_is_a_loud_failure(self):
        # The pyindex twin of the goindex bug: a run that read NOTHING used
        # to exit 0 with zero output, indistinguishable from an empty repo.
        import tempfile
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "broken.py"), "w") as fh:
                fh.write("def broken(:\n")
            code, out, _ = self._run_root(root)
            self.assertEqual(code, 2)
            rec = self._stats(out)
            self.assertEqual(rec["files_failed"], 1)
            self.assertEqual(rec["files_parsed"], 0)

    def test_a_missing_root_is_an_error_not_an_empty_scan(self):
        code, _, err = _run("--retrieve", "--root", "/does/not/exist/anywhere")
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)

    def _run_root(self, root):
        return _run("--retrieve", "--root", root)


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
        # The fixture also exercises the G2/G3 lanes: only records outside the
        # known kinds must stay classic G1 (empty site_kind).
        known_kinds = {"emission_point", "background_job", "server_entry"}
        for r in _retrieve_records():
            if r.get("site_kind") in known_kinds:
                continue
            self.assertFalse(r.get("site_kind"),
                             "G1 packets must not grow a site_kind: {}".format(r))



TESTS_FIXTURE_ROOT = os.path.join(HERE, "testdata", "fixture_tests")

# Every test-convention file in the fixture; each carries one requests.get
# call, so a file that is scanned is a file that produces a site.
FIXTURE_TEST_FILES = [
    "conftest.py",
    "fixtures/data.py",
    "svc/app_test.py",
    "svc/conftest.py",
    "svc/test_app.py",
    "test/unit.py",
    "testing/helpers.py",
    "tests/test_app.py",
]
FIXTURE_PRODUCTION_FILES = [
    "contest/handler.py",
    "svc/app.py",
    "svc/attestation.py",
]


class TestTestPathSkip(unittest.TestCase):
    """Test code is not scanned for API surfaces, the way goindex
    has always skipped _test.go. The skip is COUNTED on the retrieval_stats
    record, never silent, and --include-tests turns it off."""

    def _retrieve(self, *extra):
        code, out, err = _run("--retrieve", "--root", TESTS_FIXTURE_ROOT, *extra)
        self.assertEqual(code, 0, err)
        sites, kinds = _parse_stream(out)
        stats = [r for r in kinds if r["kind"] == "retrieval_stats"]
        self.assertEqual(len(stats), 1, kinds)
        return sites, stats[0]

    def test_is_test_path_matches_the_documented_conventions(self):
        sys.path.insert(0, HERE)
        try:
            import pyindex
        finally:
            sys.path.pop(0)
        for p in FIXTURE_TEST_FILES:
            self.assertTrue(pyindex.is_test_path(p), p)
        # Exact segments and exact basename shapes; a substring is not a
        # convention, so these production names must all be scanned.
        for p in FIXTURE_PRODUCTION_FILES + [
            "src/latest.py",
            "src/protest_handler.py",
            "src/testing_utils.py",
            "src/test_utils/helpers.py",
            "pytest_plugin.py",
        ]:
            self.assertFalse(pyindex.is_test_path(p), p)

    def test_test_paths_are_skipped_counted_and_reported(self):
        sites, stats = self._retrieve()
        self.assertEqual(sorted({r["file_path"] for r in sites}),
                         FIXTURE_PRODUCTION_FILES)
        self.assertEqual(stats["test_files_skipped"], len(FIXTURE_TEST_FILES),
                         "the skip must be counted, never silent: {}".format(stats))
        # NAMED as well as counted: rvl's packet index flags each skipped
        # file so a warm scan can report the repository-wide number from
        # reused entries, not just the files one invocation re-parsed.
        self.assertEqual(sorted(stats["test_files_skipped_paths"]),
                         FIXTURE_TEST_FILES)
        # A skipped file was never attempted, so it is not in files_total:
        # otherwise a tests-only tree reads as "every file failed to parse".
        self.assertEqual(stats["files_total"], len(FIXTURE_PRODUCTION_FILES))

    def test_include_tests_restores_test_paths(self):
        sites, stats = self._retrieve("--include-tests")
        self.assertEqual(sorted({r["file_path"] for r in sites}),
                         sorted(FIXTURE_PRODUCTION_FILES + FIXTURE_TEST_FILES))
        self.assertEqual(stats["test_files_skipped"], 0)
        self.assertEqual(stats["test_files_skipped_paths"], [])
        self.assertEqual(stats["files_total"],
                         len(FIXTURE_PRODUCTION_FILES) + len(FIXTURE_TEST_FILES))

    def test_files_naming_only_a_test_file_is_a_counted_skip_not_an_error(self):
        # The incremental path asks for exactly the changed files. A commit
        # that touches only a test must emit no test sites -- and must NOT
        # trip the "none of the requested --files exist" exit 2, because the
        # file exists; it was skipped on purpose and the record says so.
        sites, stats = self._retrieve("--files", "tests/test_app.py")
        self.assertEqual(sites, [])
        self.assertEqual(stats["test_files_skipped"], 1)
        self.assertEqual(stats["test_files_skipped_paths"], ["tests/test_app.py"])
        sites, stats = self._retrieve("--files", "tests/test_app.py",
                                      "--include-tests")
        self.assertEqual({r["file_path"] for r in sites}, {"tests/test_app.py"})
        self.assertEqual(stats["test_files_skipped"], 0)


GRAPH_ROOT = os.path.join(HERE, "testdata", "fixture_graph")


def _graph_records(*extra):
    code, out, err = _run("--retrieve", "--root", GRAPH_ROOT, *extra)
    if code != 0:
        raise AssertionError("retrieve failed ({}): {}".format(code, err))
    sites, _ = _parse_stream(out)
    return sites


def _site_in(records, symbol, file_path):
    hits = [r for r in records
            if r["symbol"] == symbol and r["file_path"] == file_path]
    if len(hits) != 1:
        raise AssertionError("expected one site in {} ({}), got {}".format(
            symbol, file_path, len(hits)))
    return hits[0]


class TestCallGraph(unittest.TestCase):
    """The caller/callee graph (po-cafdn.3): what v1 emitted as empty arrays.

    testdata/fixture_graph holds a known multi-hop chain,
    main -> run_once -> sync_user -> fetch_profile, across three modules,
    beside one case per rule the walk has to keep."""

    def test_multi_hop_chain_reaches_its_root_across_modules(self):
        site = _site_in(_graph_records(), "fetch_profile", "app/gateway.py")
        # Proximity order: both direct callers first, then each hop outward.
        self.assertEqual([c["symbol"] for c in site["callers"]],
                         ["_warm", "sync_user", "run_once", "main"])
        by_symbol = {c["symbol"]: c for c in site["callers"]}
        self.assertEqual(by_symbol["sync_user"]["file"], "app/service.py")
        self.assertEqual(by_symbol["sync_user"]["line"], 7)
        self.assertIn("return fetch_profile(uid)",
                      by_symbol["sync_user"]["source"])
        prov = site["provenance"]
        self.assertEqual(prov["callers_total"], 4)
        self.assertEqual(prov["callers_included"], 4)
        self.assertEqual(prov["ancestry_depth_searched"], 4)
        self.assertFalse(prov["hit_depth_cap"])
        self.assertFalse(prov["hit_caller_budget"])
        self.assertEqual(sorted(r["symbol"] for r in prov["chain_roots"]),
                         ["_warm", "main"])

    def test_chain_root_carries_structural_facts_not_a_classification(self):
        site = _site_in(_graph_records(), "fetch_profile", "app/gateway.py")
        roots = {r["symbol"]: r for r in site["provenance"]["chain_roots"]}
        self.assertEqual(roots["main"], {
            "symbol": "main",
            "package": "app.main",
            "signature": "def main()",
            "doc": "Run one sync pass and exit.",
            "exported": True,
            "in_package_main": True,
            "referenced_as_value": 0,
            "decorators": [],
        })
        # A leading underscore is the Python spelling of "not exported", and
        # jobs.py has no __main__ guard.
        self.assertFalse(roots["_warm"]["exported"])
        self.assertFalse(roots["_warm"]["in_package_main"])
        self.assertEqual(roots["_warm"]["package"], "app.jobs")

    def test_method_hops_resolve_through_self_and_a_constructed_attribute(self):
        # Gateway.pull <- Syncer._one (self.gw.pull, gw = gateway.Gateway())
        #              <- Syncer.sync_all (self._one) <- run_once
        #              (Syncer().sync_all()) <- main.
        site = _site_in(_graph_records(), "pull", "app/gateway.py")
        self.assertEqual([c["symbol"] for c in site["callers"]],
                         ["Syncer._one", "Syncer.sync_all", "run_once", "main"])
        self.assertEqual(
            [r["symbol"] for r in site["provenance"]["chain_roots"]], ["main"])

    def test_callees_are_the_in_repo_functions_the_enclosing_function_calls(self):
        site = _site_in(_graph_records(), "fetch_with_auth", "app/gateway.py")
        self.assertEqual([c["symbol"] for c in site["callees"]],
                         ["_token", "_headers"])
        self.assertIn('return "t"', site["callees"][0]["source"])
        self.assertEqual(site["callees"][0]["file"], "app/gateway.py")
        prov = site["provenance"]
        self.assertEqual(prov["callees_total"], 2)
        self.assertEqual(prov["callees_included"], 2)
        # Nothing calls fetch_with_auth: it is its own chain root.
        self.assertEqual(site["callers"], [])
        self.assertEqual([r["symbol"] for r in prov["chain_roots"]],
                         ["fetch_with_auth"])

    def test_root_reports_decorators_and_value_references(self):
        site = _site_in(_graph_records(), "refresh_all", "app/jobs.py")
        self.assertEqual([c["symbol"] for c in site["callers"]], ["nightly"])
        (root,) = site["provenance"]["chain_roots"]
        self.assertEqual(root["symbol"], "nightly")
        self.assertEqual(root["decorators"], ["@retrying"])
        # register() hands `nightly` to a scheduler without calling it.
        self.assertEqual(root["referenced_as_value"], 1)
        self.assertEqual(root["doc"], "Refresh everything once a night.")

    def test_a_cycle_terminates_and_reports_no_root(self):
        site = _site_in(_graph_records(), "pong", "app/jobs.py")
        self.assertEqual([c["symbol"] for c in site["callers"]], ["ping"])
        self.assertEqual([c["symbol"] for c in site["callees"]], ["ping"])
        self.assertEqual(site["provenance"]["chain_roots"], [])
        self.assertFalse(site["provenance"]["hit_depth_cap"])

    def test_a_function_that_only_calls_itself_is_its_own_root(self):
        site = _site_in(_graph_records(), "walk", "app/jobs.py")
        self.assertEqual(site["callers"], [])
        self.assertEqual(site["callees"], [])
        self.assertEqual(
            [r["symbol"] for r in site["provenance"]["chain_roots"]], ["walk"])

    def test_caller_budget_truncation_is_reported(self):
        site = _site_in(_graph_records(), "leaf", "app/fanout.py")
        prov = site["provenance"]
        self.assertEqual([c["symbol"] for c in site["callers"]],
                         ["c1", "c2", "c3", "c4"])
        self.assertEqual(prov["callers_total"], 6)
        self.assertEqual(prov["callers_included"], 4)
        self.assertTrue(prov["hit_caller_budget"])
        # The roots are counted over the WHOLE walk, not the emitted slice.
        # `outer` is one of them: its nested def has a parameter named
        # `leaf`, which shadows nothing in `outer` itself.
        self.assertEqual([r["symbol"] for r in prov["chain_roots"]],
                         ["c1", "c2", "c3", "c4", "c5", "outer"])

    def test_unresolved_and_shadowed_calls_make_no_edge(self):
        # `obj.leaf()` on an unknown receiver and `leaf()` on a parameter of
        # that name are not calls of fanout.leaf: abstain, never name-match.
        site = _site_in(_graph_records(), "leaf", "app/fanout.py")
        roots = [r["symbol"] for r in site["provenance"]["chain_roots"]]
        self.assertNotIn("dynamic", roots)
        self.assertNotIn("shadowed", roots)

    def test_depth_cap_truncation_is_reported(self):
        with tempfile.TemporaryDirectory() as root:
            lines = ["import requests", "", "def f0():",
                     "    return requests.post('https://x')", ""]
            for i in range(1, 15):
                lines += ["def f{}():".format(i),
                          "    return f{}()".format(i - 1), ""]
            with open(os.path.join(root, "deep.py"), "w") as fh:
                fh.write("\n".join(lines))
            code, out, err = _run("--retrieve", "--root", root)
            self.assertEqual(code, 0, err)
            (site,) = _parse_stream(out)[0]
        prov = site["provenance"]
        self.assertTrue(prov["hit_depth_cap"])
        self.assertEqual(prov["ancestry_depth_searched"], 12)
        self.assertEqual(prov["callers_total"], 12)
        # The walk stopped before any function with no callers: a truncated
        # search names no root rather than inventing one.
        self.assertEqual(prov["chain_roots"], [])

    def test_ambiguous_import_makes_no_edge(self):
        # Two modules answer to `util`: the import cannot be pinned to one
        # file, so neither `helper` gets the caller.
        with tempfile.TemporaryDirectory() as root:
            for pkg in ("a", "b"):
                os.makedirs(os.path.join(root, pkg))
                with open(os.path.join(root, pkg, "util.py"), "w") as fh:
                    fh.write("import requests\n\n"
                             "def helper():\n"
                             "    return requests.post('https://x')\n")
            with open(os.path.join(root, "run.py"), "w") as fh:
                fh.write("from util import helper\n\n"
                         "def go():\n    return helper()\n")
            code, out, err = _run("--retrieve", "--root", root)
            self.assertEqual(code, 0, err)
            sites = _parse_stream(out)[0]
        self.assertEqual(len(sites), 2)
        for site in sites:
            self.assertEqual(site["callers"], [])
            self.assertEqual(
                [r["symbol"] for r in site["provenance"]["chain_roots"]],
                ["helper"])

    def test_files_filter_emits_the_same_packets_as_a_full_run(self):
        # The incremental path must not hand rvl a different packet for the
        # same site: the graph still spans the whole tree.
        full = [r for r in _graph_records()
                if r["file_path"] == "app/gateway.py"]
        only = _graph_records("--files", "app/gateway.py")
        self.assertTrue(only)
        self.assertEqual(only, full)

    def test_files_filter_stats_count_only_the_requested_files(self):
        code, out, err = _run("--retrieve", "--root", GRAPH_ROOT,
                              "--files", "app/gateway.py")
        self.assertEqual(code, 0, err)
        _, kinds = _parse_stream(out)
        (stats,) = [k for k in kinds if k["kind"] == "retrieval_stats"]
        self.assertEqual(stats["files_total"], 1)
        self.assertEqual(stats["files_parsed"], 1)
        self.assertEqual(stats["files_failed"], 0)

    def test_a_broken_neighbour_does_not_fail_an_incremental_reload(self):
        # A file outside --files that does not parse costs its own edges and
        # nothing else: it is not counted, and the reload stays exit 0.
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "ok.py"), "w") as fh:
                fh.write("import requests\n\n"
                         "def go():\n    return requests.post('https://x')\n")
            with open(os.path.join(root, "broken.py"), "w") as fh:
                fh.write("def (:\n")
            code, out, err = _run("--retrieve", "--root", root,
                                  "--files", "ok.py")
            self.assertEqual(code, 0, err)
            sites, kinds = _parse_stream(out)
        self.assertEqual(len(sites), 1)
        self.assertEqual(kinds[0]["files_failed"], 0)

    def test_test_paths_stay_out_of_the_graph_unless_included(self):
        with tempfile.TemporaryDirectory() as root:
            with open(os.path.join(root, "svc.py"), "w") as fh:
                fh.write("import requests\n\n"
                         "def go():\n    return requests.post('https://x')\n")
            with open(os.path.join(root, "test_svc.py"), "w") as fh:
                fh.write("from svc import go\n\n"
                         "def test_go():\n    return go()\n")
            code, out, err = _run("--retrieve", "--root", root)
            self.assertEqual(code, 0, err)
            (site,) = _parse_stream(out)[0]
            self.assertEqual(site["callers"], [])
            code, out, err = _run("--retrieve", "--root", root,
                                  "--include-tests")
            self.assertEqual(code, 0, err)
            (site,) = _parse_stream(out)[0]
            self.assertEqual([c["symbol"] for c in site["callers"]],
                             ["test_go"])

    def test_site_at_module_scope_has_no_ancestry(self):
        # No enclosing function, so there is nothing to walk up from.
        (site,) = [r for r in _retrieve_records()
                   if r["file_path"] == "svc.py" and r["symbol"] == ""
                   and r.get("site_kind", "") == ""]
        self.assertEqual(site["callers"], [])
        self.assertEqual(site["callees"], [])
        self.assertEqual(site["provenance"]["chain_roots"], [])

    def test_packet_contracts_are_unchanged(self):
        for rec in _graph_records():
            self.assertEqual(rec["packet_schema"], 2)
            self.assertEqual(rec["site_key"], "{}:{}:{}:{}".format(
                rec["file_path"], rec["line_number"], rec["client_type"],
                rec["func"]))
            for snip in rec["callers"] + rec["callees"]:
                self.assertEqual(sorted(snip),
                                 ["file", "line", "source", "symbol"])


# Last statement in the module: `python3 test_pyindex.py` is a documented
# way to run this suite, and unittest.main() only collects classes defined
# ABOVE it.
if __name__ == "__main__":
    unittest.main()
