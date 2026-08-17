#!/usr/bin/env python3
# pyindex -- Python retriever helper for rvl.
#
# Retrieval mode: emit the SOURCE that bears on a call site, never a verdict.
# This is the Python sibling of helpers/goindex. It emits the SAME versioned
# packet stream rvl consumes, for Python source instead of Go.
#
# The split this enforces
#
#   Per-language work is RETRIEVAL: mechanical, semantically neutral, no
#   reliability opinion. "Here is the call site." "Here is the client this
#   receiver was constructed from." That is compiler-frontend work and it is
#   genuinely cheap to add per language.
#
#   JUDGEMENT stays semantic -- the LLM panel now, a distilled student later.
#   Nothing here decides whether a call is bounded, retried, or safe. It only
#   reports what exists and where, and how confident the resolution was.
#
# Why stdlib `ast` and not pyright / LibCST
#
#   Python has no compile-time type system to lean on the way Go does, so full
#   type resolution would mean shelling out to a heavyweight external checker
#   (pyright) or a third-party CST library. That trades pinnability and a clean
#   dependency story for resolution we cannot fully trust anyway: Python is
#   dynamically typed, so even a "resolved" receiver is a best-effort inference.
#   We keep the engine in the standard library (`ast`) and make the confidence
#   explicit per site via `provenance.client_type_resolved`. Sites we cannot
#   resolve are still emitted with `client_type: ""` and resolved=False -- a low
#   tier for the panel, not a dropped site.
#
# callers/callees are empty in v1: this helper walks a single file's imports
# and local assignments, it does not build a cross-module call graph. The keys
# are emitted (as empty arrays) so the packet shape is stable and a later
# version can fill them without a schema bump.

import argparse
import ast
import json
import os
import sys

# PACKET_SCHEMA is the version of the emitted packet contract. rvl absorbs
# helper churn behind this number: a consumer that does not know a version
# refuses the stream rather than guessing at its shape. It MUST agree with
# goindex's PacketSchema, tsindex's PACKET_SCHEMA, and rvl_core::PACKET_SCHEMA.
#
# v2 adds const_args (constant-valued arguments at the call site) and
# macro_expansion (always False for Python, which has no macros; mechanical
# for C/C++). v2 is a strict superset of v1.
PACKET_SCHEMA = 2

# Byte cap per emitted snippet, mirroring goindex's maxSnippetBytes. A pathologically
# long function body should not blow up a packet line.
MAX_SNIPPET_BYTES = 2400

# Construction snippets to include per site (mirrors goindex maxCtorsEmitted).
MAX_CTORS_EMITTED = 2

# ---------------------------------------------------------------------------
# Client-detection heuristic.
#
# Python is dynamically typed, so we cannot ask a type checker "is this an HTTP
# client?". Instead we key off the METHOD NAME being called, split into two
# tiers by how likely the name is to also be an ordinary builtin-container or
# string method:
#
#   STRONG_IO_METHODS -- verbs that are almost never methods on a list/dict/str
#     (execute, request, fetchall, ...). We emit these whether or not the
#     receiver type resolved: a `cur.execute(sql)` on an unresolved cursor is
#     still a real DB call site, it just lands as a low-confidence tier.
#
#   WEAK_IO_METHODS -- verbs that collide with builtins (`dict.get`, `str.split`
#     is not here but `get`/`send`/`read` are ambiguous). We emit these ONLY
#     when the receiver resolves to an imported/constructed client, so
#     `requests.get(...)` and `session.get(...)` survive but `somedict.get(k)`
#     is dropped as noise.
#
# Everything else -- `items.append(x)`, `os.path.join(...)`, `s.strip()` -- has
# a method name in neither set and is never emitted. This is a deliberately
# small, conservative allowlist; it favours a resolvable, meaningful set over
# indexing every attribute call in the file.
# ---------------------------------------------------------------------------

STRONG_IO_METHODS = frozenset({
    # HTTP verbs (requests/httpx/urllib3/aiohttp style)
    "request", "post", "put", "patch", "delete", "head", "options",
    # DB drivers / cursors (psycopg2, sqlite3, pymysql, SQLAlchemy)
    "execute", "executemany", "fetchone", "fetchall", "fetchmany",
    # generic RPC / messaging / do-style clients
    "do", "publish", "subscribe",
    # sockets
    "sendall", "recv", "recvfrom",
    # urllib / subprocess
    "urlopen", "check_output", "check_call",
})

WEAK_IO_METHODS = frozenset({
    # ambiguous with builtin containers -- require a resolved receiver
    "get", "send", "connect", "call", "run", "query", "invoke", "read", "write",
    # LLM SDK verbs (po-av01j.133.8). All ambiguous in isolation ("create" is
    # every ORM and factory), so they ride the weak set: only a receiver that
    # RESOLVED to a constructed client emits. openai/anthropic
    # (...completions.create / messages.create), google.genai
    # (generate_content), bedrock (invoke_model / converse).
    "create", "stream", "generate_content", "invoke_model", "converse",
})


def _is_io_method(method, resolved):
    """A call qualifies as a site if its method is a strong I/O verb, or a weak
    one whose receiver resolved to a concrete client type."""
    if method in STRONG_IO_METHODS:
        return True
    if method in WEAK_IO_METHODS and resolved:
        return True
    return False


# ---------------------------------------------------------------------------
# G3 background-job registration surfaces (po-av01j.4).
#
# Schedulers, cron registrations, dispatchers, and worker loops ride the SAME
# packet stream, marked site_kind="background_job". Like the I/O-method
# allowlists this is a RETRIEVAL selection table, not a judgment: it picks
# which sites to surface; whether a registration needs a bound is spec
# knowledge downstream (ApiSpec.site_kinds). Detection is IMPORT-driven -- the
# receiver or decorator must resolve through this module's imports into the
# framework's package -- so a same-named method on an unresolved object is
# never guessed at (abstain-by-omission).
# ---------------------------------------------------------------------------

# Registration/dispatch/loop methods called on a resolved framework object,
# keyed by the ROOT package of the resolved client type.
JOB_CALL_METHODS = {
    "celery": frozenset({"send_task", "add_periodic_task"}),
    "apscheduler": frozenset({"add_job"}),
    "rq": frozenset({"enqueue", "enqueue_call", "enqueue_at", "enqueue_in",
                     "work"}),
}

# Decorator ATTRIBUTES that register the decorated function as background
# work (`@app.task`, `@sched.scheduled_job(...)`), keyed the same way.
JOB_DECORATOR_ATTRS = {
    "celery": frozenset({"task", "periodic_task"}),
    "apscheduler": frozenset({"scheduled_job"}),
}

# Imported NAMES that are themselves registration decorators
# (`from celery import shared_task`): dotted import -> (client_type, method).
JOB_DECORATOR_IMPORTS = {
    "celery.shared_task": ("celery", "shared_task"),
    "celery.task": ("celery", "task"),
}


def _root_package(dotted):
    return dotted.split(".", 1)[0] if dotted else ""


def _is_job_call(method, client_type, resolved):
    """A method call registers/dispatches background work only when its
    receiver RESOLVED to a known scheduler/queue framework type."""
    if not resolved:
        return False
    methods = JOB_CALL_METHODS.get(_root_package(client_type))
    return bool(methods and method in methods)


def _job_decorator(idx, dec):
    """(client_type, method) when `dec` registers the decorated function as
    background work, else None. Both idioms: an attribute decorator on a
    resolved framework object, and a decorator imported from the framework."""
    node = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Attribute):
        client_type, resolved = idx.resolve_receiver(node.value)
        if resolved:
            attrs = JOB_DECORATOR_ATTRS.get(_root_package(client_type))
            if attrs and node.attr in attrs:
                return client_type, node.attr
    elif isinstance(node, ast.Name):
        dotted = idx.imports.get(node.id)
        if dotted in JOB_DECORATOR_IMPORTS:
            return JOB_DECORATOR_IMPORTS[dotted]
    return None
# G2 server-entry detection (po-av01j.3).
#
# Server-entry sites (HTTP handler registrations, route definitions,
# middleware attachments) ride the SAME packet stream, distinguished by the
# additive `site_kind` field. Detection is deliberately conservative: a
# registration is emitted only when the receiver RESOLVES (via imports /
# assignments) to a known framework type, or the called name resolves to a
# django.urls function -- an unresolved `app.get(...)` could as easily be an
# HTTP client, so it abstains from this lane rather than guessing.
# ---------------------------------------------------------------------------

# Mirrors rvl_core::SITE_KIND_SERVER_ENTRY.
SITE_KIND_SERVER_ENTRY = "server_entry"

# Framework types whose route/middleware methods register server entries.
_SERVER_TYPES = frozenset({
    "flask.Flask", "flask.Blueprint", "fastapi.FastAPI", "fastapi.APIRouter",
})

# Route-registration verbs on those types (flask app.route / add_url_rule,
# FastAPI's per-verb decorators and router mounting surface).
_SERVER_ROUTE_METHODS = frozenset({
    "route", "get", "post", "put", "delete", "patch", "options", "head",
    "api_route", "add_api_route", "add_url_rule", "websocket",
})

# Middleware-chain attachment verbs on those types.
_SERVER_MIDDLEWARE_METHODS = frozenset({
    "add_middleware", "middleware", "before_request", "after_request",
    "include_router",
})

# django URL-configuration functions, matched by their import-resolved dotted
# names (a local helper named `path` never matches).
_DJANGO_URL_FUNCS = frozenset({
    "django.urls.path", "django.urls.re_path", "django.conf.urls.url",
})


def _server_entry_target(target, idx):
    """(client_type, method) when `target` -- the callable expression of a call
    or decorator -- is a server-entry registration surface, else None."""
    if isinstance(target, ast.Attribute):
        method = target.attr
        if (method not in _SERVER_ROUTE_METHODS
                and method not in _SERVER_MIDDLEWARE_METHODS):
            return None
        client_type, resolved = idx.resolve_receiver(target.value)
        if resolved and client_type in _SERVER_TYPES:
            return client_type, method
        return None
    if isinstance(target, ast.Name):
        dotted = idx.imports.get(target.id)
        if dotted in _DJANGO_URL_FUNCS:
            mod, name = dotted.rsplit(".", 1)
            return mod, name
    return None


def _server_entry_record(snapshot, file_path, line, symbol, method, client_type,
                         receiver, snippet, body, const_args):
    """One server-entry packet. Same shape as a G1 record plus the site_kind
    stamp; the route path (a literal in the mainstream frameworks) rides the
    existing const_args machinery."""
    return {
        "packet_schema": PACKET_SCHEMA,
        "site_key": "",  # stamped in emit()
        "snapshot_id": snapshot,
        "file_path": file_path,
        "line_number": line,
        "symbol": symbol,
        "func": method,
        "receiver": receiver,
        "client_type": client_type,
        "snippet": snippet,
        "enclosing_function_body": body,
        "callers": [],
        "callees": [],
        "client_construction": [],
        "const_args": const_args,
        "macro_expansion": False,
        "site_kind": SITE_KIND_SERVER_ENTRY,
        "provenance": {
            "client_type_resolved": True,
            "callers_total": 0,
            "callers_included": 0,
            "callees_total": 0,
            "callees_included": 0,
        },
        "lang": "python",
    }

# ---------------------------------------------------------------------------
# Expression rendering
# ---------------------------------------------------------------------------

def expr_to_str(node):
    """Render a receiver expression to its dotted source-ish text.

    Mirrors goindex's exprString: `Name` -> "session", `Attribute` -> "self.client".
    Anything more complex (a call result, a subscript) falls back to the exact
    source segment when available, else "".
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = expr_to_str(node.value)
        if base:
            return base + "." + node.attr
        return node.attr
    # ast.unparse is stdlib (3.9+) and gives a faithful rendering for the rest.
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _root_name(node):
    """Leftmost Name identifier of an attribute chain, or None."""
    while isinstance(node, ast.Attribute):
        node = node.value
    if isinstance(node, ast.Name):
        return node.id
    return None


def _cap(text):
    if text is None:
        return ""
    if len(text) > MAX_SNIPPET_BYTES:
        return text[:MAX_SNIPPET_BYTES] + "\n# ... truncated"
    return text


def _segment(source, node):
    """Exact source text of an AST node (stdlib, 3.8+), byte-capped."""
    try:
        seg = ast.get_source_segment(source, node)
    except Exception:
        seg = None
    return _cap(seg or "")


# ---------------------------------------------------------------------------
# Per-file retrieval
# ---------------------------------------------------------------------------

class FileIndex:
    """Import + assignment tracking for a single Python module.

    Everything is best-effort and module-scoped (no real name scoping): a later
    assignment shadows an earlier one, last write wins. That is unsound in the
    same way goindex's assignedFromDeadline is -- rare in practice, cheaper than
    a full control-flow graph, and recorded here rather than hidden. The panel
    sees the confidence via client_type_resolved and discounts accordingly.
    """

    def __init__(self, source):
        self.source = source
        # name/alias -> dotted client path.  `import requests` -> requests:requests;
        # `from redis import Redis` -> Redis:redis.Redis.
        self.imports = {}
        # local variable name -> resolved client type (`session` -> requests.Session)
        self.var_types = {}
        # "self.<attr>" -> resolved client type (best-effort, keyed across the module)
        self.self_attr_types = {}
        # construction snippets, so a construction-time timeout= is retrievable
        self.ctor_by_var = {}       # var name -> [Snippet]
        self.ctor_by_selfattr = {}  # "self.x" -> [Snippet]
        self.ctor_by_type = {}      # client type -> [Snippet]
        # name -> constant value, from `NAME = <literal>` assignments (schema
        # v2 named-constant resolution). Same module-scoped, last-write-wins
        # best effort as var_types; no deep constant propagation.
        self.const_by_name = {}

    # -- import resolution ---------------------------------------------------

    def collect_imports(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        # `import a.b as c` -> c resolves to a.b
                        self.imports[alias.asname] = alias.name
                    else:
                        # `import a.b.c` binds the top name `a`
                        top = alias.name.split(".")[0]
                        self.imports[top] = top
            elif isinstance(node, ast.ImportFrom):
                if node.module is None:
                    # relative `from . import x` -- no reliable dotted path
                    continue
                for alias in node.names:
                    bound = alias.asname or alias.name
                    self.imports[bound] = node.module + "." + alias.name

    def resolve_ctor(self, func):
        """Resolve a constructor expression to its dotted client type via imports.

        `Redis(...)`           -> redis.Redis   (name imported)
        `requests.Session()`   -> requests.Session (module imported, attr appended)
        `conn.cursor()`        -> None          (conn is not an imported name)
        """
        if isinstance(func, ast.Name):
            return self.imports.get(func.id)
        if isinstance(func, ast.Attribute):
            root = _root_name(func)
            if root is not None and root in self.imports:
                dotted = expr_to_str(func)
                # replace the imported alias root with its resolved module path
                return self.imports[root] + dotted[len(root):]
        return None

    # -- assignment resolution ----------------------------------------------

    def collect_assignments(self, tree):
        for node in ast.walk(tree):
            targets = None
            value = None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            if targets is None:
                continue
            # `NAME = <literal>` feeds named-constant argument resolution
            # (schema v2). Only plain names and literal values: anything
            # computed is not a constant we can cheaply stand behind.
            if isinstance(value, ast.Constant):
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        self.const_by_name[tgt.id] = value.value
                continue
            if not isinstance(value, ast.Call):
                continue
            ctype = self.resolve_ctor(value.func)
            if not ctype:
                continue
            # Whole assignment statement, so an options/kwargs literal carrying a
            # timeout comes along with it.
            snip = {
                "file": None,  # filled by caller (needs the emit-relative path)
                "line": node.lineno,
                "symbol": ctype,
                "source": _segment(self.source, node),
            }
            for tgt in targets:
                if isinstance(tgt, ast.Name):
                    self.var_types[tgt.id] = ctype
                    self.ctor_by_var.setdefault(tgt.id, []).append(snip)
                elif (isinstance(tgt, ast.Attribute)
                      and isinstance(tgt.value, ast.Name)
                      and tgt.value.id == "self"):
                    key = "self." + tgt.attr
                    self.self_attr_types[key] = ctype
                    self.ctor_by_selfattr.setdefault(key, []).append(snip)
            self.ctor_by_type.setdefault(ctype, []).append(snip)

    # -- receiver resolution at a call site ---------------------------------

    def resolve_receiver(self, recv):
        """(client_type, resolved) for a receiver expression, best-effort."""
        if isinstance(recv, ast.Name):
            if recv.id in self.var_types:
                return self.var_types[recv.id], True
            if recv.id in self.imports:
                return self.imports[recv.id], True
            return "", False
        if isinstance(recv, ast.Attribute):
            dotted = expr_to_str(recv)
            if dotted in self.self_attr_types:
                return self.self_attr_types[dotted], True
            # A chain hanging off a constructed self attr:
            # `self.client.chat.completions` resolves via `self.client`,
            # appending the rest of the path to the constructed type.
            if dotted.startswith("self."):
                head = ".".join(dotted.split(".")[:2])  # "self.<attr>"
                if head in self.self_attr_types:
                    return self.self_attr_types[head] + dotted[len(head):], True
            root = _root_name(recv)
            # A chain hanging off a constructed LOCAL: `client.chat.completions`
            # where `client = OpenAI(...)`. This is the shape every modern LLM
            # SDK call takes (openai, anthropic, boto3, google.genai), and it
            # was invisible (po-av01j.133.8): the root is a variable, not an
            # import, so the imports lookup below never matched and ambiguous
            # methods like `create` were then dropped for being unresolved.
            # Same precedence as the bare-Name branch above: a local
            # assignment shadows an imported name.
            if root is not None and root in self.var_types:
                return self.var_types[root] + dotted[len(root):], True
            if root is not None and root in self.imports:
                return self.imports[root] + dotted[len(root):], True
            return "", False
        return "", False

    def constructions_for(self, recv, recv_str, client_type):
        """Construction snippets bearing on this receiver, capped."""
        out = []
        if isinstance(recv, ast.Name) and recv.id in self.ctor_by_var:
            out = self.ctor_by_var[recv.id]
        elif recv_str in self.ctor_by_selfattr:
            out = self.ctor_by_selfattr[recv_str]
        elif (isinstance(recv, ast.Attribute)
              and _root_name(recv) in self.ctor_by_var):
            # Chained receiver on a constructed local (`client.chat.completions`):
            # the construction is where these SDKs put timeout/max_retries, so
            # it must travel with the chained call site too.
            out = self.ctor_by_var[_root_name(recv)]
        elif (recv_str.startswith("self.")
              and ".".join(recv_str.split(".")[:2]) in self.ctor_by_selfattr):
            out = self.ctor_by_selfattr[".".join(recv_str.split(".")[:2])]
        elif client_type and client_type in self.ctor_by_type:
            out = self.ctor_by_type[client_type]
        return out[:MAX_CTORS_EMITTED]


def _const_args(call, idx):
    """Constant-valued arguments at the call site (schema v2).

    Literal tokens report as "literal"; names resolved through the module-level
    constant map report as "named_constant". `index` is the zero-based position
    of the argument as written; `name` is the keyword for keyword arguments,
    "" for positional ones. Values render via repr() (source-level: 5, '5',
    True, None). Retrieval only: no deep constant propagation, and no opinion
    about what a value means — that is spec-layer knowledge.
    """
    def resolve(node):
        if isinstance(node, ast.Constant):
            return repr(node.value), "literal"
        if isinstance(node, ast.Name) and node.id in idx.const_by_name:
            return repr(idx.const_by_name[node.id]), "named_constant"
        return None, None

    out = []
    pos = 0
    for a in call.args:
        value, how = (None, None) if isinstance(a, ast.Starred) else resolve(a)
        if how:
            out.append({"index": pos, "name": "", "value": value, "how": how})
        pos += 1
    for kw in call.keywords:
        # kw.arg is None for a **kwargs expansion: a written argument slot,
        # but not one carrying a per-argument name or constant value.
        value, how = (None, None) if kw.arg is None else resolve(kw.value)
        if how:
            out.append({"index": pos, "name": kw.arg, "value": value, "how": how})
        pos += 1
    return out


# ---------------------------------------------------------------------------
# G4 emission-point inventory (po-av01j.5).
#
# Log statements, span/trace instrumentation, and error-handling sites ride
# the SAME packet stream, stamped site_kind: "emission_point". VOLUME CONTROL
# is the load-bearing constraint: emission packets are AGGREGATES -- one per
# (enclosing function, framework identity, category), with the category and
# call count riding const_args (emission_category / emission_count, how:
# "aggregate") -- never one packet per log line.
#
# Classification is import-resolved like every other receiver in this helper:
# a call is an emission only when its receiver resolves into a known telemetry
# framework. Unresolved receivers are skipped -- abstain rather than guess.
# The framework list is the candidate extractor (like STRONG_IO_METHODS for
# G1): it decides what gets inventoried, never what a match means -- that is
# the spec layer's job (EmissionSpec).
# ---------------------------------------------------------------------------

SITE_KIND_EMISSION = "emission_point"

# Emit-verb allowlists per category: a framework module also exports
# non-emitting surface (logging.getLogger, sentry_sdk.init) that must not
# count as emission calls.
_EMISSION_METHODS = {
    "log": frozenset({
        "debug", "info", "warning", "warn", "error", "exception", "critical",
        "success", "trace", "log", "msg",
    }),
    "trace": frozenset({"start_span", "start_as_current_span"}),
    "error_capture": frozenset({
        "capture_exception", "capture_message", "capture_event",
    }),
}


def _emission_identity(ctype):
    """Map a resolved dotted receiver path to (framework identity, category).

    The identity is NORMALIZED to the framework's canonical surface
    (`logging.getLogger` -> `logging.Logger`) so the spec corpus keys on one
    string per framework. Returns (None, None) for everything else."""
    if not ctype:
        return None, None
    root = ctype.split(".")[0]
    if root == "logging":
        return "logging.Logger", "log"
    if root == "structlog":
        return "structlog", "log"
    if root == "loguru":
        return "loguru.logger", "log"
    if root == "sentry_sdk":
        return "sentry_sdk", "error_capture"
    if root == "opentelemetry":
        return "opentelemetry.trace.Tracer", "trace"
    return None, None


def collect_emissions(tree, source, idx, enclosing, file_path, snapshot):
    """Return the file's emission-point aggregate records.

    Also inventories the SWALLOW fact RC-027's capture-vs-swallow question
    needs: an except handler that neither emits anything recognized nor
    re-raises is an error path with no capture, aggregated per function under
    the `except_handler` identity. A handler that logs, captures, or raises
    is instrumented (or propagating), never a swallow."""
    handler_nodes = [n for n in ast.walk(tree)
                     if isinstance(n, ast.ExceptHandler)]
    contained = {}   # id(node) -> index of the handler containing it
    reraises = []    # per handler: body contains a raise
    for i, h in enumerate(handler_nodes):
        for n in ast.walk(h):
            contained.setdefault(id(n), i)
        reraises.append(any(isinstance(n, ast.Raise) for n in ast.walk(h)))
    handler_emits = [False] * len(handler_nodes)

    aggs = {}  # (symbol, framework, category) -> agg dict
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        method = func.attr
        ctype, _resolved = idx.resolve_receiver(func.value)
        framework, category = _emission_identity(ctype)
        if framework is None or method not in _EMISSION_METHODS[category]:
            continue
        h = contained.get(id(node))
        if h is not None:
            handler_emits[h] = True
            if category == "log":
                # A log emission ON an error path is the capture fact.
                category = "error_capture"
        symbol, _fn = enclosing.get(id(node), ("", None))
        key = (symbol, framework, category)
        agg = aggs.get(key)
        if agg is None:
            aggs[key] = agg = {
                "line": node.lineno,
                "method": method,
                "snippet": _segment(source, node),
                "count": 0,
            }
        agg["count"] += 1

    # Swallowed error paths: no recognized emission, no re-raise.
    for i, h in enumerate(handler_nodes):
        if handler_emits[i] or reraises[i]:
            continue
        symbol, _fn = enclosing.get(id(h), ("", None))
        key = (symbol, "except_handler", "error_capture")
        agg = aggs.get(key)
        if agg is None:
            aggs[key] = agg = {
                "line": h.lineno,
                "method": "except",
                "snippet": "",
                "count": 0,
            }
        agg["count"] += 1

    records = []
    for (symbol, framework, category), agg in sorted(
            aggs.items(), key=lambda kv: kv[1]["line"]):
        records.append({
            "packet_schema": PACKET_SCHEMA,
            "site_key": "",  # stamped in emit(), like every packet
            "site_kind": SITE_KIND_EMISSION,
            "snapshot_id": snapshot,
            "file_path": file_path,
            "line_number": agg["line"],
            "symbol": symbol,
            "func": agg["method"],
            "receiver": "",
            "client_type": framework,
            "snippet": agg["snippet"],
            # Volume control: no function body on aggregates.
            "enclosing_function_body": "",
            "callers": [],
            "callees": [],
            "client_construction": [],
            "const_args": [
                {"index": 0, "name": "emission_category",
                 "value": category, "how": "aggregate"},
                {"index": 0, "name": "emission_count",
                 "value": str(agg["count"]), "how": "aggregate"},
            ],
            "macro_expansion": False,
            "provenance": {
                "client_type_resolved": framework != "except_handler",
                "callers_total": 0,
                "callers_included": 0,
                "callees_total": 0,
                "callees_included": 0,
            },
            "lang": "python",
        })
    return records


def _enclosing_functions(tree):
    """Map every AST node to the innermost enclosing FunctionDef/AsyncFunctionDef.

    Returns {id(node): (func_name, func_node)}. Nodes at module scope are absent.
    """
    mapping = {}

    def visit(node, func_name, func_node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                mapping[id(child)] = (child.name, child)
                # descend with this def as the new enclosing function
                visit(child, child.name, child)
            else:
                if func_node is not None:
                    mapping[id(child)] = (func_name, func_node)
                visit(child, func_name, func_node)

    visit(tree, "", None)
    return mapping


def retrieve_file(abs_path, file_path, snapshot):
    """Parse one Python file and return a list of site records (dicts), or
    None when the file could not be read or parsed.

    None vs [] is the distinction the retrieval_stats record carries
    downstream (po-av01j.209): a file that FAILED is counted, never silently
    collapsed into "parsed and empty"."""
    try:
        with open(abs_path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, UnicodeDecodeError) as err:
        print("skip {}: {}".format(file_path, err), file=sys.stderr)
        return None
    try:
        tree = ast.parse(source, filename=abs_path)
    except SyntaxError as err:
        print("parse failed {}: {}".format(file_path, err), file=sys.stderr)
        return None

    idx = FileIndex(source)
    idx.collect_imports(tree)
    idx.collect_assignments(tree)
    # stamp the emit-relative path onto every construction snippet
    for bucket in (idx.ctor_by_var, idx.ctor_by_selfattr, idx.ctor_by_type):
        for snips in bucket.values():
            for s in snips:
                s["file"] = file_path

    enclosing = _enclosing_functions(tree)

    out = []
    # G2 pre-pass: decorator registrations. @app.route("/x") / @api.get("/y")
    # attach the route to the DECORATED handler, so the record's symbol is the
    # handler and its enclosing body is the handler's source. Registered
    # decorator Call nodes are skipped by the main walk below, or @api.get
    # would ALSO emit as a G1 client call (get is a weak I/O verb on a
    # resolved receiver).
    decorator_nodes = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            target = call.func if call is not None else dec
            se = _server_entry_target(target, idx)
            if se is None:
                continue
            decorator_nodes.add(id(dec))
            client_type, method = se
            recv = target.value if isinstance(target, ast.Attribute) else None
            out.append(_server_entry_record(
                snapshot, file_path, dec.lineno, node.name, method, client_type,
                expr_to_str(recv) if recv is not None else "",
                _segment(source, dec), _segment(source, node),
                _const_args(call, idx) if call is not None else []))

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if id(node) in decorator_nodes:
            continue  # already emitted as a decorator registration
        func = node.func
        # G2 call-form registrations: app.add_middleware(...), app.add_url_rule,
        # api.include_router(...), django's path()/re_path()/url(). Checked
        # BEFORE the G1 gate so a registration never emits as a client call.
        se = _server_entry_target(func, idx)
        if se is not None:
            client_type, method = se
            func_name, func_node = enclosing.get(id(node), ("", None))
            recv = func.value if isinstance(func, ast.Attribute) else None
            out.append(_server_entry_record(
                snapshot, file_path, node.lineno, func_name, method, client_type,
                expr_to_str(recv) if recv is not None else "",
                _segment(source, node),
                _segment(source, func_node) if func_node is not None else "",
                _const_args(node, idx)))
            continue
        if not isinstance(func, ast.Attribute):
            # only receiver.method(...) shapes are call sites
            continue
        method = func.attr
        recv = func.value
        client_type, resolved = idx.resolve_receiver(recv)
        is_job = _is_job_call(method, client_type, resolved)
        if not is_job and not _is_io_method(method, resolved):
            continue

        recv_str = expr_to_str(recv)
        func_name, func_node = enclosing.get(id(node), ("", None))
        line = node.lineno
        snippet = _segment(source, node)
        body = _segment(source, func_node) if func_node is not None else ""
        constructions = idx.constructions_for(recv, recv_str, client_type)

        record = {
            "packet_schema": PACKET_SCHEMA,
            # site_key stamped below in emit(); kept identical to goindex's siteKey
            "site_key": "",
            "snapshot_id": snapshot,
            "file_path": file_path,
            "line_number": line,
            "symbol": func_name,
            "func": method,
            "receiver": recv_str,
            "client_type": client_type,
            "snippet": snippet,
            "enclosing_function_body": body,
            "callers": [],   # empty (no cross-module call graph yet)
            "callees": [],   # empty
            "client_construction": constructions,
            # Schema v2: constant-valued arguments as evidence, and the macro
            # flag (Python has no macros; C/C++ sets it mechanically).
            "const_args": _const_args(node, idx),
            "macro_expansion": False,
            # G3: a resolved scheduler/queue registration is a background-job
            # site; everything else stays the classic call site.
            "site_kind": "background_job" if is_job else "",
            "provenance": {
                "client_type_resolved": resolved,
                "callers_total": 0,
                "callers_included": 0,
                "callees_total": 0,
                "callees_included": 0,
            },
            "lang": "python",
        }
        out.append(record)
    out.extend(_job_decorator_records(tree, idx, source, file_path, snapshot))
    # G4 emission inventory rides the same stream (po-av01j.5).
    out.extend(collect_emissions(tree, source, idx, enclosing, file_path, snapshot))
    return out


def _job_decorator_records(tree, idx, source, file_path, snapshot):
    """Background-job sites registered by DECORATOR (G3): `@app.task`,
    `@shared_task(time_limit=...)`, `@sched.scheduled_job(...)`. The
    registration site is the decorator itself; the decorated function is the
    job body, emitted as the enclosing source. The function's decorators also
    ride provenance.chain_roots as structural facts, so the existing
    decorator-bound judgment mechanism downstream sees a time_limit without
    any new machinery."""
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = ["@" + _segment(source, d) for d in node.decorator_list]
        for dec in node.decorator_list:
            hit = _job_decorator(idx, dec)
            if hit is None:
                continue
            client_type, method = hit
            head = dec.func if isinstance(dec, ast.Call) else dec
            receiver = expr_to_str(
                head.value if isinstance(head, ast.Attribute) else head)
            out.append({
                "packet_schema": PACKET_SCHEMA,
                "site_key": "",  # stamped in emit()
                "snapshot_id": snapshot,
                "file_path": file_path,
                "line_number": dec.lineno,
                "symbol": node.name,
                "func": method,
                "receiver": receiver,
                "client_type": client_type,
                "snippet": "@" + _segment(source, dec),
                "enclosing_function_body": _segment(source, node),
                "callers": [],
                "callees": [],
                "client_construction": [],
                "const_args": _const_args(dec, idx) if isinstance(dec, ast.Call) else [],
                "macro_expansion": False,
                "site_kind": "background_job",
                "provenance": {
                    "client_type_resolved": True,
                    "callers_total": 0,
                    "callers_included": 0,
                    "callees_total": 0,
                    "callees_included": 0,
                    "chain_roots": [{
                        "symbol": node.name,
                        "decorators": decorators,
                    }],
                },
                "lang": "python",
            })
    return out


def site_key(record):
    """Mirror rvl_index::site_key and goindex's siteKey exactly:
    file:line:client_type:method. A file:line is NOT unique -- several client
    calls can share a line -- so downstream joins key on this."""
    return "{}:{}:{}:{}".format(
        record["file_path"], record["line_number"],
        record["client_type"], record["func"])


def emit(records, out=sys.stdout):
    """Stamp schema + site_key on every record and write one JSON object per
    line. One choke point: a record that reaches a consumer unstamped is a
    record no index can key."""
    for rec in records:
        rec["packet_schema"] = PACKET_SCHEMA
        rec["site_key"] = site_key(rec)
        out.write(json.dumps(rec))
        out.write("\n")


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

_SKIP_DIRS = frozenset({
    ".git", "__pycache__", ".venv", "venv", "env", "node_modules",
    "site-packages", ".tox", ".mypy_cache", ".pytest_cache", "build", "dist",
})


def _rel(root, abs_path):
    """Emit-relative path, forward-slashed, matching goindex's filepath.Rel+ToSlash."""
    return os.path.relpath(abs_path, root).replace(os.sep, "/")


def discover(root, files_arg):
    """Yield (abs_path, emit_relative_path) for the files to index.

    With --files, only the listed (repo-relative) files are processed -- the
    incremental reload path. Matching is exact-path (via normpath), never a
    prefix, so a shallow reload of db.py does not pull in db_extra.py.
    """
    if files_arg:
        for raw in files_arg.split(","):
            name = raw.strip()
            if not name:
                continue
            abs_path = name if os.path.isabs(name) else os.path.join(root, name)
            abs_path = os.path.normpath(abs_path)
            if os.path.isfile(abs_path) and abs_path.endswith(".py"):
                yield abs_path, _rel(root, abs_path)
        return
    for dirpath, dirnames, filenames in os.walk(root):
        # prune noise directories in place
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                abs_path = os.path.join(dirpath, fn)
                yield abs_path, _rel(root, abs_path)


def run_retrieve(root, snapshot, files_arg):
    """Retrieve every discovered file. Returns (records, stats) where stats
    counts what was attempted: {"files_total", "files_parsed", "files_failed"}.
    """
    records = []
    total = parsed = failed = 0
    for abs_path, file_path in discover(root, files_arg):
        total += 1
        got = retrieve_file(abs_path, file_path, snapshot)
        if got is None:
            failed += 1
            continue
        parsed += 1
        records.extend(got)
    return records, {
        "files_total": total,
        "files_parsed": parsed,
        "files_failed": failed,
    }


def emit_stats(snapshot, stats, n_sites, out=sys.stdout):
    """The repo-scoped record this helper writes on EVERY run, whether or not
    any site matched (po-av01j.209).

    rvl's silent-zero guard keys on it: a stream with no record rvl recognizes
    means the helper never reached its own emit path -- it bailed early and
    still exited 0, which is exactly the shape that gave a Go repo without the
    Go toolchain a permanently green gate. Site packets alone cannot carry
    that signal, because "no call sites here" is a legitimate, common answer.

    The kind is `retrieval_stats`, following cindex, and deliberately NOT an
    empty `repo_config`: rvl_core::parse_stream folds every repo_config on the
    concatenated polyglot stream into one, so this helper must never put a
    construction-facts record it has no construction facts for on the wire.
    No site_key on purpose -- rvl counts sites by that field."""
    out.write(json.dumps({
        "packet_schema": PACKET_SCHEMA,
        "kind": "retrieval_stats",
        "snapshot_id": snapshot,
        "lang": "python",
        "files_total": stats["files_total"],
        "files_parsed": stats["files_parsed"],
        "files_failed": stats["files_failed"],
        "sites": n_sites,
    }))
    out.write("\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="pyindex",
        description="Python retriever helper: emit rvl's versioned packet "
                    "stream for Python source. Retrieval only, no verdicts.")
    p.add_argument("--packet-schema", action="store_true",
                   help="print the emitted packet schema version and exit")
    p.add_argument("--retrieve", action="store_true",
                   help="emit retrieved SOURCE packets (JSONL) to stdout")
    p.add_argument("--root", default=".",
                   help="repository root to index (default: .)")
    p.add_argument("--name", default=None,
                   help="snapshot id (defaults to the base name of --root)")
    p.add_argument("--files", default="",
                   help="comma-separated repo-relative .py files; emit packets "
                        "only for these (incremental reload path)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    # Lets a consumer negotiate the contract before paying for a load.
    if args.packet_schema:
        print(PACKET_SCHEMA)
        return 0

    if args.retrieve:
        root = os.path.abspath(args.root)
        # A root that is not a directory is a caller error, not an empty repo.
        # os.walk on a missing path silently yields nothing, which used to
        # read as "scanned, zero sites" -- the po-av01j.209 shape.
        if not os.path.isdir(root):
            print("pyindex: --root {} is not a directory".format(root),
                  file=sys.stderr)
            return 2
        snapshot = args.name or os.path.basename(root.rstrip(os.sep)) or root
        records, stats = run_retrieve(root, snapshot, args.files)
        emit(records)
        emit_stats(snapshot, stats, len(records))
        print("{}: {} retrieved sites ({} files, {} failed)".format(
            snapshot, len(records), stats["files_total"],
            stats["files_failed"]), file=sys.stderr)
        # Exit non-zero when NOTHING was read, so the lane degrades loudly
        # instead of recording a successful retrieval of zero sites:
        #   - --files named files that do not exist here (all filtered out);
        #   - every discovered file failed to read or parse.
        # A tree with genuinely zero .py files (a pyproject.toml-only repo)
        # stays exit 0: the stats record proves the helper ran and read the
        # tree, and "nothing to read" is a real answer.
        if args.files.strip(",").strip() and stats["files_total"] == 0:
            print("pyindex: none of the requested --files exist under {}"
                  .format(root), file=sys.stderr)
            return 2
        if stats["files_total"] > 0 and stats["files_parsed"] == 0:
            print("pyindex: every discovered file failed to read or parse; "
                  "no Python source was retrieved", file=sys.stderr)
            return 2
        return 0

    build_parser().print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
