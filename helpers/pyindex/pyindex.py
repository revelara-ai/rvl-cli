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
# callers/callees and chain roots come from a call graph built over the whole
# tree (see CallGraph below), by the same structural resolution as everything
# else here: an edge exists only where a call resolves to exactly one in-repo
# definition. A call that does not resolve makes no edge. The keys were emitted
# as empty arrays in v1 so that filling them needed no schema bump.

import argparse
import ast
import hashlib
import json
import os
import re
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

# Call-graph budgets, mirroring goindex's maxCallersEmitted, maxCalleesEmitted
# and maxChainDepth. A walk that runs into one says so in provenance
# (hit_caller_budget, hit_depth_cap): downstream only reasons from "no bound
# found" when the search was complete.
MAX_CALLERS_EMITTED = 4
MAX_CALLEES_EMITTED = 4
MAX_CHAIN_DEPTH = 12

# How many import / constructor / base-class indirections one name resolution
# follows before it gives up. Bounds re-export chains and import cycles.
MAX_RESOLVE_HOPS = 6

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

    def constructions_for(self, recv, recv_str, client_type, func_node=None):
        """Construction snippets bearing on this receiver, capped.

        A bare-name receiver constructed inside the enclosing function is a
        LOCAL of it, so only that function's constructions reach the call: a
        same-named variable in another function is a different object, and
        attaching its construction made an unbounded `queue.Queue()` and a
        bounded one indistinguishable at their `put` sites (po-av01j.231). A
        name the function does not construct is the module's and keeps every
        construction of it.
        """
        out = []
        if isinstance(recv, ast.Name) and recv.id in self.ctor_by_var:
            out = self.ctor_by_var[recv.id]
            if func_node is not None:
                first = func_node.lineno
                last = getattr(func_node, "end_lineno", None) or first
                local = [c for c in out if first <= c["line"] <= last]
                out = local or out
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


def collect_emissions(tree, source, idx, enclosing, file_path, snapshot,
                      swallowed=None):
    """Return the file's emission-point aggregate records.

    `swallowed`, when given, is a set this fills with the id() of every
    handler counted as a swallow, so the misuse inventory can leave those
    handlers to this lane.

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
        if swallowed is not None:
            swallowed.add(id(h))
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


# ---------------------------------------------------------------------------
# Misuse-shape inventory: error-handling and async shapes that are wrong where
# they stand.
#
# They ride the SAME stream, stamped site_kind: "misuse_shape", as AGGREGATES
# like the emission points: one packet per (enclosing function, class,
# identity), with the class and the count in const_args. Five classes are
# about error handling and async code (the local shapes of retry, query, SQL,
# print and metric code are below, at _local_shapes):
#
#   overbroad_catch    `except Exception`, `except BaseException`, bare
#                      `except:`. Identity: the caught type, or "bare".
#   blocking_in_async  a call to a blocking function, lexically inside an
#                      `async def`. Identity: the dotted callee.
#   sync_over_async    a synchronous wait on async work inside an `async def`.
#   fire_and_forget    `asyncio.create_task(...)` as a statement: nothing
#                      holds the task.
#   missing_await      a coroutine function of this module called as a
#                      statement, or assigned to a name nothing reads.
#
# The retrieval/judgment split holds. Which control a shape violates, and
# which identities are legitimate, is a misuse spec downstream.
#
# Three shapes are kept back here, because each is a different FACT and not a
# legitimate case of the same one:
#
#   - A handler that re-raises. It propagates the error, like the swallow
#     rule in collect_emissions says.
#   - A handler collect_emissions counts as a swallow. That is the emission
#     lane's finding already, and one handler is reported once.
#   - A call inside a lambda or a nested sync def. It runs where that callable
#     is called (run_in_executor, to_thread), not on the event loop.
#
# Detection is IMPORT-RESOLVED for the tables and STRUCTURAL for coroutines:
# a callee is a coroutine only when this module defines it with `async def`,
# at module level or on the enclosing class, under a name nothing else in the
# module or the function binds. There are no types here, so a coroutine
# imported from another module, or a method on another object, is not seen.
# ---------------------------------------------------------------------------

SITE_KIND_MISUSE = "misuse_shape"

# Blocking functions worth surfacing inside an `async def`. Like
# STRONG_IO_METHODS this selects WHICH calls to surface, never what they mean.
# Module-level functions only: a method on a client object needs the
# receiver's type, and the G1 site for that call already carries it.
_BLOCKING_CALLS = frozenset({
    "time.sleep",
    "requests.get", "requests.post", "requests.put", "requests.patch",
    "requests.delete", "requests.head", "requests.options", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.patch", "httpx.delete",
    "httpx.head", "httpx.options", "httpx.request",
    "urllib.request.urlopen",
    "subprocess.run", "subprocess.call", "subprocess.check_call",
    "subprocess.check_output",
    "os.system",
    "socket.create_connection", "socket.getaddrinfo", "socket.gethostbyname",
})

# Synchronous waits on async work, by dotted callee.
_SYNC_WAIT_CALLS = frozenset({"asyncio.run"})

# Calls that start a task. As a statement, the task has no owner.
_TASK_STARTERS = frozenset({"asyncio.create_task", "asyncio.ensure_future"})

_ROOT_EXCEPTIONS = ("BaseException", "Exception")


def _overbroad_type(handler):
    """The root exception type a handler catches, "bare" for `except:`, or
    None for a handler that names only narrower types."""
    t = handler.type
    if t is None:
        return "bare"
    names = [e.id for e in (t.elts if isinstance(t, ast.Tuple) else [t])
             if isinstance(e, ast.Name)]
    for root in _ROOT_EXCEPTIONS:
        if root in names:
            return root
    return None


def _coroutine_names(body):
    """Names a block binds with `async def` and with nothing else."""
    is_async, other = set(), set()
    for stmt in body:
        if isinstance(stmt, ast.AsyncFunctionDef):
            is_async.add(stmt.name)
        elif isinstance(stmt, (ast.FunctionDef, ast.ClassDef)):
            other.add(stmt.name)
        else:
            for n in ast.walk(stmt):
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                    other.add(n.id)
                elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef,
                                    ast.ClassDef)):
                    # A def under `if` or `try`: which one binds is not known.
                    other.add(n.name)
                elif isinstance(n, ast.alias):
                    other.add((n.asname or n.name).split(".")[0])
    return is_async - other


# ---------------------------------------------------------------------------
# Local shapes of the misuse lane that are not about a handler or an await.
# Each class is named for the SHAPE that is read, never for the defect a
# reader may infer from it:
#
#   retry_shape            a wait on the failure path of an attempt loop, or a
#                          retry-library config. Identity: constant_delay,
#                          no_jitter or unbounded_attempts.
#   loop_variable_query    a query method called on a relation of a loop
#                          variable (`for c in cs: c.orders.all()`). Identity:
#                          the method.
#   sql_concat_in_call     an `execute` call whose SQL argument is built in
#                          that same expression. Identity: the method.
#   print_logging          a call of the builtin `print` to a standard stream.
#   latency_scalar_metric  a Prometheus Gauge or Counter registered with a
#                          latency name. Identity: the constructor.
#
# What each rule does NOT see is part of the rule:
#
#   - retry_shape reads the delay expression and does not guess intent. An
#     attempt loop is a `while`, or a `for` over `range(...)`. A `for` over a
#     collection gives each item one attempt. The wait must be in an `except`
#     handler, or after a `try` that leaves the loop on success: a sleep
#     anywhere else is a poll interval. A delay that a function computes has
#     no shape in this expression, and is not reported.
#   - loop_variable_query is NOT the N+1 defect. It is the one form of it that
#     one function shows: the loop and the query are in the same function and
#     the receiver is the loop variable. There are no types, so the method
#     name is the only evidence that the call is a query. A query in a helper
#     that the loop calls is not seen.
#   - sql_concat_in_call is the same-expression form only. SQL text built in
#     one statement and run in another needs data flow, and is not claimed.
#   - print_logging is `print` only. A call on the `logging` module is a log
#     emission in collect_emissions, and one line cannot be both.
# ---------------------------------------------------------------------------

# Method names that load rows from an ORM relation. `count` and `get` are left
# out: `str.count` and `dict.get` are far more common than the query forms.
_QUERY_METHODS = frozenset({
    "all", "filter", "filter_by", "exclude", "first", "last", "exists",
    "order_by", "values", "values_list", "select_related", "prefetch_related",
    "aggregate", "annotate",
})

_SQL_EXEC_METHODS = frozenset({"execute", "executemany", "executescript"})

# Wrappers that mark a string as SQL text and pass it through.
_SQL_TEXT_WRAPPERS = frozenset({
    "sqlalchemy.text", "sqlalchemy.sql.text", "sqlalchemy.sql.expression.text",
})

_SCALAR_METRICS = frozenset({"prometheus_client.Gauge", "prometheus_client.Counter"})

# A metric name that says it measures latency. A bare `_seconds` is not
# enough: `process_cpu_seconds_total` is a correct counter.
_LATENCY_NAME = re.compile(r"latency|duration|response_time|elapsed", re.I)

_SLEEP_CALLS = frozenset({"time.sleep", "asyncio.sleep"})

_TENACITY_RETRY = frozenset({
    "tenacity.retry", "tenacity.Retrying", "tenacity.AsyncRetrying",
})
_TENACITY_GROWING = frozenset({"wait_exponential", "wait_incrementing", "wait_chain"})
_TENACITY_CONSTANT = frozenset({"wait_fixed", "wait_none"})

# Arithmetic builtins a delay expression can use and keep its shape visible.
_DELAY_BUILTINS = frozenset({"min", "max", "float", "int", "pow", "abs"})


def _is_text(e):
    return isinstance(e, ast.JoinedStr) or (
        isinstance(e, ast.Constant) and isinstance(e.value, str))


def _built_sql(idx, e):
    """Whether a SQL argument is put together where it stands from a part
    that is not a constant: a concatenation, an f-string with a value, a `%`
    format or `str.format`."""
    if isinstance(e, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in e.values)
    if isinstance(e, ast.BinOp):
        left, right = e.left, e.right
        if isinstance(e.op, ast.Mod):
            return _is_text(left)
        if isinstance(e.op, ast.Add):
            return (_built_sql(idx, left) or _built_sql(idx, right)
                    or (_is_text(left) and not isinstance(right, ast.Constant))
                    or (_is_text(right) and not isinstance(left, ast.Constant)))
        return False
    if isinstance(e, ast.Call):
        func = e.func
        if (isinstance(func, ast.Attribute) and func.attr == "format"
                and _is_text(func.value)):
            return bool(e.args or e.keywords)
        if idx.resolve_ctor(func) in _SQL_TEXT_WRAPPERS and e.args:
            return _built_sql(idx, e.args[0])
    return False


def _relation_root(func):
    """`c.orders.all` -> "c". None unless the receiver is an attribute chain
    of at least one relation on a plain name."""
    v = func.value
    if not isinstance(v, ast.Attribute):
        return None
    while isinstance(v, ast.Attribute):
        v = v.value
    return v.id if isinstance(v, ast.Name) else None


def _loop_nodes(loop):
    """The nodes of a loop that run on its terms: not the functions and the
    inner loops in it."""
    stack = list(ast.iter_child_nodes(loop))
    while stack:
        n = stack.pop()
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                          ast.For, ast.AsyncFor, ast.While)):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def _retry_loop(loop, idx, note):
    """Report the delay shape of an attempt loop."""
    waits = []

    def sleep_call(stmt):
        v = stmt.value if isinstance(stmt, ast.Expr) else None
        if isinstance(v, ast.Await):
            v = v.value
        if (isinstance(v, ast.Call) and len(v.args) == 1
                and idx.resolve_ctor(v.func) in _SLEEP_CALLS):
            return v
        return None

    def leaves(stmts):
        return any(isinstance(s, (ast.Return, ast.Break)) for s in stmts)

    def walk(stmts, on_fail):
        for s in stmts:
            call = sleep_call(s)
            if call is not None:
                if on_fail:
                    waits.append(call)
            elif isinstance(s, ast.Try):
                walk(s.body, on_fail)
                for h in s.handlers:
                    walk(h.body, True)
                walk(s.orelse, on_fail)
                walk(s.finalbody, on_fail)
                if s.handlers and (leaves(s.body) or leaves(s.orelse)):
                    # What follows runs only after a failed attempt.
                    on_fail = True
            elif isinstance(s, ast.If):
                walk(s.body, on_fail)
                walk(s.orelse, on_fail)
            elif isinstance(s, (ast.With, ast.AsyncWith)):
                walk(s.body, on_fail)

    walk(loop.body, False)
    if not waits:
        return

    # What the loop says about its own variables: the ones it changes in
    # place, and every value it assigns.
    mutated, defs = set(), {}
    if isinstance(loop, ast.For):
        mutated.update(n.id for n in ast.walk(loop.target)
                       if isinstance(n, ast.Name))
    for n in _loop_nodes(loop):
        if isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name):
            mutated.add(n.target.id)
            defs.setdefault(n.target.id, []).append(n.value)
        elif (isinstance(n, ast.Assign) and len(n.targets) == 1
                and isinstance(n.targets[0], ast.Name)):
            defs.setdefault(n.targets[0].id, []).append(n.value)

    def shape(e, resolving, out):
        for n in ast.walk(e):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                # A variable whose value depends on itself varies.
                if n.id in mutated or n.id in resolving:
                    out.add("varying")
                if n.id not in resolving and n.id in defs:
                    resolving.add(n.id)
                    for d in defs[n.id]:
                        shape(d, resolving, out)
                    resolving.discard(n.id)
            elif isinstance(n, ast.Call):
                dotted = idx.resolve_ctor(n.func) or ""
                top = dotted.split(".")[0]
                if top in ("random", "secrets"):
                    out.add("random")
                elif top == "math" or (
                        isinstance(n.func, ast.Name)
                        and n.func.id in _DELAY_BUILTINS
                        and n.func.id not in idx.imports):
                    pass  # arithmetic: the shape is in the arguments
                else:
                    out.add("opaque")

    counters = set(mutated)
    for call in waits:
        out = set()
        shape(call.args[0], set(), out)
        if "opaque" in out or "random" in out:
            continue
        identity = "no_jitter" if "varying" in out else "constant_delay"
        note(call, "retry_shape", identity, "sleep")
    for name in defs:
        out = set()
        shape(ast.Name(id=name, ctx=ast.Load()), set(), out)
        if "varying" in out:
            counters.add(name)

    # `while True` with no test of a counter that leaves the loop.
    if not (isinstance(loop, ast.While) and isinstance(loop.test, ast.Constant)
            and loop.test.value):
        return
    for n in _loop_nodes(loop):
        if not isinstance(n, ast.If):
            continue
        tests_counter = any(
            isinstance(c, ast.Compare) and any(
                isinstance(x, ast.Name) and x.id in counters
                for x in ast.walk(c))
            for c in ast.walk(n.test))
        if tests_counter and any(
                isinstance(x, (ast.Break, ast.Return, ast.Raise))
                for b in n.body for x in ast.walk(b)):
            return
    note(waits[0], "retry_shape", "unbounded_attempts", "sleep")


def _retry_config(call, idx, note):
    """Report the delay shape of a tenacity config. A wait strategy this does
    not know is not reported."""
    kws = {k.arg: k.value for k in call.keywords}
    if None in kws:
        return  # **kwargs: the config is not in this expression
    if "stop" not in kws:
        note(call, "retry_shape", "unbounded_attempts", "retry")
    wait = kws.get("wait")
    if wait is None:
        note(call, "retry_shape", "constant_delay", "retry")
        return
    names = [idx.resolve_ctor(c.func) or "" for c in ast.walk(wait)
             if isinstance(c, ast.Call)]
    if not names or not all(n.startswith("tenacity.") for n in names):
        return
    tails = {n.rsplit(".", 1)[-1] for n in names}
    if any("random" in t or "jitter" in t for t in tails):
        return
    if tails & _TENACITY_GROWING:
        note(call, "retry_shape", "no_jitter", "retry")
    elif tails <= _TENACITY_CONSTANT:
        note(call, "retry_shape", "constant_delay", "retry")


def _local_shapes(tree, idx, note):
    """Report the local shapes of one module through `note`."""
    seen_queries = set()

    def queries(names, bodies):
        for body in bodies:
            for n in ast.walk(body):
                if (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr in _QUERY_METHODS
                        and _relation_root(n.func) in names
                        and id(n) not in seen_queries):
                    seen_queries.add(id(n))
                    note(n, "loop_variable_query", n.func.attr, n.func.attr,
                         resolved=False)

    def names_of(target):
        return {n.id for n in ast.walk(target) if isinstance(n, ast.Name)}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                # A bare `@retry` has no stop and no wait.
                if (not isinstance(dec, ast.Call)
                        and idx.resolve_ctor(dec) == "tenacity.retry"):
                    note(dec, "retry_shape", "unbounded_attempts", "retry")
                    note(dec, "retry_shape", "constant_delay", "retry")
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            queries(names_of(node.target), node.body)
            is_range = (isinstance(node.iter, ast.Call)
                        and isinstance(node.iter.func, ast.Name)
                        and node.iter.func.id == "range")
            if isinstance(node, ast.For) and is_range:
                _retry_loop(node, idx, note)
        elif isinstance(node, ast.While):
            _retry_loop(node, idx, note)
        elif isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp,
                               ast.DictComp)):
            names = set()
            for gen in node.generators:
                names |= names_of(gen.target)
            bodies = [node.key, node.value] if isinstance(node, ast.DictComp) \
                else [node.elt]
            queries(names, bodies + [i for g in node.generators for i in g.ifs])
        elif isinstance(node, ast.Call):
            func = node.func
            dotted = idx.resolve_ctor(func)
            if isinstance(func, ast.Name) and func.id not in idx.imports:
                if (func.id == "map" and node.args
                        and isinstance(node.args[0], ast.Lambda)):
                    lam = node.args[0]
                    queries({a.arg for a in lam.args.args}, [lam.body])
                elif func.id == "print":
                    # `file=` anything but a standard stream is a write.
                    files = [k.value for k in node.keywords if k.arg == "file"]
                    if all(idx.resolve_ctor(f) in ("sys.stdout", "sys.stderr")
                           for f in files):
                        note(node, "print_logging", "print", "print")
            elif (isinstance(func, ast.Attribute)
                    and func.attr in _SQL_EXEC_METHODS and node.args
                    and _built_sql(idx, node.args[0])):
                note(node, "sql_concat_in_call", func.attr, func.attr,
                     resolved=False)
            if dotted in _TENACITY_RETRY:
                _retry_config(node, idx, note)
            elif dotted in _SCALAR_METRICS:
                name = node.args[0] if node.args else next(
                    (k.value for k in node.keywords if k.arg == "name"), None)
                if (isinstance(name, ast.Constant) and isinstance(name.value, str)
                        and _LATENCY_NAME.search(name.value)):
                    note(node, "latency_scalar_metric", dotted,
                         dotted.rsplit(".", 1)[-1])


def collect_misuse(tree, source, idx, enclosing, file_path, snapshot,
                   swallowed):
    """Return the file's misuse-shape aggregate records. `swallowed` is the
    set of handler ids collect_emissions counted as swallows."""
    module_coros = _coroutine_names(tree.body)
    aggs = {}  # (symbol, class, identity) -> agg dict
    bound_cache, loads_cache = {}, {}

    def note(node, cls, identity, method, resolved=True):
        symbol = enclosing.get(id(node), ("", None))[0]
        key = (symbol, cls, identity)
        agg = aggs.get(key)
        if agg is None:
            aggs[key] = agg = {
                "line": node.lineno,
                "method": method,
                "snippet": "" if cls == "overbroad_catch" else _segment(source, node),
                "resolved": resolved,
                "count": 0,
            }
        agg["count"] += 1

    def bound_in(fn):
        """Names a function binds itself: parameters and assignments."""
        if id(fn) not in bound_cache:
            names = {a.arg for a in ast.walk(fn.args) if isinstance(a, ast.arg)}
            names.update(n.id for n in ast.walk(fn)
                         if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store))
            bound_cache[id(fn)] = names
        return bound_cache[id(fn)]

    def loads_in(fn):
        if id(fn) not in loads_cache:
            loads_cache[id(fn)] = {
                n.id for n in ast.walk(fn)
                if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)}
        return loads_cache[id(fn)]

    def coroutine_callee(call, class_coros):
        """The name of the coroutine function a call invokes, or None."""
        func = call.func
        fn = enclosing.get(id(call), ("", None))[1]
        if isinstance(func, ast.Name) and func.id in module_coros:
            if fn is None or func.id not in bound_in(fn):
                return func.id
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id == "self" and func.attr in class_coros):
            return func.attr
        return None

    def handle(node, class_coros, in_async):
        if isinstance(node, ast.ExceptHandler):
            caught = _overbroad_type(node)
            reraises = any(isinstance(n, ast.Raise) for n in ast.walk(node))
            if caught and not reraises and id(node) not in swallowed:
                note(node, "overbroad_catch", caught, "except")
        elif isinstance(node, ast.Call) and in_async:
            func = node.func
            dotted = idx.resolve_ctor(func)
            if dotted in _BLOCKING_CALLS:
                note(node, "blocking_in_async", dotted, dotted.rsplit(".", 1)[-1])
            elif dotted in _SYNC_WAIT_CALLS:
                note(node, "sync_over_async", dotted, dotted.rsplit(".", 1)[-1])
            elif isinstance(func, ast.Attribute):
                if func.attr == "run_until_complete":
                    # Named for what it is: the receiver has no type here.
                    note(node, "sync_over_async",
                         "asyncio.loop.run_until_complete", func.attr,
                         resolved=False)
                elif (func.attr == "result" and isinstance(func.value, ast.Call)
                        and idx.resolve_ctor(func.value.func)
                        == "asyncio.run_coroutine_threadsafe"):
                    note(node, "sync_over_async",
                         "asyncio.run_coroutine_threadsafe.result", func.attr)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            dotted = idx.resolve_ctor(node.value.func)
            if dotted in _TASK_STARTERS:
                note(node, "fire_and_forget", dotted, dotted.rsplit(".", 1)[-1])
            else:
                name = coroutine_callee(node.value, class_coros)
                if name:
                    note(node, "missing_await", "coroutine", name)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and isinstance(node.value, ast.Call)):
            # Inside a function only: a module-level name can be read from
            # another module.
            fn = enclosing.get(id(node), ("", None))[1]
            name = coroutine_callee(node.value, class_coros)
            if name and fn is not None and node.targets[0].id not in loads_in(fn):
                note(node, "missing_await", "coroutine", name)

    def visit(node, class_coros, in_async):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef):
                visit(child, _coroutine_names(child.body), False)
            elif isinstance(child, ast.AsyncFunctionDef):
                visit(child, class_coros, True)
            elif isinstance(child, (ast.FunctionDef, ast.Lambda)):
                visit(child, class_coros, False)
            else:
                handle(child, class_coros, in_async)
                visit(child, class_coros, in_async)

    visit(tree, frozenset(), False)
    _local_shapes(tree, idx, note)

    records = []
    for (symbol, cls, identity), agg in sorted(
            aggs.items(), key=lambda kv: (kv[1]["line"], kv[0])):
        records.append({
            "packet_schema": PACKET_SCHEMA,
            "site_key": "",  # stamped in emit(), like every packet
            "site_kind": SITE_KIND_MISUSE,
            "snapshot_id": snapshot,
            "file_path": file_path,
            "line_number": agg["line"],
            "symbol": symbol,
            "func": agg["method"],
            "receiver": "",
            "client_type": identity,
            "snippet": agg["snippet"],
            # Volume control: no function body on aggregates.
            "enclosing_function_body": "",
            "callers": [],
            "callees": [],
            "client_construction": [],
            "const_args": [
                {"index": 0, "name": "misuse_class",
                 "value": cls, "how": "aggregate"},
                {"index": 0, "name": "misuse_count",
                 "value": str(agg["count"]), "how": "aggregate"},
            ],
            "macro_expansion": False,
            "provenance": {
                "client_type_resolved": agg["resolved"],
                "callers_total": 0,
                "callers_included": 0,
                "callees_total": 0,
                "callees_included": 0,
            },
            "lang": "python",
        })
    return records


# ---------------------------------------------------------------------------
# Unsized-construction inventory.
#
# A queue, a connection pool or a cache was built here. One packet per
# construction, on the SAME stream, stamped site_kind: "unsized_construction".
# The retrieval/judgment split holds: the packet lists the constructor's
# arguments as OBSERVED, and a construction-bound spec downstream says which
# of them is a bound and which values of it mean "no limit".
#
# A constant is reported as a value. Anything else (maxsize=settings.max_jobs)
# is reported with how: "name" -- its source text, never a resolved value.
# Downstream credits a name as a bound and compares nothing against it.
#
# Detection is IMPORT-RESOLVED: the callee must resolve through this module's
# imports to a table entry. A local name that only looks like one is skipped.
#
# Whole-body reads (`.read()`, `.objects.all()`) are deliberately not here:
# without receiver types they cannot be told from a bounded or lazy read.
# ---------------------------------------------------------------------------

SITE_KIND_UNSIZED = "unsized_construction"

# Dotted constructor -> class. Like STRONG_IO_METHODS this selects WHICH
# sites to surface, never what they mean.
_BOUND_CONSTRUCTORS = {
    "queue.Queue": "queue",
    "queue.LifoQueue": "queue",
    "queue.PriorityQueue": "queue",
    "asyncio.Queue": "queue",
    "asyncio.LifoQueue": "queue",
    "asyncio.PriorityQueue": "queue",
    "multiprocessing.Queue": "queue",
    "collections.deque": "queue",
    "redis.ConnectionPool": "pool",
    "redis.BlockingConnectionPool": "pool",
    "sqlalchemy.create_engine": "pool",
    "psycopg_pool.ConnectionPool": "pool",
    "functools.lru_cache": "cache",
    "functools.cache": "cache",
}


def _bound_observation(index, name, node, source, idx):
    """One constructor argument as an observation: a value when it is a
    constant, a NAME (its source text) when it is not."""
    if isinstance(node, ast.Constant):
        value, how = repr(node.value), "literal"
    elif isinstance(node, ast.Name) and node.id in idx.const_by_name:
        value, how = repr(idx.const_by_name[node.id]), "named_constant"
    else:
        value, how = _segment(source, node), "name"
    return {"index": index, "name": name, "value": value, "how": how}


def collect_unsized(tree, source, idx, enclosing, file_path, snapshot):
    """Return the file's unsized-construction records."""
    # (node the record sits on, constructor expression, call or None, symbol)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # `@lru_cache` with no call builds the cache with its defaults.
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    found.append((dec, dec, None, node.name))
        elif isinstance(node, ast.Call):
            symbol = enclosing.get(id(node), ("", None))[0]
            found.append((node, node.func, node, symbol))

    records = []
    for node, ctor, call, symbol in found:
        ctype = idx.resolve_ctor(ctor)
        cls = _BOUND_CONSTRUCTORS.get(ctype)
        if cls is None:
            continue
        const_args = [{"index": 0, "name": "bound_class", "value": cls,
                       "how": "aggregate"}]
        opaque = []
        pos = 0
        for a in (call.args if call else []):
            if isinstance(a, ast.Starred):
                opaque.append(_segment(source, a))
            else:
                const_args.append(_bound_observation(
                    pos, "arg{}".format(pos), a, source, idx))
            pos += 1
        for kw in (call.keywords if call else []):
            if kw.arg is None:
                opaque.append("**" + _segment(source, kw.value))
            else:
                const_args.append(_bound_observation(
                    pos, kw.arg, kw.value, source, idx))
            pos += 1
        if opaque:
            # Some options are not written out; a bound may be among them.
            const_args.append({"index": 0, "name": "bound_opaque",
                               "value": ", ".join(opaque), "how": "aggregate"})
        records.append({
            "site_kind": SITE_KIND_UNSIZED,
            "snapshot_id": snapshot,
            "file_path": file_path,
            "line_number": node.lineno,
            "symbol": symbol,
            "func": ctype.rsplit(".", 1)[-1],
            "receiver": "",
            "client_type": ctype,
            "snippet": _segment(source, node),
            "enclosing_function_body": "",
            "callers": [],
            "callees": [],
            "client_construction": [],
            "const_args": const_args,
            "macro_expansion": False,
            "provenance": {
                "client_type_resolved": True,
                "callers_total": 0,
                "callers_included": 0,
                "callees_total": 0,
                "callees_included": 0,
            },
            "lang": "python",
        })
    return records


# ---------------------------------------------------------------------------
# Call graph (po-cafdn.3): callers, callees and chain roots.
#
# goindex resolves a call through the type checker. Python has none, so an
# edge here exists only where the callee expression resolves STRUCTURALLY to
# exactly one definition in this repository:
#
#   foo()            a def nested in an enclosing function, a module-level def,
#                    or an imported name
#   mod.foo()        an imported module's top-level def (re-exports followed)
#   self.foo()       a method on the enclosing class or an in-repo base class
#   Cls.foo()        the same lookup, by class
#   obj.foo()        where `obj = Cls(...)` or `self.obj = Cls(...)`
#   Cls()            Cls.__init__, when the repository defines one
#   Cls().foo()      a method on a value constructed in place
#
# Everything else -- a method on a parameter, a callable pulled out of a dict,
# an import two files could answer to -- makes NO edge. The retriever abstains
# rather than match by name: a guessed caller is evidence for a chain that may
# not exist, and its source is read downstream as in scope of the site.
#
# The walk upward is by graph proximity only, as in goindex: no content
# inspection, no name matching. The functions it stops at because nothing
# resolved calls them are reported with their structural facts (RootFact).
# Whether a root is a real entrypoint is a judgement and stays downstream.
# ---------------------------------------------------------------------------

_STDLIB_MODULES = getattr(sys, "stdlib_module_names", frozenset())


def _module_name(file_path):
    """Dotted module path of a root-relative file: `a/b/c.py` -> `a.b.c`,
    `a/b/__init__.py` -> `a.b`."""
    parts = file_path[:-3].split("/") if file_path.endswith(".py") \
        else file_path.split("/")
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _dotted(node):
    """`a.b.c` for a pure Name/Attribute chain, else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _callee(node):
    """How a call names what it calls: (dotted, None) for a plain name or
    attribute chain, (constructor, method) for a method called on a value
    constructed in place (`Syncer(...).sync_all()`), else None."""
    dotted = _dotted(node)
    if dotted is not None:
        return dotted, None
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Call):
        ctor = _dotted(node.value.func)
        if ctor is not None:
            return ctor, node.attr
    return None


def _is_main_guard(node):
    """`if __name__ == "__main__":`, written either way round."""
    if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
        return False
    sides = [node.test.left] + list(node.test.comparators)
    return (any(isinstance(x, ast.Name) and x.id == "__name__" for x in sides)
            and any(isinstance(x, ast.Constant) and x.value == "__main__"
                    for x in sides))


def _signature(node):
    try:
        text = "def {}({})".format(node.name, ast.unparse(node.args))
        if node.returns is not None:
            text += " -> " + ast.unparse(node.returns)
    except Exception:
        text = "def {}(...)".format(node.name)
    if isinstance(node, ast.AsyncFunctionDef):
        text = "async " + text
    return _cap(text)


class _Span(object):
    """Where a node sits in its file: what ast.get_source_segment reads, kept
    after the node is gone."""

    __slots__ = ("lineno", "col_offset", "end_lineno", "end_col_offset")

    def __init__(self, node):
        self.lineno = node.lineno
        self.col_offset = node.col_offset
        self.end_lineno = getattr(node, "end_lineno", None)
        self.end_col_offset = getattr(node, "end_col_offset", None)


class _Func(object):
    """One function or method definition: a node of the call graph.

    Its source and decorators are kept as spans and cut out of the module
    source on demand: most functions are never emitted, and cutting a segment
    costs a pass over the file."""

    __slots__ = ("qualname", "module", "self_cls", "scopes", "locals",
                 "span", "decorator_spans", "signature", "doc", "calls",
                 "ref_as_value", "_snippet", "_root")

    def snippet(self):
        if self._snippet is None:
            self._snippet = {
                "file": self.module.file, "line": self.span.lineno,
                "symbol": self.qualname,
                "source": _segment(self.module.source, self.span)}
        return self._snippet

    def root(self):
        """The RootFact. Read only after the graph is resolved, when
        ref_as_value is final."""
        if self._root is None:
            name = self.qualname.rsplit(".", 1)[-1]
            self._root = {
                "symbol": self.qualname,
                "package": self.module.name,
                "signature": self.signature,
                "doc": self.doc,
                "exported": not name.startswith("_"),
                "in_package_main": self.module.is_main,
                "referenced_as_value": self.ref_as_value,
                "decorators": ["@" + _segment(self.module.source, d)
                               for d in self.decorator_spans],
            }
        return self._root


class ModuleSummary(object):
    """What the call graph keeps of one module once its AST is gone: the
    definitions, the names that can reach another module, and every call and
    value reference still in source form, resolved when all modules are in."""

    def __init__(self, file_path, source, tree):
        self.file = file_path
        self.name = _module_name(file_path)
        base = file_path.rsplit("/", 1)[-1]
        self.is_package = base == "__init__.py"
        # `python -m pkg` runs __main__.py; a __main__ guard marks a script.
        self.is_main = base == "__main__.py" or any(
            _is_main_guard(n) for n in tree.body)
        self.functions = {}      # qualname -> _Func; a later def wins
        self.all_functions = []  # every def, in source order
        self.classes = {}        # qualname -> [base expression, dotted]
        self.imports = {}        # bound name -> (module, member or None)
        self.var_class = {}      # (function qualname or "", name) -> ctor
        self.self_class = {}     # (class qualname, attribute) -> ctor
        self.value_refs = {}     # (dotted, self_cls, scopes) -> count
        self.by_pos = {}         # (line, column) of a def -> _Func
        self.source = source
        for node in tree.body:
            self._visit(node, "", None, None, None, ())

    def _import(self, node):
        """Bind what an import statement names. Module-scoped and
        last-write-wins wherever the statement sits, like FileIndex."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    self.imports[alias.asname] = (alias.name, None)
                else:
                    top = alias.name.split(".")[0]
                    self.imports[top] = (top, None)
            return
        base = []
        if node.level:
            # Relative: counted up from this module's package.
            package = self.name.split(".") if self.name else []
            if not self.is_package:
                package = package[:-1]
            up = node.level - 1
            if up > len(package):
                return  # climbs out of the tree
            base = package[:len(package) - up]
        if node.module:
            base = base + node.module.split(".")
        parent = ".".join(base)
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name
            if parent:
                self.imports[bound] = (parent, alias.name)
            else:
                self.imports[bound] = (alias.name, None)

    def _add_func(self, node, prefix, self_cls, scopes):
        fn = _Func()
        fn.qualname = prefix + node.name
        fn.module = self
        fn.self_cls = self_cls
        fn.scopes = (fn.qualname,) + scopes
        args = node.args
        fn.locals = {a.arg for a in
                     args.posonlyargs + args.args + args.kwonlyargs}
        for extra in (args.vararg, args.kwarg):
            if extra is not None:
                fn.locals.add(extra.arg)
        fn.span = _Span(node)
        fn.decorator_spans = [_Span(d) for d in node.decorator_list]
        fn._snippet = fn._root = None
        fn.signature = _signature(node)
        # The summary line only: a root's docstring rides every packet whose
        # chain reaches it.
        fn.doc = _cap((ast.get_docstring(node) or "").split("\n", 1)[0])
        fn.calls = []
        fn.ref_as_value = 0
        self.functions[fn.qualname] = fn
        self.all_functions.append(fn)
        self.by_pos[(node.lineno, node.col_offset)] = fn
        return fn

    def _bind(self, node, cls, func, self_cls):
        """`x = Cls(...)` and `self.x = Cls(...)`: what a later `x.method()`
        is a method of. Scoped to the function (or the module) that assigns."""
        value = node.value
        if not isinstance(value, ast.Call):
            return
        ctor = _dotted(value.func)
        if ctor is None:
            return
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for tgt in targets:
            if isinstance(tgt, ast.Name):
                if cls is None:  # a class-body name is a class attribute
                    scope = func.qualname if func is not None else ""
                    self.var_class[(scope, tgt.id)] = ctor
            elif (isinstance(tgt, ast.Attribute) and self_cls is not None
                  and isinstance(tgt.value, ast.Name)
                  and tgt.value.id == "self"):
                self.self_class[(self_cls, tgt.attr)] = ctor

    def _visit(self, node, prefix, cls, func, self_cls, scopes):
        """Walk one node. `prefix` is the qualname prefix for a def found
        here, `cls` the class whose body this is (None inside a function),
        `func` the innermost enclosing function, `self_cls` the class `self`
        refers to, `scopes` the enclosing function qualnames, innermost
        first."""
        here = (prefix, cls, func, self_cls, scopes)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # A decorator CALL and the argument defaults run in the scope
            # that defines the function. A bare `@name` is the framework
            # applying itself, reported on the root as source, not as a
            # reference to `name`.
            outer = [d for d in node.decorator_list if isinstance(d, ast.Call)]
            outer += node.args.defaults
            outer += [d for d in node.args.kw_defaults if d is not None]
            for part in outer:
                self._visit(part, *here)
            fn = self._add_func(node, prefix, cls or self_cls, scopes)
            for child in node.body:
                self._visit(child, fn.qualname + ".", None, fn, fn.self_cls,
                            fn.scopes)
            return
        if isinstance(node, ast.ClassDef):
            qual = prefix + node.name
            self.classes[qual] = [d for d in map(_dotted, node.bases) if d]
            for part in (node.decorator_list + node.bases
                         + [kw.value for kw in node.keywords]):
                self._visit(part, *here)
            for child in node.body:
                self._visit(child, qual + ".", qual, func, self_cls, scopes)
            return
        if isinstance(node, ast.Call):
            callee = _callee(node.func)
            if callee is None or callee[1] is not None:
                self._visit(node.func, *here)
            if callee is not None and func is not None:
                func.calls.append(callee)
            for arg in node.args:
                self._visit(arg, *here)
            for kw in node.keywords:
                self._visit(kw.value, *here)
            return
        if isinstance(node, (ast.Name, ast.Attribute)):
            if isinstance(node.ctx, ast.Load):
                ref = _dotted(node)
                if ref is not None:
                    # Named but not called: handed to a router, a scheduler, a
                    # thread. Counted on the definition it resolves to.
                    key = (ref, self_cls, scopes)
                    self.value_refs[key] = self.value_refs.get(key, 0) + 1
                    return
            elif isinstance(node, ast.Name) and func is not None:
                func.locals.add(node.id)
        elif isinstance(node, ast.arg):
            # Reached for a lambda's parameters (a def's are read in
            # _add_func): they shadow like any other local of the function.
            if func is not None:
                func.locals.add(node.arg)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            self._bind(node, cls, func, self_cls)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            self._import(node)
            return
        for child in ast.iter_child_nodes(node):
            self._visit(child, *here)


# ---------------------------------------------------------------------------
# framework_type (po-av01j.225).
#
# `Message.objects.get(...)` has the client_type `zerver.models.Message.objects`:
# one type per model, so a spec keyed on it covers one model. framework_type
# names the framework class the receiver is an instance of, and it rides
# beside client_type so one spec (django.db.models.Manager.get) covers every
# model's manager. client_type and site_key do not change.
#
# It is stamped only on proof: the receiver's owner must resolve, through the
# repo-wide graph, to a class that descends from the framework's base. An
# `objects` attribute of any other class gets nothing. The same shape is
# planned for SQLAlchemy session/query; add a row here, not a new code path.
# ---------------------------------------------------------------------------

# framework_type -> (base classes whose descendants own the receiver,
#                    attributes of such a class that hold the receiver).
_FRAMEWORK_RECEIVERS = {
    "django.db.models.Manager": (
        frozenset({
            "django.db.models.Model",
            "django.db.models.base.Model",
            "django.contrib.auth.models.AbstractUser",
            "django.contrib.auth.models.AbstractBaseUser",
            "django.contrib.auth.base_user.AbstractBaseUser",
        }),
        frozenset({"objects", "_default_manager", "_base_manager"}),
    ),
}


def _framework_owner(recv):
    """The dotted owner of a receiver that may be a framework object:
    `Order` for `Order.objects`. None when no row of _FRAMEWORK_RECEIVERS
    names the receiver's last attribute."""
    if not isinstance(recv, ast.Attribute):
        return None
    if not any(recv.attr in attrs
               for _, attrs in _FRAMEWORK_RECEIVERS.values()):
        return None
    return _dotted(recv.value)


class CallGraph(object):
    """Caller and callee edges over every module added, resolved once."""

    def __init__(self):
        self.modules = []
        self.by_suffix = {}   # dotted suffix of a module name -> [module]
        self.packages = set()  # module names that are packages
        self.callers = {}     # _Func -> [_Func], in module path order
        self.callees = {}     # _Func -> [_Func], in call order
        self.pending = []     # (record, _Func) waiting for the walk
        # (record, module, owner, attribute, _Func or None) waiting for the
        # owner's class to be resolved.
        self.framework_pending = []

    def add(self, summary):
        self.modules.append(summary)

    def wants_framework(self, record, mod, owner, attr, fn):
        """Stamp framework_type on this record once the graph is complete,
        if `owner` turns out to be a class of a known framework."""
        self.framework_pending.append((record, mod, owner, attr, fn))

    def wants(self, record, fn):
        """Fill this record's ancestry once the graph is complete."""
        self.pending.append((record, fn))

    # -- name resolution -----------------------------------------------------
    #
    # An entity is ("func", _Func), ("class", module, qualname),
    # ("instance", module, class qualname) or ("mod", dotted name).

    def _find_module(self, name):
        """The one module `name` imports, or None when no file or more than
        one could answer to it."""
        found = self.by_suffix.get(name, ())
        for mod in found:
            if mod.name == name:
                return mod
        if name.split(".", 1)[0] in _STDLIB_MODULES:
            return None  # `import json` is not app/json.py
        # A source root is not a package: `src/app/x.py` imports as `app.x`,
        # but `app/x.py` inside package `app` never imports as `x`.
        found = [m for m in found
                 if m.name[:-len(name) - 1] not in self.packages]
        return found[0] if len(found) == 1 else None

    def _instance(self, mod, ctor, hops):
        if hops > MAX_RESOLVE_HOPS:
            return None
        ent = self._resolve(mod, ctor, None, (), hops + 1)
        if ent is not None and ent[0] == "class":
            return ("instance", ent[1], ent[2])
        return None

    def _top(self, mod, name, hops):
        """A module's top-level name."""
        fn = mod.functions.get(name)
        if fn is not None:
            return ("func", fn)
        if name in mod.classes:
            return ("class", mod, name)
        ctor = mod.var_class.get(("", name))
        if ctor is not None:
            return self._instance(mod, ctor, hops)
        imp = mod.imports.get(name)
        if imp is None or hops > MAX_RESOLVE_HOPS:
            return None
        parent, member = imp
        if member is None:
            return ("mod", parent)
        return self._member(("mod", parent), member, hops + 1)

    def _head(self, mod, name, self_cls, scopes, hops):
        if self_cls is not None:
            if name == "self":
                return ("instance", mod, self_cls)
            if name == "cls":
                return ("class", mod, self_cls)
        for scope in scopes:
            nested = scope + "." + name
            fn = mod.functions.get(nested)
            if fn is not None:
                return ("func", fn)
            if nested in mod.classes:
                return ("class", mod, nested)
            owner = mod.functions.get(scope)
            if owner is not None and name in owner.locals:
                # A local or a parameter shadows the module's name. It is
                # something only if this function constructed it.
                ctor = mod.var_class.get((scope, name))
                return self._instance(mod, ctor, hops) if ctor else None
        return self._top(mod, name, hops)

    def _method(self, mod, qual, name, hops, seen):
        """`name` on class `qual` or the nearest in-repo base that has it."""
        key = (mod.file, qual)
        if key in seen or hops > MAX_RESOLVE_HOPS:
            return None
        seen.add(key)
        fn = mod.functions.get(qual + "." + name)
        if fn is not None:
            return fn
        for base in mod.classes.get(qual, ()):
            ent = self._resolve(mod, base, None, (), hops + 1)
            if ent is not None and ent[0] == "class":
                fn = self._method(ent[1], ent[2], name, hops + 1, seen)
                if fn is not None:
                    return fn
        return None

    def _member(self, ent, name, hops):
        kind = ent[0]
        if kind == "mod":
            mod = self._find_module(ent[1])
            if mod is not None:
                got = self._top(mod, name, hops)
                if got is not None:
                    return got
            return ("mod", ent[1] + "." + name)
        if kind == "func":
            return None
        _, mod, qual = ent
        fn = self._method(mod, qual, name, hops, set())
        if fn is not None:
            return ("func", fn)
        if kind == "class":
            nested = qual + "." + name
            return ("class", mod, nested) if nested in mod.classes else None
        ctor = mod.self_class.get((qual, name))
        return self._instance(mod, ctor, hops) if ctor else None

    def _resolve(self, mod, dotted, self_cls, scopes, hops=0):
        parts = dotted.split(".")
        ent = self._head(mod, parts[0], self_cls, scopes, hops)
        for part in parts[1:]:
            if ent is None:
                return None
            ent = self._member(ent, part, hops)
        return ent

    def _descends(self, mod, qual, bases, seen, hops=0):
        """Whether class `qual` has one of the dotted `bases` among its
        ancestors. In-repo bases are followed; a base outside the repo is
        compared by its import-resolved name."""
        key = (mod.file, qual)
        if key in seen or hops > MAX_RESOLVE_HOPS:
            return False
        seen.add(key)
        for base in mod.classes.get(qual, ()):
            ent = self._resolve(mod, base, None, (), hops + 1)
            if ent is None:
                continue
            if ent[0] == "mod" and ent[1] in bases:
                return True
            if ent[0] == "class" and self._descends(
                    ent[1], ent[2], bases, seen, hops + 1):
                return True
        return False

    def _framework_type(self, mod, owner, attr, fn):
        self_cls = fn.self_cls if fn is not None else None
        scopes = fn.scopes if fn is not None else ()
        ent = self._resolve(mod, owner, self_cls, scopes)
        if ent is None or ent[0] != "class":
            return None
        for framework, (bases, attrs) in sorted(_FRAMEWORK_RECEIVERS.items()):
            if attr in attrs and self._descends(ent[1], ent[2], bases, set()):
                return framework
        return None

    def _call_target(self, fn, callee):
        dotted, method = callee
        ent = self._resolve(fn.module, dotted, fn.self_cls, fn.scopes)
        if ent is None:
            return None
        if method is None and ent[0] == "func":
            return ent[1]
        if ent[0] == "class":
            # Calling a class runs its __init__; `Cls().method` is a method
            # of the instance that call returns.
            return self._method(ent[1], ent[2], method or "__init__", 0, set())
        return None

    # -- edges ---------------------------------------------------------------

    def resolve(self):
        """Build the edges, once every module is in. Modules are taken in path
        order, so a full run and a --files run see callers in the same
        order."""
        self.modules.sort(key=lambda m: m.file)
        for mod in self.modules:
            if mod.is_package:
                self.packages.add(mod.name)
            parts = mod.name.split(".")
            for i in range(len(parts)):
                self.by_suffix.setdefault(".".join(parts[i:]), []).append(mod)
        for mod in self.modules:
            for fn in mod.all_functions:
                # A function that calls itself is not its own caller: one
                # nothing else calls is still where its chain starts.
                seen = {fn}
                for callee in fn.calls:
                    target = self._call_target(fn, callee)
                    if target is None or target in seen:
                        continue
                    seen.add(target)
                    self.callees.setdefault(fn, []).append(target)
                    self.callers.setdefault(target, []).append(fn)
            for (dotted, self_cls, scopes), n in mod.value_refs.items():
                ent = self._resolve(mod, dotted, self_cls, scopes)
                if ent is not None and ent[0] == "func":
                    ent[1].ref_as_value += n

    def ancestors(self, start):
        """Walk callers upward, breadth-first, cycle-safe. Returns (callers by
        proximity, depth searched, chain roots, hit the depth cap). The same
        walk as goindex's ancestors()."""
        seen = {start}
        frontier = [start]
        ordered, roots = [], []
        depth = 0
        while depth < MAX_CHAIN_DEPTH and frontier:
            nxt = []
            for cur in frontier:
                callers = self.callers.get(cur)
                if not callers:
                    roots.append(cur)  # in the frontier once: `seen` dedupes
                    continue
                for caller in callers:
                    if caller in seen:
                        continue
                    seen.add(caller)
                    ordered.append(caller)
                    nxt.append(caller)
            frontier = nxt
            depth += 1
        return ordered, depth, roots, bool(frontier)

    def attach(self):
        """Fill callers, callees and search provenance on every waiting
        record."""
        self.resolve()
        for record, fn in self.pending:
            anc, depth, roots, hit_depth = self.ancestors(fn)
            down = self.callees.get(fn, [])
            callers = [f.snippet() for f in anc[:MAX_CALLERS_EMITTED]]
            callees = [f.snippet() for f in down[:MAX_CALLEES_EMITTED]]
            record["callers"] = callers
            record["callees"] = callees
            record["provenance"].update({
                "callers_total": len(anc),
                "callers_included": len(callers),
                "callees_total": len(down),
                "callees_included": len(callees),
                "ancestry_depth_searched": depth,
                "chain_roots": [f.root() for f in roots],
                "hit_depth_cap": hit_depth,
                "hit_caller_budget": len(anc) > len(callers),
            })
        self.pending = []
        for record, mod, owner, attr, fn in self.framework_pending:
            framework = self._framework_type(mod, owner, attr, fn)
            if framework is not None:
                record["framework_type"] = framework
        self.framework_pending = []


def _parse(abs_path, file_path):
    """(source, tree) for one file, or None when it could not be read or
    parsed (reported on stderr)."""
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
    return source, tree


def _summarize(file_path, source, tree):
    """The module's call-graph summary, or None when its AST nests deeper
    than the walk can follow: the file then contributes no edges, and its
    sites are still emitted."""
    try:
        return ModuleSummary(file_path, source, tree)
    except RecursionError:
        print("call graph skipped {}: expression nesting too deep"
              .format(file_path), file=sys.stderr)
        return None


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


def retrieve_file(abs_path, file_path, snapshot, graph):
    """Parse one Python file and return a list of site records (dicts), or
    None when the file could not be read or parsed.

    None vs [] is the distinction the retrieval_stats record carries
    downstream (po-av01j.209): a file that FAILED is counted, never silently
    collapsed into "parsed and empty".

    The module joins `graph`, and its call-site records wait there for their
    callers and callees: CallGraph.attach() fills them once every module is
    in."""
    parsed = _parse(abs_path, file_path)
    if parsed is None:
        return None
    source, tree = parsed
    summary = _summarize(file_path, source, tree)
    if summary is not None:
        graph.add(summary)

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
        constructions = idx.constructions_for(
            recv, recv_str, client_type, func_node)

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
            # Filled by CallGraph.attach() when the site has an enclosing
            # function; a module-scope site has no ancestry to walk.
            "callers": [],
            "callees": [],
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
                "ancestry_depth_searched": 0,
                "chain_roots": [],
                "hit_depth_cap": False,
                "hit_caller_budget": False,
            },
            "lang": "python",
        }
        out.append(record)
        fn = None
        if summary is not None and func_node is not None:
            fn = summary.by_pos.get((func_node.lineno, func_node.col_offset))
            if fn is not None:
                graph.wants(record, fn)
        owner = _framework_owner(recv)
        if summary is not None and owner is not None:
            graph.wants_framework(record, summary, owner, recv.attr, fn)
    out.extend(_job_decorator_records(tree, idx, source, file_path, snapshot))
    # G4 emission inventory rides the same stream (po-av01j.5).
    swallowed = set()
    out.extend(collect_emissions(tree, source, idx, enclosing, file_path,
                                 snapshot, swallowed))
    # Misuse-shape inventory: overbroad catches and async misuse.
    out.extend(collect_misuse(tree, source, idx, enclosing, file_path,
                              snapshot, swallowed))
    # Unsized-construction inventory: queues, pools and caches.
    out.extend(collect_unsized(tree, source, idx, enclosing, file_path, snapshot))
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


# TEST CODE IS NOT SCANNED FOR API SURFACES, the way goindex has
# always skipped _test.go. The skip is by PATH CONVENTION -- exact directory
# segments and exact basename shapes, never a substring, so `contest/` and
# `attestation.py` are production code. It is counted and reported on the
# retrieval_stats record (`test_files_skipped`), and --include-tests turns it
# off for a caller who wants test code scanned.
_TEST_DIR_SEGMENTS = frozenset({"tests", "test", "testing", "fixtures"})


def is_test_path(rel):
    """True when a root-relative, forward-slashed path is test material."""
    parts = rel.split("/")
    base = parts[-1]
    if any(seg in _TEST_DIR_SEGMENTS for seg in parts[:-1]):
        return True
    if base == "conftest.py":
        return True
    return ((base.startswith("test_") or base.endswith("_test.py"))
            and base.endswith(".py"))


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


def run_retrieve(root, snapshot, files_arg, include_tests=False):
    """Retrieve every discovered file. Returns (records, stats) where stats
    counts what was attempted: {"files_total", "files_parsed", "files_failed"}
    plus "test_files_skipped", which is NOT in files_total: a skipped file was
    never attempted, and counting it would make a tests-only tree read as
    "every file failed to parse".
    """
    records = []
    graph = CallGraph()
    seen = set()
    total = parsed = failed = 0
    # NAMED, not just counted: rvl's packet index flags each skipped file so
    # a warm scan can report the repository-wide number from reused entries.
    skipped = []
    for abs_path, file_path in discover(root, files_arg):
        if not include_tests and is_test_path(file_path):
            skipped.append(file_path)
            continue
        total += 1
        seen.add(file_path)
        got = retrieve_file(abs_path, file_path, snapshot, graph)
        if got is None:
            failed += 1
            continue
        parsed += 1
        records.extend(got)
    if files_arg and (graph.pending or graph.framework_pending):
        # The incremental path emits packets for the listed files only, but a
        # caller lives wherever it lives: the graph still spans the tree, so a
        # reloaded file gets the packets a full run would give it. The other
        # files are read for their edges and nothing else. They are not in
        # the stats, and one that fails to parse costs only its own edges.
        for abs_path, file_path in discover(root, ""):
            if file_path in seen:
                continue
            if not include_tests and is_test_path(file_path):
                continue
            neighbour = _parse(abs_path, file_path)
            if neighbour is not None:
                summary = _summarize(file_path, *neighbour)
                if summary is not None:
                    graph.add(summary)
    graph.attach()
    return records, {
        "files_total": total,
        "files_parsed": parsed,
        "files_failed": failed,
        "test_files_skipped": len(skipped),
        "test_files_skipped_paths": skipped,
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
        "test_files_skipped": stats["test_files_skipped"],
        "test_files_skipped_paths": stats["test_files_skipped_paths"],
    }))
    out.write("\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def content_version():
    """The second line of the --packet-schema reply: which pyindex this is.

    The schema integer says what SHAPE the stream has. It does not move when
    the helper learns a new client surface, so a week-old pyindex and today's
    answer the same "2" and scan differently. This is the first 12 hex digits
    of the sha256 of this file. rvl computes the same value for the copy it
    ships and warns when the helper it found is a different one.
    """
    with open(os.path.abspath(__file__), "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:12]


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
    p.add_argument("--include-tests", action="store_true",
                   help="also retrieve test paths (tests/, test/, testing/, "
                        "fixtures/, conftest.py, test_*.py, *_test.py), "
                        "which are skipped and counted by default")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    # Lets a consumer negotiate the contract before paying for a load.
    if args.packet_schema:
        print(PACKET_SCHEMA)
        print("content-version " + content_version())
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
        records, stats = run_retrieve(root, snapshot, args.files,
                                      args.include_tests)
        emit(records)
        emit_stats(snapshot, stats, len(records))
        print("{}: {} retrieved sites ({} files, {} failed, {} test files "
              "skipped)".format(snapshot, len(records), stats["files_total"],
                                stats["files_failed"],
                                stats["test_files_skipped"]), file=sys.stderr)
        # Exit non-zero when NOTHING was read, so the lane degrades loudly
        # instead of recording a successful retrieval of zero sites:
        #   - --files named files that do not exist here (all filtered out);
        #   - every discovered file failed to read or parse.
        # A tree with genuinely zero .py files (a pyproject.toml-only repo)
        # stays exit 0: the stats record proves the helper ran and read the
        # tree, and "nothing to read" is a real answer. So is a --files set
        # made only of test paths: the files exist, they were skipped on
        # purpose, and the stats record says so.
        if (args.files.strip(",").strip() and stats["files_total"] == 0
                and stats["test_files_skipped"] == 0):
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
