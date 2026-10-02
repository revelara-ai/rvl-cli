//! The libclang retrieval walk.
//!
//! Engine pin (po-ae75b.9): the libclang C API, runtime-loaded. Compile-db
//! native paths ONLY — `compile_commands.json` at the repo root or under
//! `build/`; no shipped build interception (Bear / CMake's
//! `CMAKE_EXPORT_COMPILE_COMMANDS` are documented as user-run). A TU that
//! fails to parse is COUNTED in the `retrieval_stats` record, never guessed
//! at. Repos with no compile db fall back to the curated extern-C allowlist
//! at LOW tier (`.c` files only; C++ without flags is a documented
//! abstention class).

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::Write;
use std::os::raw::c_uint;
use std::path::{Path, PathBuf};

use clang_sys::*;

use crate::engine::{self, Source};
use crate::PACKET_SCHEMA;

/// A loaded engine: its version string and where it came from.
pub struct Engine {
    pub version: String,
    pub source: Source,
}

/// Load libclang at runtime and report its version string. Fails with
/// actionable guidance when no library can be found — rvl surfaces this
/// stderr, so a detected C/C++ repo fails CLOSED rather than silently
/// under-reporting. Which library loads is decided by [`crate::engine`]:
/// LIBCLANG_PATH, then the vendored bundle, then (dev builds only) the system.
pub fn load_engine() -> Result<Engine, String> {
    let exe = std::env::current_exe().ok();
    let source = engine::resolve(
        std::env::var_os("LIBCLANG_PATH").as_deref(),
        exe.as_deref(),
        engine::REQUIRE_VENDORED,
    )
    .map_err(|e| format!("cindex requires libclang (engine pin po-ae75b.9): {e}"))?;
    if !clang_sys::is_loaded() {
        if let Source::Vendored { lib, .. } = &source {
            // clang-sys searches only LIBCLANG_PATH when it is set, and a file
            // path there names that exact library, so this pins the load to
            // the bundle. Safe to set: nothing else runs yet (the helper is
            // single-threaded and has not spawned anything).
            std::env::set_var("LIBCLANG_PATH", lib);
        }
        clang_sys::load().map_err(|e| match &source {
            Source::Vendored { lib, .. } => format!(
                "cindex could not load its vendored libclang at {}: {e}. \
                 Reinstall rvl, or point LIBCLANG_PATH at a libclang to override the pin.",
                lib.display()
            ),
            _ => format!(
                "cindex requires libclang (engine pin po-ae75b.9) and none could be loaded: {e}. \
                 Install one (e.g. `apt install libclang-dev`) or point LIBCLANG_PATH at it."
            ),
        })?;
    }
    let version = unsafe { cx_string(clang_getClangVersion()) };
    Ok(Engine { version, source })
}

// --- packet shapes (field-for-field with the goindex/pyindex/tsindex contract) ---

#[derive(Serialize, Default)]
struct ProvenanceOut {
    callers_total: u32,
    callers_included: u32,
    callees_total: u32,
    callees_included: u32,
    client_type_resolved: bool,
    /// Virtual dispatch reports its definition ambiguity here (the mid tier):
    /// 1 + the overriding definitions seen in this TU. 0 = not applicable.
    callee_candidates: u32,
}

#[derive(Serialize)]
struct ConstArgOut {
    index: u32,
    name: String,
    value: String,
    how: &'static str,
}

#[derive(Serialize)]
struct SiteOut {
    packet_schema: u32,
    site_key: String,
    snapshot_id: String,
    file_path: String,
    line_number: u32,
    symbol: String,
    #[serde(rename = "func")]
    method: String,
    receiver: String,
    client_type: String,
    snippet: String,
    enclosing_function_body: String,
    /// Empty in v1 of this helper: cross-TU graph walking is future work,
    /// and the keys are emitted so the shape is stable (pyindex precedent).
    callers: Vec<serde_json::Value>,
    callees: Vec<serde_json::Value>,
    client_construction: Vec<serde_json::Value>,
    provenance: ProvenanceOut,
    lang: &'static str,
    const_args: Vec<ConstArgOut>,
    macro_expansion: bool,
    /// "" = a classic G1 client call (the key is omitted, so G1 packets are
    /// unchanged); [`SITE_KIND_SERVER_ENTRY`] = a G2 handler registration;
    /// [`SITE_KIND_BACKGROUND_JOB`] = a G3 thread-start registration;
    /// [`SITE_KIND_EMISSION`] = a G4 aggregate.
    #[serde(skip_serializing_if = "str::is_empty")]
    site_kind: &'static str,
}

/// Repo-scoped retrieval accounting. Rides the same stream tagged by `kind`;
/// rvl-core routes unknown kinds away from Site parsing, so this is additive.
#[derive(Serialize)]
struct StatsOut {
    kind: &'static str,
    packet_schema: u32,
    snapshot_id: String,
    lang: &'static str,
    /// "compile_db" | "allowlist"
    mode: &'static str,
    tus_total: u32,
    /// TUs libclang returned an AST for. INCLUDES the incomplete ones below:
    /// `tus_parsed - tus_incomplete` is the count of genuinely clean parses.
    tus_parsed: u32,
    /// TUs that failed to parse: counted and documented, never guessed at.
    tus_failed: u32,
    /// Parsed TUs whose parse raised at least one error (po-av01j.138). Clang
    /// recovers from an error by DROPPING the construct it could not build:
    /// with `<curl/curl.h>` missing, `CURL *h = curl_easy_init();` parses as
    /// a multiplication of two undeclared identifiers and the whole statement
    /// vanishes, call and all. No call expression is left to count, so the
    /// only record of the loss is the diagnostic. A zero from one of these
    /// TUs is not a complete zero.
    tus_incomplete: u32,
    /// Repo-relative paths behind `tus_incomplete`, sorted.
    tus_incomplete_paths: Vec<String>,
    /// `#include` directives that resolved to no file, summed over TUs. The
    /// usual cause: the repo is scanned without its -dev packages installed.
    includes_missing: u32,
    /// Error diagnostics naming an identifier with no visible declaration
    /// (undeclared identifier or function, unknown type name). Each marks a
    /// construct clang may have dropped, and every call inside it with it.
    decls_unresolved: u32,
    /// Call expressions clang DID form whose callee did not resolve
    /// (template-dependent callees in uninstantiated templates are the
    /// dominant class): documented abstentions, never guesses. NOT a
    /// completeness claim: a call lost to recovery never becomes a call
    /// expression and so can never be counted here. That is why this was
    /// renamed from `calls_unresolved`, which read as "no call went
    /// unresolved" when the parse had silently dropped calls
    /// (po-av01j.138); `decls_unresolved` and `tus_incomplete` count those.
    calls_callee_unresolved: u32,
    /// C++ sources seen in no-db mode: a flagless C++ parse is guesswork, so
    /// they are skipped and counted (documented abstention class).
    cpp_files_skipped_no_db: u32,
}

// --- compile db ---

struct TuJob {
    /// Absolute path of the TU's source file.
    file: PathBuf,
    /// Parse args with compiler argv0 / -c / -o / the file itself stripped
    /// and relative include paths resolved against the entry's directory.
    args: Vec<String>,
}

/// Locate the compile db (native paths only): `<root>/compile_commands.json`,
/// then `<root>/build/compile_commands.json` (the common CMake layout).
fn find_compile_db(root: &Path) -> Option<PathBuf> {
    [
        root.join("compile_commands.json"),
        root.join("build").join("compile_commands.json"),
    ]
    .into_iter()
    .find(|p| p.is_file())
}

/// Split a `command` string into argv, honoring quotes and backslashes the
/// way the compile-db spec expects (POSIX-ish; enough for real CMake/Bear
/// output).
fn shell_split(cmd: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = cmd.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                } else if c == '\\' && q == '"' {
                    if let Some(&n) = chars.peek() {
                        cur.push(n);
                        chars.next();
                    }
                } else {
                    cur.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' => {
                    if let Some(&n) = chars.peek() {
                        cur.push(n);
                        chars.next();
                        in_word = true;
                    }
                }
                c if c.is_whitespace() => {
                    if in_word {
                        out.push(std::mem::take(&mut cur));
                        in_word = false;
                    }
                }
                c => {
                    cur.push(c);
                    in_word = true;
                }
            },
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

/// Flags whose relative path VALUE must resolve against the entry directory.
const PATH_FLAGS: &[&str] = &["-I", "-isystem", "-iquote", "-include", "-imacros"];

/// Reduce a compile-db entry's argv to clang parse args: drop the compiler
/// argv0, `-c`, `-o <out>`, and the source file itself; resolve relative
/// include-ish paths against `dir` (the entry's working directory), because
/// libclang resolves them against the PROCESS cwd otherwise.
fn tu_parse_args(argv: &[String], dir: &Path, file: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let abs = |p: &str| -> String {
        let pb = PathBuf::from(p);
        if pb.is_absolute() {
            p.to_string()
        } else {
            dir.join(pb).to_string_lossy().into_owned()
        }
    };
    let mut it = argv.iter().skip(1).peekable();
    while let Some(a) = it.next() {
        if a == "-c" {
            continue;
        }
        if a == "-o" {
            it.next();
            continue;
        }
        // The source file, spelled absolutely or relative to dir.
        let as_path = PathBuf::from(a);
        if as_path == file || dir.join(&as_path) == file {
            continue;
        }
        if let Some(flag) = PATH_FLAGS.iter().find(|f| a == **f) {
            if let Some(v) = it.next() {
                out.push((*flag).to_string());
                out.push(abs(v));
            }
            continue;
        }
        if let Some(flag) = PATH_FLAGS
            .iter()
            .find(|f| a.starts_with(**f) && a.len() > f.len())
        {
            out.push(format!("{flag}{}", abs(&a[flag.len()..])));
            continue;
        }
        out.push(a.clone());
    }
    out
}

/// Parse the compile db into per-TU jobs. Relative `directory` entries are
/// resolved against `root` (fixtures and relocatable repos; real dbs are
/// absolute). Duplicate entries for one file keep the FIRST (deterministic).
fn load_compile_db(db_path: &Path, root: &Path) -> anyhow::Result<Vec<TuJob>> {
    let text = std::fs::read_to_string(db_path)?;
    let entries: Vec<serde_json::Value> = serde_json::from_str(&text)?;
    let mut jobs = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for e in &entries {
        let dir_raw = e.get("directory").and_then(|d| d.as_str()).unwrap_or(".");
        let dir = {
            let d = PathBuf::from(dir_raw);
            if d.is_absolute() {
                d
            } else {
                root.join(d)
            }
        };
        let dir = dir.canonicalize().unwrap_or(dir);
        let Some(file_raw) = e.get("file").and_then(|f| f.as_str()) else {
            continue;
        };
        let file = {
            let f = PathBuf::from(file_raw);
            if f.is_absolute() {
                f
            } else {
                dir.join(f)
            }
        };
        let file = file.canonicalize().unwrap_or(file);
        if !seen.insert(file.clone()) {
            continue;
        }
        let argv: Vec<String> = if let Some(args) = e.get("arguments").and_then(|a| a.as_array()) {
            args.iter()
                .filter_map(|a| a.as_str().map(str::to_string))
                .collect()
        } else if let Some(cmd) = e.get("command").and_then(|c| c.as_str()) {
            shell_split(cmd)
        } else {
            continue;
        };
        let args = tu_parse_args(&argv, &dir, &file);
        jobs.push(TuJob { file, args });
    }
    Ok(jobs)
}

// --- identity tables ---

/// The C free-function G1 candidate set: unique unmangled identities mapped
/// to their client type. Identity-driven by design — C has no receiver to
/// resolve. POSIX `read`/`write` are deliberately ABSENT: telling a socket fd
/// from a file fd needs dataflow (documented abstention, follow-up bead).
fn c_family(name: &str) -> Option<&'static str> {
    match name {
        "curl_easy_perform" | "curl_easy_setopt" | "curl_easy_send" | "curl_easy_recv"
        | "curl_multi_perform" | "curl_multi_wait" => Some("libcurl.CURL"),
        "PQconnectdb" | "PQconnectdbParams" | "PQexec" | "PQexecParams" | "PQexecPrepared"
        | "PQprepare" | "PQsendQuery" | "PQsendQueryParams" | "PQgetResult" => Some("libpq.PGconn"),
        "redisConnect"
        | "redisConnectWithTimeout"
        | "redisCommand"
        | "redisCommandArgv"
        | "redisAppendCommand"
        | "redisGetReply" => Some("hiredis.redisContext"),
        "connect" | "send" | "recv" | "sendto" | "recvfrom" | "sendmsg" | "recvmsg" => {
            Some("posix.socket")
        }
        _ => None,
    }
}

/// The `site_kind` a G3 registration carries (the cross-helper contract value).
const SITE_KIND_BACKGROUND_JOB: &str = "background_job";

/// The C free-function G3 set: calls that START a background thread, mapped
/// to their client type. Registrations only — the retriever reports where a
/// thread starts and never analyzes the loop it runs.
fn c_job_family(name: &str) -> Option<&'static str> {
    match name {
        "pthread_create" => Some("posix.pthread"),
        _ => None,
    }
}

/// Mirrors `rvl_core::SITE_KIND_SERVER_ENTRY`.
const SITE_KIND_SERVER_ENTRY: &str = "server_entry";

/// The C free-function G2 candidate set: HTTP handler registrations of the
/// embedded servers, mapped to their framework identity. Identity-driven like
/// [`c_family`]: each name is a unique unmangled identifier of ONE library
/// (civetweb and mongoose share the `mg_` prefix, not these names).
/// RETRIEVAL, not judgement: which path is a health endpoint is the lane's
/// question. `mg_match` is deliberately ABSENT: it is mongoose's general glob
/// matcher and is a route only under the event-handler gate in `handle_call`.
fn server_family(name: &str) -> Option<&'static str> {
    match name {
        "mg_set_request_handler" => Some("civetweb.mg_context"),
        "mg_http_listen" => Some("mongoose.mg_mgr"),
        "mg_http_match_uri" => Some(MONGOOSE_MESSAGE),
        _ => None,
    }
}

/// The identity of a mongoose route match (`mg_http_match_uri`, gated
/// `mg_match`): the request message whose URI is matched.
const MONGOOSE_MESSAGE: &str = "mongoose.mg_http_message";

/// (client type, site kind) of a C free function on any identity table.
fn c_identity(name: &str) -> Option<(&'static str, &'static str)> {
    c_family(name)
        .map(|f| (f, ""))
        .or_else(|| server_family(name).map(|f| (f, SITE_KIND_SERVER_ENTRY)))
        .or_else(|| c_job_family(name).map(|f| (f, SITE_KIND_BACKGROUND_JOB)))
}

/// C++ types whose construction WITH a callable starts a background thread.
const THREAD_TYPES: &[&str] = &["std::thread", "std::jthread"];

/// Method names that are almost never non-I/O in C++ client code: emitted on
/// any resolved member call. Mirrors pyindex's strong-verb tier.
const STRONG_VERBS: &[&str] = &[
    "execute",
    "executemany",
    "perform",
    "request",
    "publish",
    "subscribe",
    "post",
    "put",
    "patch",
    "head",
    "fetchone",
    "fetchall",
    "fetchmany",
    "urlopen",
    "sendall",
];

/// Ambiguous-with-anything names: emitted only when the receiver type is
/// out-of-repo (a third-party client) or the dispatch is virtual (the mid
/// tier — an interface method is exactly where I/O hides behind a name like
/// `get`). Mirrors pyindex's weak-verb tier.
const WEAK_VERBS: &[&str] = &[
    "get", "send", "connect", "call", "run", "query", "invoke", "read", "write", "fetch", "delete",
    "exec", "wait", "recv",
];

// --- G4 emission identities ---

/// Mirrors `rvl_core::SITE_KIND_EMISSION`.
const SITE_KIND_EMISSION: &str = "emission_point";

/// The only category this helper reports. `error_capture` needs to know that
/// an emission sits on an error path, which waits on C++ catch-clause
/// analysis (po-av01j.52).
const EMISSION_CATEGORY_LOG: &str = "log";

/// spdlog's emitting names, shared by `spdlog::logger` members and the free
/// functions that forward to the default logger. The rest of that surface
/// (`set_level`, `flush`, `set_pattern`) configures and emits nothing.
const SPDLOG_EMIT_VERBS: &[&str] = &["trace", "debug", "info", "warn", "error", "critical", "log"];

/// The G4 candidate set: a resolved callee's identity mapped to the framework
/// its aggregate is filed under. `scope` is the class for a member function
/// and the namespace path for a free one (`""` = global).
///
/// Identity-driven, like [`c_family`]: a C++ name counts only inside its own
/// namespace or class, so a user's `app::syslog` or `Report::info` abstains.
/// The macro surfaces need no rule of their own: `SPDLOG_*` expands to a
/// `logger::log` member call, and every glog `LOG`/`PLOG`/`VLOG`/`LOG_IF`
/// statement to exactly one `google::LogMessage::stream()` call.
fn emission_framework(is_method: bool, scope: &str, name: &str) -> Option<&'static str> {
    match (is_method, scope) {
        (false, "") if matches!(name, "syslog" | "vsyslog") => Some("posix.syslog"),
        (false, "spdlog") | (true, "spdlog::logger") if SPDLOG_EMIT_VERBS.contains(&name) => {
            Some("spdlog::logger")
        }
        (true, "google::LogMessage") if name == "stream" => Some("google::LogMessage"),
        _ => None,
    }
}

// --- libclang plumbing ---

unsafe fn cx_string(s: CXString) -> String {
    if s.data.is_null() {
        return String::new();
    }
    let out = std::ffi::CStr::from_ptr(clang_getCString(s))
        .to_string_lossy()
        .into_owned();
    clang_disposeString(s);
    out
}

/// (file path, line, column, offset) of a location under one of libclang's
/// three lenses; empty path when the location has no file.
unsafe fn loc_parts(
    loc: CXSourceLocation,
    which: unsafe fn(CXSourceLocation, *mut CXFile, *mut c_uint, *mut c_uint, *mut c_uint),
) -> (String, u32, u32, u32) {
    let mut file: CXFile = std::ptr::null_mut();
    let (mut line, mut col, mut off) = (0, 0, 0);
    which(loc, &mut file, &mut line, &mut col, &mut off);
    let path = if file.is_null() {
        String::new()
    } else {
        cx_string(clang_getFileName(file))
    };
    (path, line, col, off)
}

/// The `::`-joined namespaces enclosing a declaration; empty at global scope.
/// Non-namespace parents (an `extern "C"` block) are transparent.
unsafe fn namespace_path(decl: CXCursor) -> String {
    let mut parts = Vec::new();
    let mut cur = clang_getCursorSemanticParent(decl);
    while clang_Cursor_isNull(cur) == 0 && clang_isTranslationUnit(clang_getCursorKind(cur)) == 0 {
        if clang_getCursorKind(cur) == CXCursor_Namespace {
            parts.push(cx_string(clang_getCursorSpelling(cur)));
        }
        cur = clang_getCursorSemanticParent(cur);
    }
    parts.reverse();
    parts.join("::")
}

/// First child of a cursor, if any.
unsafe fn first_child(cursor: CXCursor) -> Option<CXCursor> {
    extern "C" fn grab(c: CXCursor, _p: CXCursor, data: CXClientData) -> CXChildVisitResult {
        unsafe { *(data as *mut Option<CXCursor>) = Some(c) };
        CXChildVisit_Break
    }
    let mut out: Option<CXCursor> = None;
    clang_visitChildren(cursor, grab, &mut out as *mut _ as CXClientData);
    out
}

/// Depth-first search for the declaration of kind `target` that a
/// DeclRefExpr or MemberRefExpr under `cursor` references.
unsafe fn find_ref_of_kind(cursor: CXCursor, target: CXCursorKind) -> Option<CXCursor> {
    let kind = clang_getCursorKind(cursor);
    if kind == CXCursor_DeclRefExpr || kind == CXCursor_MemberRefExpr {
        let r = clang_getCursorReferenced(cursor);
        if clang_Cursor_isNull(r) == 0 && clang_getCursorKind(r) == target {
            return Some(r);
        }
    }
    extern "C" fn walk(c: CXCursor, _p: CXCursor, data: CXClientData) -> CXChildVisitResult {
        let state = data as *mut (CXCursorKind, Option<CXCursor>);
        unsafe {
            if let Some(r) = find_ref_of_kind(c, (*state).0) {
                (*state).1 = Some(r);
                return CXChildVisit_Break;
            }
        }
        CXChildVisit_Continue
    }
    let mut state: (CXCursorKind, Option<CXCursor>) = (target, None);
    clang_visitChildren(cursor, walk, &mut state as *mut _ as CXClientData);
    state.1
}

/// Peel implicit casts / parens down to the interesting expression.
unsafe fn peel(cursor: CXCursor) -> CXCursor {
    let mut cur = cursor;
    for _ in 0..8 {
        match clang_getCursorKind(cur) {
            k if k == CXCursor_UnexposedExpr || k == CXCursor_ParenExpr => match first_child(cur) {
                Some(c) => cur = c,
                None => break,
            },
            _ => break,
        }
    }
    cur
}

fn is_literal_kind(kind: CXCursorKind) -> bool {
    kind == CXCursor_IntegerLiteral
        || kind == CXCursor_FloatingLiteral
        || kind == CXCursor_StringLiteral
        || kind == CXCursor_CharacterLiteral
        || kind == CXCursor_CXXBoolLiteralExpr
}

/// Constant-valued arguments at a call (schema v2). Enum-constant references
/// report the constant NAME (`CURLOPT_TIMEOUT`) as `named_constant` — the
/// libcurl-class discrimination the spec layer needs. Literal tokens report
/// their value as `literal`; other constant-foldable expressions (a cast of
/// `sizeof`, arithmetic on constants) report the folded value as
/// `named_constant`, mirroring goindex's folded-expression convention.
/// Evidence, never a verdict.
unsafe fn const_args_of(call: CXCursor) -> Vec<ConstArgOut> {
    let n = clang_Cursor_getNumArguments(call);
    if n <= 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..n.min(8) {
        let arg = clang_Cursor_getArgument(call, i as c_uint);
        if let Some(e) = find_ref_of_kind(arg, CXCursor_EnumConstantDecl) {
            out.push(ConstArgOut {
                index: i as u32,
                name: String::new(),
                value: cx_string(clang_getCursorSpelling(e)),
                how: "named_constant",
            });
            continue;
        }
        let ev = clang_Cursor_Evaluate(arg);
        if ev.is_null() {
            continue;
        }
        let kind = clang_EvalResult_getKind(ev);
        let value = match kind {
            k if k == CXEval_Int => Some(clang_EvalResult_getAsLongLong(ev).to_string()),
            k if k == CXEval_Float => Some(clang_EvalResult_getAsDouble(ev).to_string()),
            k if k == CXEval_StrLiteral => {
                let p = clang_EvalResult_getAsStr(ev);
                if p.is_null() {
                    None
                } else {
                    Some(format!(
                        "{:?}",
                        std::ffi::CStr::from_ptr(p).to_string_lossy()
                    ))
                }
            }
            _ => None,
        };
        clang_EvalResult_dispose(ev);
        if let Some(value) = value {
            let how = if is_literal_kind(clang_getCursorKind(peel(arg))) {
                "literal"
            } else {
                "named_constant"
            };
            out.push(ConstArgOut {
                index: i as u32,
                name: String::new(),
                value,
                how,
            });
        }
    }
    out
}

// --- the walk ---

struct PendingSite {
    site: SiteOut,
    /// USR of a virtual callee: callee_candidates is finalized after the TU
    /// walk from the override counts (1 + in-TU overriding definitions).
    virtual_usr: Option<String>,
    /// USR of the enclosing function of a mongoose `mg_match` route match:
    /// the site is kept only when that function is a registered event
    /// handler (decided after the TU walk; a handler is usually defined
    /// before the `mg_http_listen` call that registers it).
    handler_gate: Option<String>,
}

/// One G4 aggregate under construction: the packet of the function's FIRST
/// emission call into a framework, and how many calls it stands for.
struct EmissionAgg {
    site: SiteOut,
    count: u32,
}

struct WalkState {
    root: PathBuf,
    snapshot: String,
    /// compile-db mode = resolved identities (high tier); allowlist mode =
    /// extern-C names only (low tier).
    compile_db_mode: bool,
    fn_stack: Vec<CXCursor>,
    /// base-method USR -> number of overriding definitions seen in this TU.
    override_counts: HashMap<String, u32>,
    pending: Vec<PendingSite>,
    /// G4 aggregates of this TU in first-seen order (the stream must be
    /// deterministic), indexed by (enclosing function USR, framework).
    emissions: Vec<EmissionAgg>,
    emission_index: HashMap<(String, &'static str), usize>,
    /// USRs of the functions this TU passes to `mg_http_listen` as the event
    /// handler.
    http_handlers: HashSet<String>,
    calls_callee_unresolved: u32,
    /// Per-TU count of `#include` directives that resolved to no file,
    /// collected in the preprocessing pass.
    tu_includes_missing: u32,
    file_cache: HashMap<String, Vec<u8>>,
    /// Macro-expansion ranges per file (byte offsets), collected from the
    /// detailed preprocessing record in a first pass. The v2 `macro_expansion`
    /// flag is set mechanically: a site whose offset falls inside one of
    /// these ranges sits in an expansion.
    macro_ranges: HashMap<String, Vec<(u32, u32)>>,
    /// Appended to every TU's args: the engine's own needs (the vendored
    /// bundle's `-resource-dir`), after the compile db's flags so they win.
    engine_args: Vec<String>,
}

impl WalkState {
    fn in_macro_expansion(&self, file: &str, offset: u32) -> bool {
        self.macro_ranges
            .get(file)
            .is_some_and(|rs| rs.iter().any(|&(s, e)| offset >= s && offset < e))
    }
}

impl WalkState {
    /// Repo-relative forward-slashed path, or None when outside the root.
    fn rel_path(&self, path: &str) -> Option<String> {
        if path.is_empty() {
            return None;
        }
        let canon = Path::new(path)
            .canonicalize()
            .unwrap_or_else(|_| PathBuf::from(path));
        let rel = canon.strip_prefix(&self.root).ok()?;
        Some(
            rel.components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/"),
        )
    }

    fn source_slice(&mut self, path: &str, start: u32, end: u32, cap: usize) -> String {
        let bytes = self
            .file_cache
            .entry(path.to_string())
            .or_insert_with(|| std::fs::read(path).unwrap_or_default());
        let (s, e) = (start as usize, end as usize);
        if s >= e || e > bytes.len() {
            return String::new();
        }
        let e = e.min(s + cap);
        String::from_utf8_lossy(&bytes[s..e]).into_owned()
    }
}

/// Source text of a cursor's extent (via the file-location lens, which maps
/// macro locations to the expansion point).
unsafe fn extent_text(cursor: CXCursor, st: &mut WalkState, cap: usize) -> String {
    let range = clang_getCursorExtent(cursor);
    let (path, _, _, s_off) = loc_parts(clang_getRangeStart(range), clang_getFileLocation);
    let (epath, _, _, e_off) = loc_parts(clang_getRangeEnd(range), clang_getFileLocation);
    if path.is_empty() || path != epath {
        return String::new();
    }
    st.source_slice(&path, s_off, e_off, cap)
}

extern "C" fn visitor(
    cursor: CXCursor,
    _parent: CXCursor,
    data: CXClientData,
) -> CXChildVisitResult {
    let st = unsafe { &mut *(data as *mut WalkState) };
    unsafe { visit(cursor, st) };
    CXChildVisit_Continue
}

/// Pass 1: collect macro-expansion ranges from the detailed preprocessing
/// record (purely mechanical evidence for the v2 `macro_expansion` flag), and
/// count the `#include` directives that resolved to no file.
extern "C" fn macro_visitor(
    cursor: CXCursor,
    _parent: CXCursor,
    data: CXClientData,
) -> CXChildVisitResult {
    let st = unsafe { &mut *(data as *mut WalkState) };
    unsafe {
        if clang_getCursorKind(cursor) == CXCursor_MacroExpansion {
            let range = clang_getCursorExtent(cursor);
            let (path, _, _, s_off) = loc_parts(clang_getRangeStart(range), clang_getFileLocation);
            let (epath, _, _, e_off) = loc_parts(clang_getRangeEnd(range), clang_getFileLocation);
            if !path.is_empty() && path == epath {
                st.macro_ranges
                    .entry(path)
                    .or_default()
                    .push((s_off, e_off + 1));
            }
        } else if clang_getCursorKind(cursor) == CXCursor_InclusionDirective
            && clang_getIncludedFile(cursor).is_null()
        {
            st.tu_includes_missing += 1;
        }
    }
    CXChildVisit_Continue
}

unsafe fn visit(cursor: CXCursor, st: &mut WalkState) {
    let kind = clang_getCursorKind(cursor);
    let is_fn = kind == CXCursor_FunctionDecl
        || kind == CXCursor_CXXMethod
        || kind == CXCursor_Constructor
        || kind == CXCursor_Destructor
        || kind == CXCursor_FunctionTemplate;
    if is_fn {
        st.fn_stack.push(cursor);
    }
    if kind == CXCursor_CXXMethod && clang_isCursorDefinition(cursor) != 0 {
        // Count overriding DEFINITIONS toward each overridden base method:
        // this is the virtual-dispatch ambiguity the mid tier reports.
        let mut overridden: *mut CXCursor = std::ptr::null_mut();
        let mut num: c_uint = 0;
        clang_getOverriddenCursors(cursor, &mut overridden, &mut num);
        if !overridden.is_null() {
            for i in 0..num as usize {
                let usr = cx_string(clang_getCursorUSR(*overridden.add(i)));
                *st.override_counts.entry(usr).or_insert(0) += 1;
            }
            clang_disposeOverriddenCursors(overridden);
        }
    }
    if kind == CXCursor_CallExpr {
        handle_call(cursor, st);
    }
    clang_visitChildren(cursor, visitor, st as *mut WalkState as CXClientData);
    if is_fn {
        st.fn_stack.pop();
    }
}

unsafe fn handle_call(call: CXCursor, st: &mut WalkState) {
    let loc = clang_getCursorLocation(call);
    if clang_Location_isInSystemHeader(loc) != 0 {
        return;
    }
    let (exp_path, exp_line, _, exp_off) = loc_parts(loc, clang_getExpansionLocation);
    let Some(file_path) = st.rel_path(&exp_path) else {
        return; // outside the repo: not this scan's inventory
    };
    let macro_expansion = st.in_macro_expansion(&exp_path, exp_off);

    let callee = clang_getCursorReferenced(call);
    let callee_resolved =
        clang_Cursor_isNull(callee) == 0 && clang_getCursorKind(callee) != CXCursor_NoDeclFound;

    let method: String;
    let client_type: String;
    let mut receiver = String::new();
    let mut virtual_usr: Option<String> = None;
    let mut handler_gate: Option<String> = None;
    let site_kind: &'static str;

    if callee_resolved {
        let ckind = clang_getCursorKind(callee);
        method = cx_string(clang_getCursorSpelling(callee));
        let framework = match ckind {
            k if k == CXCursor_FunctionDecl => {
                emission_framework(false, &namespace_path(callee), &method)
            }
            k if k == CXCursor_CXXMethod => {
                let class_cur = clang_getCursorSemanticParent(callee);
                let class = cx_string(clang_getTypeSpelling(clang_getCursorType(class_cur)));
                emission_framework(true, &class, &method)
            }
            _ => None,
        };
        if let Some(framework) = framework {
            record_emission(
                call,
                framework,
                method,
                file_path,
                exp_line,
                macro_expansion,
                st,
            );
            return;
        }
        if method.starts_with("operator") {
            return;
        }
        match ckind {
            k if k == CXCursor_FunctionDecl => {
                if let Some((family, kind)) = c_identity(&method) {
                    client_type = family.to_string();
                    site_kind = kind;
                } else if method == "mg_match" {
                    // mongoose's glob matcher is a route match only when it
                    // matches the request URI inside an event handler. The
                    // handler half is decided after the TU walk.
                    let Some(f) = st.fn_stack.last().copied() else {
                        return;
                    };
                    let matches_uri = clang_Cursor_getNumArguments(call) > 0
                        && find_ref_of_kind(clang_Cursor_getArgument(call, 0), CXCursor_FieldDecl)
                            .is_some_and(|field| {
                                cx_string(clang_getCursorSpelling(field)) == "uri"
                            });
                    if !matches_uri {
                        return;
                    }
                    handler_gate = Some(cx_string(clang_getCursorUSR(f)));
                    client_type = MONGOOSE_MESSAGE.to_string();
                    site_kind = SITE_KIND_SERVER_ENTRY;
                } else {
                    return;
                }
            }
            k if k == CXCursor_CXXMethod => {
                if !st.compile_db_mode {
                    return; // C++ without a db is a documented abstention
                }
                let class_cur = clang_getCursorSemanticParent(callee);
                let type_name = cx_string(clang_getTypeSpelling(clang_getCursorType(class_cur)));
                let is_virtual = clang_CXXMethod_isVirtual(callee) != 0;
                let lower = method.to_ascii_lowercase();
                let strong = STRONG_VERBS.contains(&lower.as_str());
                let weak = WEAK_VERBS.contains(&lower.as_str());
                let (class_file, ..) = loc_parts(
                    clang_getCursorLocation(class_cur),
                    clang_getExpansionLocation,
                );
                let external = st.rel_path(&class_file).is_none();
                let is_stub = type_name.ends_with("::Stub");
                // The C++ candidate gate: a `::Stub` identity (gRPC codegen),
                // a strong I/O verb, or a weak verb whose receiver is a
                // third-party type or a virtual interface (the mid tier).
                if !(is_stub || strong || (weak && (external || is_virtual))) {
                    return;
                }
                client_type = type_name;
                site_kind = "";
                if is_virtual {
                    virtual_usr = Some(cx_string(clang_getCursorUSR(callee)));
                }
                // Receiver source: the member access's base expression.
                if let Some(member) = first_child(call) {
                    if clang_getCursorKind(member) == CXCursor_MemberRefExpr {
                        if let Some(base) = first_child(member) {
                            receiver = extent_text(base, st, 200);
                        }
                    }
                }
            }
            k if k == CXCursor_Constructor => {
                // G3: constructing a thread type WITH a callable is the
                // registration. The default constructor starts nothing and a
                // copy/move only transfers a thread that already runs. A
                // thread built inside a library header (`emplace_back`) sits
                // in a system header and is a documented abstention.
                if !st.compile_db_mode {
                    return; // C++ without a db is a documented abstention
                }
                let class_cur = clang_getCursorSemanticParent(callee);
                let type_name = cx_string(clang_getTypeSpelling(clang_getCursorType(class_cur)));
                if !THREAD_TYPES.contains(&type_name.as_str())
                    || clang_Cursor_getNumArguments(call) < 1
                    || clang_CXXConstructor_isCopyConstructor(callee) != 0
                    || clang_CXXConstructor_isMoveConstructor(callee) != 0
                {
                    return;
                }
                client_type = type_name;
                site_kind = SITE_KIND_BACKGROUND_JOB;
            }
            _ => return, // other constructors, destructors, conversions: not sites
        }
    } else if !st.compile_db_mode {
        // No-db mode: an unresolved callee still SPELLS its name on the call
        // cursor; only the curated extern-C allowlist is trusted at low tier.
        method = cx_string(clang_getCursorSpelling(call));
        if let Some(framework) = emission_framework(false, "", &method) {
            record_emission(
                call,
                framework,
                method,
                file_path,
                exp_line,
                macro_expansion,
                st,
            );
            return;
        }
        let Some((family, kind)) = c_identity(&method) else {
            if method.is_empty() {
                st.calls_callee_unresolved += 1;
            }
            return;
        };
        client_type = family.to_string();
        site_kind = kind;
    } else {
        // Compile-db mode with an unresolved callee: the uninstantiated
        // template's dependent call lands here. Counted, never guessed.
        st.calls_callee_unresolved += 1;
        return;
    }

    if method.is_empty() {
        return;
    }
    if method == "mg_http_listen" && clang_Cursor_getNumArguments(call) > 2 {
        // The event handler this listener dispatches to (argument 2).
        if let Some(f) = find_ref_of_kind(clang_Cursor_getArgument(call, 2), CXCursor_FunctionDecl)
        {
            st.http_handlers.insert(cx_string(clang_getCursorUSR(f)));
        }
    }

    let (symbol, enclosing_body) = match st.fn_stack.last().copied() {
        Some(f) => (
            cx_string(clang_getCursorSpelling(f)),
            extent_text(f, st, 8000),
        ),
        None => (String::new(), String::new()),
    };
    let snippet = extent_text(call, st, 2000);
    let const_args = const_args_of(call);
    let site_key = format!("{file_path}:{exp_line}:{client_type}:{method}");

    st.pending.push(PendingSite {
        site: SiteOut {
            packet_schema: PACKET_SCHEMA,
            site_key,
            snapshot_id: st.snapshot.clone(),
            file_path,
            line_number: exp_line,
            symbol,
            method,
            receiver,
            client_type,
            snippet,
            enclosing_function_body: enclosing_body,
            callers: Vec::new(),
            callees: Vec::new(),
            client_construction: Vec::new(),
            provenance: ProvenanceOut {
                client_type_resolved: st.compile_db_mode,
                ..Default::default()
            },
            lang: "c_cpp",
            const_args,
            macro_expansion,
            site_kind,
        },
        virtual_usr,
        handler_gate,
    });
}

/// Count one emission call toward its (enclosing function, framework)
/// aggregate. Log statements are the highest-volume site class there is, so
/// the stream carries one packet per aggregate, never one per log line. A
/// call outside any function (a namespace-scope initializer) has no function
/// to aggregate under and is not inventoried.
unsafe fn record_emission(
    call: CXCursor,
    framework: &'static str,
    method: String,
    file_path: String,
    line: u32,
    macro_expansion: bool,
    st: &mut WalkState,
) {
    let Some(f) = st.fn_stack.last().copied() else {
        return;
    };
    let key = (cx_string(clang_getCursorUSR(f)), framework);
    let idx = match st.emission_index.get(&key) {
        Some(&idx) => idx,
        None => {
            let site = SiteOut {
                packet_schema: PACKET_SCHEMA,
                site_key: format!("{file_path}:{line}:{framework}:{method}"),
                snapshot_id: st.snapshot.clone(),
                file_path,
                line_number: line,
                symbol: cx_string(clang_getCursorSpelling(f)),
                method,
                receiver: String::new(),
                client_type: framework.to_string(),
                snippet: extent_text(call, st, 2000),
                enclosing_function_body: extent_text(f, st, 8000),
                callers: Vec::new(),
                callees: Vec::new(),
                client_construction: Vec::new(),
                provenance: ProvenanceOut {
                    client_type_resolved: st.compile_db_mode,
                    ..Default::default()
                },
                lang: "c_cpp",
                const_args: Vec::new(),
                macro_expansion: false,
                site_kind: SITE_KIND_EMISSION,
            };
            st.emissions.push(EmissionAgg { site, count: 0 });
            st.emission_index.insert(key, st.emissions.len() - 1);
            st.emissions.len() - 1
        }
    };
    let agg = &mut st.emissions[idx];
    agg.count += 1;
    // Set when ANY counted call sits in an expansion (rustindex precedent).
    agg.site.macro_expansion |= macro_expansion;
}

/// Is this diagnostic about an identifier with no visible declaration? The
/// libclang C API exposes no diagnostic IDs, so the stable message stems are
/// matched. A miss here only lowers `decls_unresolved`: the TU is still
/// marked incomplete by its error count.
fn is_undeclared_diagnostic(message: &str) -> bool {
    const STEMS: &[&str] = &[
        "undeclared identifier",
        "call to undeclared function",
        "implicit declaration of function",
        "unknown type name",
        "no type named",
        "no member named",
        "no template named",
    ];
    STEMS.iter().any(|stem| message.contains(stem))
}

/// What one parsed TU produced: its sites, plus the evidence of how complete
/// the parse was (po-av01j.138).
struct TuOutcome {
    sites: Vec<SiteOut>,
    /// Error or fatal diagnostics raised by the parse.
    errors: u32,
    includes_missing: u32,
    decls_unresolved: u32,
}

/// Count the parse's error-severity diagnostics, and the subset that name an
/// undeclared identifier.
unsafe fn error_diagnostics(tu: CXTranslationUnit) -> (u32, u32) {
    let (mut errors, mut undeclared) = (0u32, 0u32);
    for i in 0..clang_getNumDiagnostics(tu) {
        let d = clang_getDiagnostic(tu, i);
        if clang_getDiagnosticSeverity(d) >= CXDiagnostic_Error {
            errors += 1;
            if is_undeclared_diagnostic(&cx_string(clang_getDiagnosticSpelling(d))) {
                undeclared += 1;
            }
        }
        clang_disposeDiagnostic(d);
    }
    (errors, undeclared)
}

/// Parse one TU and drain its sites. Returns None when the TU fails to parse.
unsafe fn walk_tu(
    index: CXIndex,
    file: &Path,
    args: &[String],
    st: &mut WalkState,
) -> Option<TuOutcome> {
    let path = CString::new(file.to_string_lossy().as_bytes()).ok()?;
    let c_args: Vec<CString> = args
        .iter()
        .chain(st.engine_args.iter())
        .filter_map(|a| CString::new(a.as_bytes()).ok())
        .collect();
    let arg_ptrs: Vec<*const std::os::raw::c_char> = c_args.iter().map(|a| a.as_ptr()).collect();
    // The detailed preprocessing record is what makes the macro_expansion
    // flag mechanical: it carries every expansion's range.
    let options = CXTranslationUnit_DetailedPreprocessingRecord
        | if st.compile_db_mode {
            CXTranslationUnit_None
        } else {
            // Keep going past missing includes: the allowlist tier expects them.
            CXTranslationUnit_KeepGoing
        };
    let tu = clang_parseTranslationUnit(
        index,
        path.as_ptr(),
        arg_ptrs.as_ptr(),
        arg_ptrs.len() as i32,
        std::ptr::null_mut(),
        0,
        options,
    );
    if tu.is_null() {
        return None;
    }
    st.fn_stack.clear();
    st.override_counts.clear();
    st.pending.clear();
    st.emissions.clear();
    st.emission_index.clear();
    st.http_handlers.clear();
    st.macro_ranges.clear();
    st.tu_includes_missing = 0;
    let root_cursor = clang_getTranslationUnitCursor(tu);
    clang_visitChildren(
        root_cursor,
        macro_visitor,
        st as *mut WalkState as CXClientData,
    );
    clang_visitChildren(root_cursor, visitor, st as *mut WalkState as CXClientData);
    // Finalize the mid tier: a virtual callee's ambiguity is 1 (its own
    // definition) + the overriding definitions this TU declares. A gated
    // mongoose route match survives only inside a registered event handler.
    let mut sites: Vec<SiteOut> = st
        .pending
        .drain(..)
        .filter(|p| {
            p.handler_gate
                .as_ref()
                .is_none_or(|usr| st.http_handlers.contains(usr))
        })
        .map(|mut p| {
            if let Some(usr) = p.virtual_usr {
                p.site.provenance.callee_candidates =
                    1 + st.override_counts.get(&usr).copied().unwrap_or(0);
            }
            p.site
        })
        .collect();
    // Category and count ride const_args (the rvl-core G4 convention).
    sites.extend(st.emissions.drain(..).map(|mut agg| {
        agg.site.const_args = vec![
            ConstArgOut {
                index: 0,
                name: "emission_category".to_string(),
                value: EMISSION_CATEGORY_LOG.to_string(),
                how: "aggregate",
            },
            ConstArgOut {
                index: 0,
                name: "emission_count".to_string(),
                value: agg.count.to_string(),
                how: "aggregate",
            },
        ];
        agg.site
    }));
    let (errors, decls_unresolved) = error_diagnostics(tu);
    clang_disposeTranslationUnit(tu);
    Some(TuOutcome {
        sites,
        errors,
        includes_missing: st.tu_includes_missing,
        decls_unresolved,
    })
}

/// Bounded walk for no-db mode: `.c` sources parsed with the allowlist tier,
/// C++ sources counted as the documented abstention class.
fn walk_no_db(root: &Path) -> (Vec<PathBuf>, u32) {
    const SKIP_DIRS: &[&str] = &[
        ".git",
        "node_modules",
        "target",
        "vendor",
        "build",
        "__pycache__",
    ];
    let mut c_files = Vec::new();
    let mut cpp_skipped = 0u32;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() {
                let name = entry.file_name();
                if !SKIP_DIRS.contains(&name.to_string_lossy().as_ref()) {
                    stack.push(path);
                }
            } else if ft.is_file() {
                match path.extension().and_then(|e| e.to_str()) {
                    Some("c") => c_files.push(path),
                    Some("cc" | "cpp" | "cxx") => cpp_skipped += 1,
                    _ => {}
                }
            }
        }
    }
    c_files.sort();
    (c_files, cpp_skipped)
}

/// Emit the packet stream for `root` to stdout.
pub fn run(root: &Path, name: &str, files: &[String]) -> anyhow::Result<()> {
    let engine = load_engine().map_err(|e| anyhow::anyhow!(e))?;
    let root = root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("cannot resolve --root {}: {e}", root.display()))?;
    let file_filter: HashSet<&str> = files.iter().map(|s| s.as_str()).collect();

    let db = find_compile_db(&root);
    let compile_db_mode = db.is_some();
    let (jobs, cpp_skipped) = match &db {
        Some(db_path) => (load_compile_db(db_path, &root)?, 0),
        None => {
            let (c_files, skipped) = walk_no_db(&root);
            (
                c_files
                    .into_iter()
                    .map(|file| TuJob {
                        file,
                        args: Vec::new(),
                    })
                    .collect(),
                skipped,
            )
        }
    };

    let mut st = WalkState {
        root: root.clone(),
        snapshot: name.to_string(),
        compile_db_mode,
        fn_stack: Vec::new(),
        override_counts: HashMap::new(),
        pending: Vec::new(),
        emissions: Vec::new(),
        emission_index: HashMap::new(),
        http_handlers: HashSet::new(),
        calls_callee_unresolved: 0,
        tu_includes_missing: 0,
        file_cache: HashMap::new(),
        macro_ranges: HashMap::new(),
        engine_args: engine.source.parse_args(),
    };

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut seen_keys: HashSet<String> = HashSet::new();
    let (mut tus_total, mut tus_parsed, mut tus_failed) = (0u32, 0u32, 0u32);
    let (mut includes_missing, mut decls_unresolved) = (0u32, 0u32);
    let mut tus_incomplete_paths: Vec<String> = Vec::new();

    let index = unsafe { clang_createIndex(0, 0) };
    let mut jobs = jobs;
    jobs.sort_by(|a, b| a.file.cmp(&b.file));
    for job in &jobs {
        // Repo-relative spelling for the --files filter.
        let rel = st
            .rel_path(&job.file.to_string_lossy())
            .unwrap_or_else(|| job.file.to_string_lossy().into_owned());
        if !file_filter.is_empty() && !file_filter.contains(rel.as_str()) {
            continue;
        }
        tus_total += 1;
        if !job.file.is_file() {
            tus_failed += 1;
            continue;
        }
        match unsafe { walk_tu(index, &job.file, &job.args, &mut st) } {
            Some(tu) => {
                tus_parsed += 1;
                includes_missing += tu.includes_missing;
                decls_unresolved += tu.decls_unresolved;
                // An incomplete TU still emits the sites that DID resolve:
                // they are real evidence, and dropping them would turn a
                // partial answer into a bigger false negative. What it must
                // never do is count as a clean parse.
                if tu.errors > 0 || tu.includes_missing > 0 {
                    tus_incomplete_paths.push(rel.clone());
                }
                for s in tu.sites {
                    // A header included by many TUs re-emits its sites; the
                    // stream carries each site_key once.
                    if seen_keys.insert(s.site_key.clone()) {
                        writeln!(out, "{}", serde_json::to_string(&s)?)?;
                    }
                }
            }
            None => tus_failed += 1,
        }
    }
    unsafe { clang_disposeIndex(index) };
    tus_incomplete_paths.sort();

    let stats = StatsOut {
        kind: "retrieval_stats",
        packet_schema: PACKET_SCHEMA,
        snapshot_id: name.to_string(),
        lang: "c_cpp",
        mode: if compile_db_mode {
            "compile_db"
        } else {
            "allowlist"
        },
        tus_total,
        tus_parsed,
        tus_failed,
        tus_incomplete: tus_incomplete_paths.len() as u32,
        tus_incomplete_paths,
        includes_missing,
        decls_unresolved,
        calls_callee_unresolved: st.calls_callee_unresolved,
        cpp_files_skipped_no_db: cpp_skipped,
    };
    writeln!(out, "{}", serde_json::to_string(&stats)?)?;
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_split_honors_quotes_and_escapes() {
        assert_eq!(
            shell_split(r#"cc -I"my dir" -DNAME=\"x\" -c src/a.c"#),
            vec!["cc", "-Imy dir", "-DNAME=\"x\"", "-c", "src/a.c"]
        );
        assert_eq!(shell_split("  cc   -c  a.c "), vec!["cc", "-c", "a.c"]);
    }

    #[test]
    fn tu_parse_args_strips_compile_only_flags_and_resolves_includes() {
        let dir = Path::new("/repo");
        let file = Path::new("/repo/src/main.c");
        let argv: Vec<String> = [
            "cc",
            "-Ivendor",
            "-I",
            "inc",
            "-O2",
            "-o",
            "out.o",
            "-c",
            "src/main.c",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(
            tu_parse_args(&argv, dir, file),
            vec!["-I/repo/vendor", "-I", "/repo/inc", "-O2"]
        );
    }

    #[test]
    fn undeclared_diagnostics_are_recognized_and_other_errors_are_not() {
        for m in [
            "use of undeclared identifier 'CURL'",
            "call to undeclared function 'curl_easy_init'; ISO C99 and later do not support implicit function declarations",
            "implicit declaration of function 'foo' is invalid in C99",
            "unknown type name 'CURL'",
            "no type named 'Stub' in namespace 'rpc'",
            "no member named 'perform' in 'Client'",
        ] {
            assert!(is_undeclared_diagnostic(m), "{m}");
        }
        assert!(!is_undeclared_diagnostic("'curl/curl.h' file not found"));
        assert!(!is_undeclared_diagnostic("expected ';' after expression"));
    }

    #[test]
    fn c_family_covers_the_curated_allowlist_and_nothing_else() {
        assert_eq!(c_family("curl_easy_perform"), Some("libcurl.CURL"));
        assert_eq!(c_family("PQexec"), Some("libpq.PGconn"));
        assert_eq!(c_family("redisCommand"), Some("hiredis.redisContext"));
        assert_eq!(c_family("connect"), Some("posix.socket"));
        // read/write are the documented fd-ambiguity abstention.
        assert_eq!(c_family("read"), None);
        assert_eq!(c_family("write"), None);
        assert_eq!(c_family("printf"), None);
    }

    #[test]
    fn emission_framework_is_scoped_to_the_framework_identity() {
        assert_eq!(
            emission_framework(false, "", "syslog"),
            Some("posix.syslog")
        );
        assert_eq!(
            emission_framework(false, "", "vsyslog"),
            Some("posix.syslog")
        );
        assert_eq!(
            emission_framework(true, "spdlog::logger", "warn"),
            Some("spdlog::logger")
        );
        // SPDLOG_* macros expand to logger::log.
        assert_eq!(
            emission_framework(true, "spdlog::logger", "log"),
            Some("spdlog::logger")
        );
        assert_eq!(
            emission_framework(false, "spdlog", "info"),
            Some("spdlog::logger")
        );
        assert_eq!(
            emission_framework(true, "google::LogMessage", "stream"),
            Some("google::LogMessage")
        );
        // Configuration surface of a framework is not emission.
        assert_eq!(emission_framework(false, "", "openlog"), None);
        assert_eq!(
            emission_framework(true, "spdlog::logger", "set_level"),
            None
        );
        assert_eq!(emission_framework(false, "spdlog", "set_level"), None);
        // The same names outside the framework's scope abstain.
        assert_eq!(emission_framework(false, "app", "syslog"), None);
        assert_eq!(emission_framework(true, "app::Report", "info"), None);
        assert_eq!(emission_framework(false, "", "info"), None);
        assert_eq!(
            emission_framework(true, "std::stringstream", "stream"),
            None
        );
    }

    #[test]
    fn c_identity_keeps_thread_starts_off_the_g1_table() {
        assert_eq!(c_identity("PQexec"), Some(("libpq.PGconn", "")));
        assert_eq!(
            c_identity("pthread_create"),
            Some(("posix.pthread", SITE_KIND_BACKGROUND_JOB))
        );
        // A thread start is a G3 registration, never a classic G1 call site.
        assert_eq!(c_family("pthread_create"), None);
        // Lifecycle calls around the thread are not registrations.
        assert_eq!(c_identity("pthread_join"), None);
        assert_eq!(c_identity("pthread_detach"), None);
    }

    #[test]
    fn server_family_names_the_registrations_and_nothing_else() {
        assert_eq!(
            server_family("mg_set_request_handler"),
            Some("civetweb.mg_context")
        );
        assert_eq!(server_family("mg_http_listen"), Some("mongoose.mg_mgr"));
        assert_eq!(
            server_family("mg_http_match_uri"),
            Some("mongoose.mg_http_message")
        );
        // mg_match is a general glob matcher: it is a route only under the
        // event-handler gate, never by name alone.
        assert_eq!(server_family("mg_match"), None);
        // Plain listeners and starts carry no HTTP route surface.
        assert_eq!(server_family("mg_listen"), None);
        assert_eq!(server_family("mg_start"), None);
        // The two tables are disjoint: a client call is never a server entry.
        assert_eq!(server_family("curl_easy_perform"), None);
        assert_eq!(c_family("mg_http_listen"), None);
    }
}
