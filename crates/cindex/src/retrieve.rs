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

use crate::PACKET_SCHEMA;

/// Load libclang at runtime and report its version string. Fails with
/// actionable guidance when no library can be found — rvl surfaces this
/// stderr, so a detected C/C++ repo fails CLOSED rather than silently
/// under-reporting.
pub fn load_engine() -> Result<String, String> {
    if !clang_sys::is_loaded() {
        clang_sys::load().map_err(|e| {
            format!(
                "cindex requires libclang (engine pin po-ae75b.9) and none could be loaded: {e}. \
                 Install one (e.g. `apt install libclang-dev`) or point LIBCLANG_PATH at it."
            )
        })?;
    }
    let version = unsafe { cx_string(clang_getClangVersion()) };
    Ok(version)
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
    tus_parsed: u32,
    /// TUs that failed to parse: counted and documented, never guessed at.
    tus_failed: u32,
    /// Call expressions whose callee could not be resolved (template-dependent
    /// callees in uninstantiated templates are the dominant class): documented
    /// abstentions, never guesses.
    calls_unresolved: u32,
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

/// Depth-first search for a DeclRefExpr referencing an enum constant.
unsafe fn find_enum_ref(cursor: CXCursor) -> Option<CXCursor> {
    if clang_getCursorKind(cursor) == CXCursor_DeclRefExpr {
        let r = clang_getCursorReferenced(cursor);
        if clang_Cursor_isNull(r) == 0 && clang_getCursorKind(r) == CXCursor_EnumConstantDecl {
            return Some(r);
        }
    }
    extern "C" fn walk(c: CXCursor, _p: CXCursor, data: CXClientData) -> CXChildVisitResult {
        let found = data as *mut Option<CXCursor>;
        unsafe {
            if let Some(r) = find_enum_ref(c) {
                *found = Some(r);
                return CXChildVisit_Break;
            }
        }
        CXChildVisit_Continue
    }
    let mut found: Option<CXCursor> = None;
    clang_visitChildren(cursor, walk, &mut found as *mut _ as CXClientData);
    found
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
        if let Some(e) = find_enum_ref(arg) {
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
    calls_unresolved: u32,
    file_cache: HashMap<String, Vec<u8>>,
    /// Macro-expansion ranges per file (byte offsets), collected from the
    /// detailed preprocessing record in a first pass. The v2 `macro_expansion`
    /// flag is set mechanically: a site whose offset falls inside one of
    /// these ranges sits in an expansion.
    macro_ranges: HashMap<String, Vec<(u32, u32)>>,
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
/// record. Purely mechanical evidence for the v2 `macro_expansion` flag.
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

    if callee_resolved {
        let ckind = clang_getCursorKind(callee);
        method = cx_string(clang_getCursorSpelling(callee));
        if method.starts_with("operator") {
            return;
        }
        match ckind {
            k if k == CXCursor_FunctionDecl => {
                let Some(family) = c_family(&method) else {
                    return;
                };
                client_type = family.to_string();
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
            _ => return, // constructors, destructors, conversions: not G1 calls
        }
    } else if !st.compile_db_mode {
        // No-db mode: an unresolved callee still SPELLS its name on the call
        // cursor; only the curated extern-C allowlist is trusted at low tier.
        method = cx_string(clang_getCursorSpelling(call));
        let Some(family) = c_family(&method) else {
            if method.is_empty() {
                st.calls_unresolved += 1;
            }
            return;
        };
        client_type = family.to_string();
    } else {
        // Compile-db mode with an unresolved callee: the uninstantiated
        // template's dependent call lands here. Counted, never guessed.
        st.calls_unresolved += 1;
        return;
    }

    if method.is_empty() {
        return;
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
        },
        virtual_usr,
    });
}

/// Parse one TU and drain its sites. Returns None when the TU fails to parse.
unsafe fn walk_tu(
    index: CXIndex,
    file: &Path,
    args: &[String],
    st: &mut WalkState,
) -> Option<Vec<SiteOut>> {
    let path = CString::new(file.to_string_lossy().as_bytes()).ok()?;
    let c_args: Vec<CString> = args
        .iter()
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
    st.macro_ranges.clear();
    let root_cursor = clang_getTranslationUnitCursor(tu);
    clang_visitChildren(
        root_cursor,
        macro_visitor,
        st as *mut WalkState as CXClientData,
    );
    clang_visitChildren(root_cursor, visitor, st as *mut WalkState as CXClientData);
    // Finalize the mid tier: a virtual callee's ambiguity is 1 (its own
    // definition) + the overriding definitions this TU declares.
    let sites = st
        .pending
        .drain(..)
        .map(|mut p| {
            if let Some(usr) = p.virtual_usr {
                p.site.provenance.callee_candidates =
                    1 + st.override_counts.get(&usr).copied().unwrap_or(0);
            }
            p.site
        })
        .collect();
    clang_disposeTranslationUnit(tu);
    Some(sites)
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
    load_engine().map_err(|e| anyhow::anyhow!(e))?;
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
        calls_unresolved: 0,
        file_cache: HashMap::new(),
        macro_ranges: HashMap::new(),
    };

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut seen_keys: HashSet<String> = HashSet::new();
    let (mut tus_total, mut tus_parsed, mut tus_failed) = (0u32, 0u32, 0u32);

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
            Some(sites) => {
                tus_parsed += 1;
                for s in sites {
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
        calls_unresolved: st.calls_unresolved,
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
}
