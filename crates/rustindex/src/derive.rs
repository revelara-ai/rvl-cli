//! SCIP index → Site packets.
//!
//! Occurrences are matched against the catalogs, then the SOURCE is re-read
//! for everything the index does not carry: statement snippets, receivers,
//! constant arguments, macro-invocation spans, and the dyn-receiver check
//! that separates the mid tier from abstention.
//!
//! Confidence tiers (charter, po-ae75b.8):
//! - high: the moniker resolves to a concrete impl (`impl#[Type]…`) — the
//!   concrete type IS the client_type.
//! - mid: trait-level dispatch whose receiver is visibly `dyn Trait` in the
//!   enclosing source — client_type is `dyn crate::Trait`.
//! - abstain: trait-level dispatch that is not visibly dyn (uninstantiated
//!   generics land here) — empty client_type, `client_type_resolved: false`,
//!   so propagation abstains rather than guessing.
//! - macro-stamped: any site inside a macro invocation span carries
//!   `macro_expansion: true` (mechanically derived by paren-matching the
//!   invocation from source; sites whose evidence lives inside an expansion
//!   the index cannot see are exactly the ones flagged).

use crate::catalog::{classify, SiteClass};
use crate::symbol::{parse, ParsedSymbol, SymbolKind};
use rvl_core::{ConfigFact, ConstArg, Provenance, RepoConfig, Site, Snippet};
use std::collections::HashMap;
use std::path::Path;

/// SCIP symbol-role bit marking a definition.
const ROLE_DEFINITION: i32 = 1;

/// Budgets: keep packets bounded the way the sibling helpers do.
const MAX_CALLERS: usize = 3;
const MAX_CONSTRUCTIONS: usize = 3;
const MAX_SNIPPET_CHARS: usize = 1500;
const MAX_BODY_CHARS: usize = 6000;
const MAX_CALLER_SOURCE_CHARS: usize = 600;
const MAX_ARGS_SCAN_BYTES: usize = 600;

/// A position in a document, 0-based (SCIP convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Pos {
    line: usize,
    ch: usize,
}

/// A decoded SCIP range: same-line `[l, s, e]` or multi-line `[l, s, l2, e]`.
#[derive(Debug, Clone, Copy)]
struct SRange {
    start: Pos,
    end: Pos,
}

fn decode_range(range: &[i32]) -> Option<SRange> {
    match range {
        [l, s, e] => Some(SRange {
            start: Pos {
                line: *l as usize,
                ch: *s as usize,
            },
            end: Pos {
                line: *l as usize,
                ch: *e as usize,
            },
        }),
        [l, s, l2, e] => Some(SRange {
            start: Pos {
                line: *l as usize,
                ch: *s as usize,
            },
            end: Pos {
                line: *l2 as usize,
                ch: *e as usize,
            },
        }),
        _ => None,
    }
}

/// One loaded document: source text plus the structural indexes derived from
/// its occurrences.
struct Doc {
    rel_path: String,
    text: String,
    line_starts: Vec<usize>,
    /// Function definitions with body ranges: (name, symbol, body byte range).
    fn_defs: Vec<(String, String, std::ops::Range<usize>)>,
    /// Byte spans of macro invocations (`name!(...)` including the name).
    macro_spans: Vec<std::ops::Range<usize>>,
}

impl Doc {
    fn offset(&self, p: Pos) -> Option<usize> {
        let base = *self.line_starts.get(p.line)?;
        let next = self
            .line_starts
            .get(p.line + 1)
            .copied()
            .unwrap_or(self.text.len());
        Some((base + p.ch).min(next.max(base)))
    }

    fn slice(&self, r: SRange) -> Option<&str> {
        let s = self.offset(r.start)?;
        let e = self.offset(r.end)?;
        self.text.get(s..e)
    }

    /// The line's text (without newline), for snippet building.
    fn line(&self, idx: usize) -> Option<&str> {
        let s = *self.line_starts.get(idx)?;
        let e = self
            .line_starts
            .get(idx + 1)
            .copied()
            .unwrap_or(self.text.len());
        self.text
            .get(s..e)
            .map(|l| l.trim_end_matches(['\n', '\r']))
    }

    fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// Innermost function definition whose body contains `off`.
    fn enclosing_fn(&self, off: usize) -> Option<&(String, String, std::ops::Range<usize>)> {
        self.fn_defs
            .iter()
            .filter(|(_, _, r)| r.contains(&off))
            .min_by_key(|(_, _, r)| r.end - r.start)
    }

    fn in_macro_span(&self, off: usize) -> bool {
        self.macro_spans.iter().any(|r| r.contains(&off))
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut v = vec![0usize];
    for (i, b) in text.bytes().enumerate() {
        if b == b'\n' {
            v.push(i + 1);
        }
    }
    v
}

fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        s[..end].to_string()
    }
}

/// Expand the statement around `line` (0-based): up while the previous line
/// does not terminate a statement, down until this statement terminates.
/// Bounded, crude, and source-faithful — the same pragmatism pyindex uses.
fn statement_lines(doc: &Doc, line: usize) -> (usize, usize) {
    let mut start = line;
    let mut steps = 0;
    while start > 0 && steps < 8 {
        let prev = doc.line(start - 1).unwrap_or("").trim();
        if prev.is_empty()
            || prev.ends_with(';')
            || prev.ends_with('{')
            || prev.ends_with('}')
            || prev.starts_with("//")
        {
            break;
        }
        start -= 1;
        steps += 1;
    }
    let mut end = line;
    let mut dsteps = 0;
    while dsteps < 12 {
        let cur = doc.line(end).unwrap_or("").trim();
        if cur.ends_with(';') || cur.ends_with('{') {
            break;
        }
        match doc.line(end + 1) {
            Some(next) if !next.trim().starts_with('}') && !next.trim().is_empty() => {
                end += 1;
                dsteps += 1;
            }
            _ => break,
        }
    }
    (start, end.min(doc.line_count().saturating_sub(1)))
}

fn statement_snippet(doc: &Doc, line: usize) -> String {
    let (start, end) = statement_lines(doc, line);
    let mut out = String::new();
    for l in start..=end {
        if let Some(t) = doc.line(l) {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(t);
        }
    }
    cap(&out, MAX_SNIPPET_CHARS)
}

/// The receiver expression before a method-call token: the `a.b.c` /
/// `Type::assoc` chain read backwards from the dot. Empty for chained calls
/// whose receiver is a call result (`.timeout(...).send()`).
fn receiver_before(text: &str, tok_start: usize) -> String {
    let bytes = text.as_bytes();
    if tok_start == 0 {
        return String::new();
    }
    let mut i = tok_start;
    // Expect the `.` or `::` immediately before the token.
    if bytes[i - 1] == b'.' {
        i -= 1;
    } else if i >= 2 && &bytes[i - 2..i] == b"::" {
        i -= 2;
    } else {
        return String::new();
    }
    let start = {
        let mut j = i;
        while j > 0 {
            let c = bytes[j - 1] as char;
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':' {
                j -= 1;
            } else {
                break;
            }
        }
        j
    };
    text[start..i]
        .trim_matches(|c| c == '.' || c == ':')
        .to_string()
}

/// Whether `recv` is declared with a visibly-`dyn` type inside `body`
/// (`e: &dyn Executor`, `let e: Box<dyn Executor> = …`). The mid-tier test:
/// conservative by design — anything not visibly dyn abstains.
fn receiver_is_dyn(body: &str, recv: &str) -> bool {
    if recv.is_empty() || !recv.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let bytes = body.as_bytes();
    let mut from = 0;
    while let Some(pos) = body[from..].find(recv) {
        let at = from + pos;
        from = at + recv.len();
        let before_ok = at == 0 || {
            let c = bytes[at - 1] as char;
            !(c.is_ascii_alphanumeric() || c == '_')
        };
        let after = at + recv.len();
        let after_ok = after >= body.len() || {
            let c = bytes[after] as char;
            !(c.is_ascii_alphanumeric() || c == '_')
        };
        if !(before_ok && after_ok) {
            continue;
        }
        // `recv : <type-ish>` — scan the type segment for `dyn`.
        let rest = body[after..].trim_start();
        if let Some(ty) = rest.strip_prefix(':') {
            let seg: String = ty
                .chars()
                .take_while(|c| !matches!(c, ',' | ')' | '=' | ';' | '{'))
                .collect();
            if seg.contains("dyn ") {
                return true;
            }
        }
    }
    false
}

/// Constant-valued arguments at a call site, re-read from source. Literals
/// report `how: "literal"`; `Duration::from_*` constant expressions report
/// `how: "named_constant"` (cheaply resolvable, no constant propagation).
fn const_args_at(text: &str, tok_end: usize) -> Vec<ConstArg> {
    let bytes = text.as_bytes();
    let mut i = tok_end;
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'(' {
        return Vec::new();
    }
    let open = i;
    let mut depth = 0usize;
    let mut in_str = false;
    let mut close = None;
    let mut j = open;
    while j < bytes.len() && j - open <= MAX_ARGS_SCAN_BYTES {
        let c = bytes[j] as char;
        if in_str {
            if c == '\\' {
                j += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }
        j += 1;
    }
    let Some(close) = close else {
        return Vec::new();
    };
    let inner = &text[open + 1..close];
    // Split top-level commas.
    let mut args = Vec::new();
    let mut depth = 0usize;
    let mut in_str = false;
    let mut cur = String::new();
    let mut chars = inner.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            cur.push(c);
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                cur.push(c);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(c);
            }
            ')' | ']' | '}' => {
                depth = depth.saturating_sub(1);
                cur.push(c);
            }
            ',' if depth == 0 => {
                args.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        args.push(cur);
    }

    let mut out = Vec::new();
    for (idx, raw) in args.iter().enumerate() {
        let a = raw.trim();
        let how = if is_int_literal(a)
            || is_float_literal(a)
            || a == "true"
            || a == "false"
            || (a.starts_with('"') && a.ends_with('"') && a.len() >= 2)
        {
            "literal"
        } else if a.contains("Duration::from_") && a.ends_with(')') {
            "named_constant"
        } else {
            continue;
        };
        out.push(ConstArg {
            index: idx as u32,
            name: String::new(), // Rust has no keyword arguments
            value: cap(a, 120),
            how: how.into(),
        });
    }
    out
}

fn is_int_literal(s: &str) -> bool {
    let core: String = s
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .collect();
    if core.is_empty() || !s.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    let rest = &s[core.len()..];
    rest.is_empty()
        || [
            "u8", "u16", "u32", "u64", "usize", "i8", "i16", "i32", "i64", "isize",
        ]
        .contains(&rest)
}

fn is_float_literal(s: &str) -> bool {
    let mut dots = 0;
    if s.is_empty() || !s.starts_with(|c: char| c.is_ascii_digit()) {
        return false;
    }
    for c in s.chars() {
        match c {
            '.' => dots += 1,
            c if c.is_ascii_digit() || c == '_' => {}
            _ => return false,
        }
    }
    dots == 1
}

/// A matched occurrence, pre-materialization.
struct Candidate {
    doc_idx: usize,
    range: SRange,
    sym: ParsedSymbol,
    class: SiteClass,
}

/// A construction observation (bound evidence).
struct Construction {
    crate_name: String,
    type_name: String,
    bound_field: Option<String>,
    file: String,
    line: u32,
    source: String,
}

/// A call-level bound observed in a statement chain (`.timeout(d).send()`).
struct CallBound {
    doc_idx: usize,
    line: usize,
    name: &'static str,
    /// The bound call's own constant argument, when resolvable.
    arg: Option<ConstArg>,
}

/// What derivation hands back: sites (deterministic order) plus the
/// repo-scoped construction facts.
pub struct Derived {
    pub sites: Vec<Site>,
    pub repo_config: RepoConfig,
}

/// Derive packets from a SCIP index. `only_files` (repo-relative paths)
/// filters which files' SITES are emitted; evidence (constructions, callers)
/// is still gathered repo-wide so an incremental reload sees the same bounds
/// a full load would.
pub fn derive(
    root: &Path,
    snapshot: &str,
    index: &scip::types::Index,
    only_files: Option<&[String]>,
) -> Derived {
    // --- pass A: load docs, build structural indexes ---
    let mut docs: Vec<Doc> = Vec::new();
    let mut scip_docs: Vec<&scip::types::Document> = index.documents.iter().collect();
    scip_docs.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    for sdoc in &scip_docs {
        let Ok(text) = std::fs::read_to_string(root.join(&sdoc.relative_path)) else {
            continue; // moved/deleted since indexing: skip, coverage degrades
        };
        let starts = line_starts(&text);
        let mut doc = Doc {
            rel_path: sdoc.relative_path.clone(),
            text,
            line_starts: starts,
            fn_defs: Vec::new(),
            macro_spans: Vec::new(),
        };
        for occ in &sdoc.occurrences {
            let Some(range) = decode_range(&occ.range) else {
                continue;
            };
            if occ.symbol_roles & ROLE_DEFINITION != 0 {
                // Function definitions carry enclosing_range = the body.
                if let Some(sym) = parse(&occ.symbol) {
                    if matches!(sym.kind, SymbolKind::Method | SymbolKind::Function) {
                        if let Some(encl) = decode_range(&occ.enclosing_range) {
                            if let (Some(s), Some(e)) =
                                (doc.offset(encl.start), doc.offset(encl.end))
                            {
                                doc.fn_defs
                                    .push((sym.name.clone(), occ.symbol.clone(), s..e));
                            }
                        }
                    }
                }
            } else if let Some(sym) = parse(&occ.symbol) {
                if sym.kind == SymbolKind::Macro {
                    // Macro invocation: span = name!(…) by paren matching.
                    if let (Some(s), Some(e)) = (doc.offset(range.start), doc.offset(range.end)) {
                        let span_end = macro_span_end(&doc.text, e).unwrap_or(e);
                        doc.macro_spans.push(s..span_end);
                    }
                }
            }
        }
        docs.push(doc);
    }

    // Map back: doc index by rel_path, and keep occurrence lists per doc.
    let doc_idx_by_path: HashMap<&str, usize> = docs
        .iter()
        .enumerate()
        .map(|(i, d)| (d.rel_path.as_str(), i))
        .collect();

    // --- pass B: match occurrences, collect candidates + evidence ---
    let mut candidates: Vec<Candidate> = Vec::new();
    let mut constructions: Vec<Construction> = Vec::new();
    let mut call_bounds: Vec<CallBound> = Vec::new();
    // fn symbol -> reference positions (doc, range), for depth-1 callers.
    let mut fn_refs: HashMap<String, Vec<(usize, SRange)>> = HashMap::new();

    for sdoc in &scip_docs {
        let Some(&di) = doc_idx_by_path.get(sdoc.relative_path.as_str()) else {
            continue;
        };
        for occ in &sdoc.occurrences {
            if occ.symbol_roles & ROLE_DEFINITION != 0 {
                continue;
            }
            let Some(range) = decode_range(&occ.range) else {
                continue;
            };
            let Some(sym) = parse(&occ.symbol) else {
                continue;
            };
            // Token-text filter: compiler-generated occurrences (`.await`
            // desugar to Future::poll / Try::branch) sit at source positions
            // whose text is not the symbol's name. Never derive from them.
            let token = docs[di].slice(range).unwrap_or("");
            if token != sym.name {
                continue;
            }
            if matches!(sym.kind, SymbolKind::Method | SymbolKind::Function) {
                fn_refs
                    .entry(occ.symbol.clone())
                    .or_default()
                    .push((di, range));
            }
            let Some(class) = classify(&sym) else {
                continue;
            };
            match class {
                SiteClass::Construction {
                    type_name,
                    bound_field,
                } => {
                    let doc = &docs[di];
                    constructions.push(Construction {
                        crate_name: sym.crate_name.clone(),
                        type_name: type_name.to_string(),
                        bound_field: bound_field.map(str::to_string),
                        file: doc.rel_path.clone(),
                        line: range.start.line as u32 + 1,
                        source: statement_snippet(doc, range.start.line),
                    });
                }
                SiteClass::CallBound { name } => {
                    let doc = &docs[di];
                    let tok_end = doc.offset(range.end).unwrap_or(0);
                    call_bounds.push(CallBound {
                        doc_idx: di,
                        line: range.start.line,
                        name,
                        arg: const_args_at(&doc.text, tok_end).into_iter().next(),
                    });
                }
                class => candidates.push(Candidate {
                    doc_idx: di,
                    range,
                    sym,
                    class,
                }),
            }
        }
    }

    // --- pass C: materialize sites ---
    let mut sites: Vec<Site> = Vec::new();
    // (enclosing fn symbol, crate, category) -> emission aggregate.
    struct EmissionAgg {
        site: Site,
        count: u32,
    }
    let mut emissions: HashMap<(String, String, &'static str), EmissionAgg> = HashMap::new();

    let wanted = |path: &str| -> bool {
        match only_files {
            Some(list) => list.iter().any(|f| f == path),
            None => true,
        }
    };

    for cand in &candidates {
        let doc = &docs[cand.doc_idx];
        if !wanted(&doc.rel_path) {
            continue;
        }
        let off = doc.offset(cand.range.start).unwrap_or(0);
        let tok_end = doc.offset(cand.range.end).unwrap_or(off);
        let encl = doc.enclosing_fn(off);
        let (encl_name, encl_sym, body) = match encl {
            Some((name, symstr, r)) => (
                name.clone(),
                symstr.clone(),
                cap(doc.text.get(r.clone()).unwrap_or(""), MAX_BODY_CHARS),
            ),
            None => (String::new(), String::new(), String::new()),
        };
        let receiver = receiver_before(&doc.text, off);
        let (stmt_start, stmt_end) = statement_lines(doc, cand.range.start.line);
        let snippet = statement_snippet(doc, cand.range.start.line);
        let in_macro = doc.in_macro_span(off);
        let mut const_args = const_args_at(&doc.text, tok_end);
        // A bound set in the SAME statement chain (`.timeout(d).send()`)
        // becomes name-keyed const-arg evidence on this site: Rust has no
        // keyword arguments, but the builder method's name is a mechanical
        // fact from the moniker.
        for cb in &call_bounds {
            if cb.doc_idx == cand.doc_idx && cb.line >= stmt_start && cb.line <= stmt_end {
                const_args.push(ConstArg {
                    index: 0,
                    name: cb.name.into(),
                    value: cb.arg.as_ref().map(|a| a.value.clone()).unwrap_or_default(),
                    how: cb
                        .arg
                        .as_ref()
                        .map(|a| a.how.clone())
                        .unwrap_or_else(|| "named_constant".into()),
                });
            }
        }

        let mut prov = Provenance {
            ancestry_depth_searched: 1,
            ..Default::default()
        };

        // Depth-1 callers of the enclosing function.
        let mut callers: Vec<Snippet> = Vec::new();
        if !encl_sym.is_empty() {
            if let Some(refs) = fn_refs.get(&encl_sym) {
                prov.callers_total = refs.len() as u32;
                for (rdi, rrange) in refs.iter().take(MAX_CALLERS) {
                    let rdoc = &docs[*rdi];
                    let roff = rdoc.offset(rrange.start).unwrap_or(0);
                    let rsym = rdoc
                        .enclosing_fn(roff)
                        .map(|(n, _, _)| n.clone())
                        .unwrap_or_default();
                    callers.push(Snippet {
                        file: rdoc.rel_path.clone(),
                        line: rrange.start.line as u32 + 1,
                        symbol: rsym,
                        source: cap(
                            &statement_snippet(rdoc, rrange.start.line),
                            MAX_CALLER_SOURCE_CHARS,
                        ),
                    });
                }
                prov.callers_included = callers.len() as u32;
                prov.hit_caller_budget = prov.callers_total > prov.callers_included;
            }
        }

        match &cand.class {
            SiteClass::Emission { category } => {
                let key = (encl_sym.clone(), cand.sym.crate_name.clone(), *category);
                let e = emissions.entry(key).or_insert_with(|| EmissionAgg {
                    site: Site {
                        snapshot_id: snapshot.to_string(),
                        file_path: doc.rel_path.clone(),
                        line_number: cand.range.start.line as u32 + 1,
                        symbol: encl_name.clone(),
                        method: cand.sym.name.clone(),
                        client_type: cand.sym.crate_name.clone(),
                        snippet: snippet.clone(),
                        enclosing_function_body: body.clone(),
                        provenance: Provenance {
                            client_type_resolved: true,
                            ..Default::default()
                        },
                        lang: "rust".into(),
                        packet_schema: rvl_core::PACKET_SCHEMA,
                        macro_expansion: cand.sym.kind == SymbolKind::Macro,
                        site_kind: rvl_core::SITE_KIND_EMISSION.into(),
                        ..Default::default()
                    },
                    count: 0,
                });
                e.count += 1;
                if cand.sym.kind == SymbolKind::Macro {
                    e.site.macro_expansion = true;
                }
                continue;
            }
            SiteClass::ClientCall => {
                let (client_type, resolved) = match (&cand.sym.self_type, &cand.sym.owner_type) {
                    (Some(_), _) => (cand.sym.self_type_path().unwrap_or_default(), true),
                    (None, Some(_)) => {
                        // Trait-level dispatch: mid tier only when visibly dyn.
                        if receiver_is_dyn(&body, &receiver) {
                            (
                                format!("dyn {}", cand.sym.owner_type_path().unwrap_or_default()),
                                true,
                            )
                        } else {
                            (String::new(), false) // abstain
                        }
                    }
                    (None, None) => (cand.sym.crate_module_path(), true),
                };
                prov.client_type_resolved = resolved;
                // Only bound-CARRYING constructions are attached: a plain
                // `builder()`/`build()` says nothing about a bound, and the
                // ClientConfig mechanism credits whatever construction it
                // sees for a type the specs recognize.
                let constructions_for: Vec<Snippet> = constructions
                    .iter()
                    .filter(|c| c.crate_name == cand.sym.crate_name && c.bound_field.is_some())
                    .take(MAX_CONSTRUCTIONS)
                    .map(|c| Snippet {
                        file: c.file.clone(),
                        line: c.line,
                        symbol: c.type_name.clone(),
                        source: c.source.clone(),
                    })
                    .collect();
                sites.push(Site {
                    snapshot_id: snapshot.to_string(),
                    file_path: doc.rel_path.clone(),
                    line_number: cand.range.start.line as u32 + 1,
                    symbol: encl_name,
                    method: cand.sym.name.clone(),
                    receiver,
                    client_type,
                    snippet,
                    enclosing_function_body: body,
                    callers,
                    client_construction: constructions_for,
                    provenance: prov,
                    lang: "rust".into(),
                    packet_schema: rvl_core::PACKET_SCHEMA,
                    const_args,
                    macro_expansion: in_macro,
                    ..Default::default()
                });
            }
            SiteClass::ServerEntry | SiteClass::BackgroundJob => {
                let client_type = cand
                    .sym
                    .self_type_path()
                    .or_else(|| cand.sym.owner_type_path())
                    .unwrap_or_else(|| cand.sym.crate_module_path());
                prov.client_type_resolved = true;
                let site_kind = if matches!(cand.class, SiteClass::ServerEntry) {
                    rvl_core::SITE_KIND_SERVER_ENTRY
                } else {
                    "background_job"
                };
                sites.push(Site {
                    snapshot_id: snapshot.to_string(),
                    file_path: doc.rel_path.clone(),
                    line_number: cand.range.start.line as u32 + 1,
                    symbol: encl_name,
                    method: cand.sym.name.clone(),
                    receiver,
                    client_type,
                    snippet,
                    enclosing_function_body: body,
                    callers,
                    provenance: prov,
                    lang: "rust".into(),
                    packet_schema: rvl_core::PACKET_SCHEMA,
                    const_args,
                    macro_expansion: in_macro,
                    site_kind: site_kind.into(),
                    ..Default::default()
                });
            }
            SiteClass::Construction { .. } | SiteClass::CallBound { .. } => {
                unreachable!("evidence classes are filtered in pass B")
            }
        }
    }

    // Emission aggregates: category + count ride const_args (G4 convention).
    let mut emission_sites: Vec<Site> = emissions
        .into_iter()
        .map(|((_, _, category), mut e)| {
            e.site.const_args = vec![
                ConstArg {
                    index: 0,
                    name: rvl_core::CONST_ARG_EMISSION_CATEGORY.into(),
                    value: category.into(),
                    how: "aggregate".into(),
                },
                ConstArg {
                    index: 0,
                    name: rvl_core::CONST_ARG_EMISSION_COUNT.into(),
                    value: e.count.to_string(),
                    how: "aggregate".into(),
                },
            ];
            e.site
        })
        .collect();
    sites.append(&mut emission_sites);

    if let Some(list) = only_files {
        sites.retain(|s| list.iter().any(|f| f == &s.file_path));
    }
    sites.sort_by(|a, b| {
        (a.file_path.as_str(), a.line_number, a.method.as_str()).cmp(&(
            b.file_path.as_str(),
            b.line_number,
            b.method.as_str(),
        ))
    });

    // Repo-scoped construction facts: only bound-carrying constructions.
    let mut facts: Vec<ConfigFact> = Vec::new();
    for c in &constructions {
        if let Some(field) = &c.bound_field {
            facts.push(ConfigFact {
                type_name: c.type_name.clone(),
                fields: vec![field.clone()],
                file: c.file.clone(),
                line: c.line,
                source: c.source.clone(),
            });
        }
    }

    Derived {
        sites,
        repo_config: RepoConfig {
            snapshot_id: snapshot.to_string(),
            constructions: facts,
        },
    }
}

/// End of a macro invocation span: from the byte after `name!`, skip
/// whitespace, then paren-match `(`/`[`/`{` (string-aware).
fn macro_span_end(text: &str, after_name: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = after_name;
    // The occurrence covers the macro NAME; the `!` follows it.
    if i < bytes.len() && bytes[i] == b'!' {
        i += 1;
    }
    while i < bytes.len() && (bytes[i] as char).is_whitespace() {
        i += 1;
    }
    if i >= bytes.len() || !matches!(bytes[i], b'(' | b'[' | b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_str = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_str {
            if c == '\\' {
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
        } else {
            match c {
                '"' => in_str = true,
                '(' | '[' | '{' => depth += 1,
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_from(text: &str) -> Doc {
        Doc {
            rel_path: "x.rs".into(),
            line_starts: line_starts(text),
            text: text.into(),
            fn_defs: Vec::new(),
            macro_spans: Vec::new(),
        }
    }

    #[test]
    fn statement_snippet_spans_a_builder_chain() {
        let src = "fn f() {\n    let resp = client\n        .get(\"u\")\n        .timeout(d)\n        .send()\n        .await?;\n    resp\n}\n";
        let doc = doc_from(src);
        // Site on the `.send()` line (0-based line 4).
        let snip = statement_snippet(&doc, 4);
        assert!(snip.contains("let resp = client"), "snippet: {snip}");
        assert!(snip.contains(".timeout(d)"), "snippet: {snip}");
        assert!(snip.contains(".await?;"), "snippet: {snip}");
        assert!(
            !snip.contains("resp\n}"),
            "snippet must stop at the statement"
        );
    }

    #[test]
    fn receiver_reads_the_dotted_chain() {
        let src = "self.client.get(url)";
        let off = src.find("get").unwrap();
        assert_eq!(receiver_before(src, off), "self.client");
        let src2 = "Client::builder()";
        let off2 = src2.find("builder").unwrap();
        assert_eq!(receiver_before(src2, off2), "Client");
        let src3 = "x.timeout(d).send()";
        let off3 = src3.find("send").unwrap();
        assert_eq!(
            receiver_before(src3, off3),
            "",
            "call-result receiver is opaque"
        );
    }

    #[test]
    fn dyn_receiver_is_detected_in_params_and_lets() {
        assert!(receiver_is_dyn(
            "fn q(e: &dyn Executor) { e.execute(x) }",
            "e"
        ));
        assert!(receiver_is_dyn(
            "fn q() { let e: Box<dyn Executor> = mk(); e.execute(x) }",
            "e"
        ));
        assert!(
            !receiver_is_dyn("fn q<E: Executor>(e: &E) { e.execute(x) }", "e"),
            "a generic receiver is NOT visibly dyn — it must abstain"
        );
        assert!(!receiver_is_dyn(
            "fn q(pool: &PgPool) { pool.execute(x) }",
            "pool"
        ));
    }

    #[test]
    fn const_args_pick_literals_and_duration_expressions() {
        let src = "x.timeout(Duration::from_secs(5), 3, \"tag\", limit)";
        let tok_end = src.find("(").unwrap();
        let args = const_args_at(src, tok_end);
        assert_eq!(
            args.len(),
            3,
            "the bare `limit` ident is not constant: {args:?}"
        );
        assert_eq!(args[0].value, "Duration::from_secs(5)");
        assert_eq!(args[0].how, "named_constant");
        assert_eq!(args[1].value, "3");
        assert_eq!(args[1].how, "literal");
        assert_eq!(args[2].value, "\"tag\"");
        assert_eq!(args[2].how, "literal");
        assert!(args.iter().all(|a| a.name.is_empty()), "Rust has no kwargs");
    }

    #[test]
    fn macro_span_covers_the_invocation() {
        let src = "tracing::info!(\"starting {}\", name); after()";
        // occurrence covers `info`
        let name_end = src.find("info").unwrap() + 4;
        let end = macro_span_end(src, name_end).unwrap();
        assert_eq!(&src[..end], "tracing::info!(\"starting {}\", name)");
    }

    #[test]
    fn int_and_float_literal_shapes() {
        assert!(is_int_literal("30"));
        assert!(is_int_literal("5_000"));
        assert!(is_int_literal("10u64"));
        assert!(!is_int_literal("x30"));
        assert!(is_float_literal("1.5"));
        assert!(!is_float_literal("1.5.2"));
    }
}
