//! Terraform retriever (`*.tf` plus auto-loaded tfvars): family (5) of the G6
//! config lane (po-av01j.23, wayfinder po-ae75b.1).
//!
//! Parses an honest, bounded SUBSET of HCL — exactly the keys the G6 control
//! set inventories — with a minimal in-module parser (no HCL crate; the repo
//! deliberately avoids heavyweight parse dependencies). Anything needing
//! expression evaluation is a [`Resolution::Unresolvable`] marker, never a
//! guess; a file the subset cannot parse degrades to an unparseable count,
//! never aborts a scan.
//!
//! Emitted facts (spec-driven, like every retriever):
//!
//!   * `terraform.required_version` — the version constraint, else the
//!     documented default: no constraint ("none").
//!   * `terraform.backend` — the backend TYPE (`s3`, `gcs`, ..., `cloud` for
//!     a `cloud {}` block), else the documented default `local`. Remote state
//!     is a reliability control; only the type is read, never the backend's
//!     attributes.
//!   * `provider.version-constraint` — per provider, from
//!     `required_providers` (authoritative) else a legacy `provider` block
//!     `version` attribute. No constraint anywhere → the platform floats to
//!     the newest release: a platform default, value "".
//!   * `module.source` / `module.source-class` — per module call, the raw
//!     source identity and its mechanical class (`registry`|`git`|`local`|
//!     `other`). A REMOTE REGISTRY module resolves BY REGISTRY IDENTITY (the
//!     po-av01j.2 resolution): the source string is the packet value and no
//!     network fetch ever happens.
//!   * `module.version-pin` / `module.pin-class` — registry modules: the
//!     `version` constraint (`exact`|`range`|`floating`); git modules: the
//!     `?ref=` pin (`ref-pinned`|`floating`). Local (relative source) modules
//!     emit NO pin packets — they are repo-pinned by construction and their
//!     directory is walked like any other (mirrors the GitHub Actions `./`
//!     local-action rule).
//!   * `resource.lifecycle.prevent_destroy` — explicit, else the documented
//!     `false`.
//!
//! Variable references resolve ONE hop and only to literals: a value that is
//! exactly `var.x` consults the module directory's `variable "x"` default,
//! overlaid by `terraform.tfvars` then `*.auto.tfvars` (lexical order, later
//! wins — the documented precedence). The provenance chain records which of
//! default vs tfvars override produced the value. Anything deeper — any
//! expression, template, list, or non-literal assignment — is Unresolvable.

use crate::{ConfigPacket, ConfigRetriever, ProvenanceStep, Resolution, Retrieved};
use std::collections::BTreeMap;

pub struct Terraform;

impl ConfigRetriever for Terraform {
    fn format_id(&self) -> &'static str {
        "terraform"
    }

    /// `*.tf` anywhere in the walk (modules live in any directory; vendored
    /// trees are excluded by the walk's skip list, including `.terraform/`),
    /// plus the two auto-loaded values-file shapes. `*.tf.json` /
    /// `*.tfvars.json` (JSON syntax) are out of the subset and unclaimed, as
    /// are `-var-file`-only tfvars (they never auto-load, so nothing
    /// committed proves they apply).
    fn matches(&self, rel_path: &str) -> bool {
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        name.ends_with(".tf") || name == "terraform.tfvars" || name.ends_with(".auto.tfvars")
    }

    /// A single file is a module directory with one file: same semantics,
    /// just no companions to consult.
    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        let files = [(rel_path.to_string(), contents.to_string())];
        self.retrieve_all(&files, snapshot_id)
    }

    /// Directory-scoped retrieval: Terraform's unit of configuration is the
    /// module DIRECTORY, so resolution (variable defaults, tfvars overlays)
    /// spans the files the walk claimed. Local (relative-source) modules need
    /// no special following: their directory is a group here like any other.
    fn retrieve_all(&self, files: &[(String, String)], snapshot_id: &str) -> Retrieved {
        let mut out = Retrieved::default();
        let mut dirs: BTreeMap<&str, Vec<&(String, String)>> = BTreeMap::new();
        for f in files {
            dirs.entry(dir_of(&f.0)).or_default().push(f);
        }
        for (_dir, mut group) in dirs {
            group.sort_by(|a, b| a.0.cmp(&b.0));
            retrieve_dir(&group, snapshot_id, &mut out);
        }
        out
    }
}

/// The directory part of a repo-relative path ("" for the repo root).
fn dir_of(rel: &str) -> &str {
    rel.rsplit_once('/').map(|(d, _)| d).unwrap_or("")
}

// --- bounded HCL subset: tokens ---

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    /// A quoted string; `template` marks `${...}` interpolation (never a
    /// literal).
    Str {
        value: String,
        template: bool,
    },
    Num(String),
    Punct(char),
    Newline,
    /// A heredoc body: always expression-grade, content dropped.
    Heredoc,
}

fn tokenize(src: &str) -> Vec<Tok> {
    let mut toks = Vec::new();
    let b = src.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let c = b[i] as char;
        match c {
            '\n' => {
                toks.push(Tok::Newline);
                i += 1;
            }
            ' ' | '\t' | '\r' => i += 1,
            '#' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < b.len() && b[i + 1] == b'/' => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < b.len() && b[i + 1] == b'*' => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            '"' => {
                let (tok, ni) = scan_string(b, i + 1);
                toks.push(tok);
                i = ni;
            }
            '<' if i + 1 < b.len() && b[i + 1] == b'<' => {
                i = scan_heredoc(src, b, i + 2);
                toks.push(Tok::Heredoc);
            }
            '0'..='9' => {
                let start = i;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                toks.push(Tok::Num(src[start..i].to_string()));
            }
            '-' if i + 1 < b.len() && b[i + 1].is_ascii_digit() => {
                let start = i;
                i += 1;
                while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'.') {
                    i += 1;
                }
                toks.push(Tok::Num(src[start..i].to_string()));
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                let start = i;
                while i < b.len()
                    && ((b[i] as char).is_ascii_alphanumeric() || b[i] == b'_' || b[i] == b'-')
                {
                    i += 1;
                }
                toks.push(Tok::Ident(src[start..i].to_string()));
            }
            other => {
                toks.push(Tok::Punct(other));
                i += 1;
            }
        }
    }
    toks
}

/// Scan a quoted string starting AFTER the opening quote; returns the token
/// and the index after the closing quote. `${...}` marks a template
/// (expression-grade); its interior may nest braces and quotes.
fn scan_string(b: &[u8], mut i: usize) -> (Tok, usize) {
    let mut value = String::new();
    let mut template = false;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if i + 1 < b.len() {
                    value.push(b[i + 1] as char);
                }
                i += 2;
            }
            b'$' if i + 1 < b.len() && b[i + 1] == b'{' => {
                template = true;
                i += 2;
                let mut depth = 1usize;
                while i < b.len() && depth > 0 {
                    match b[i] {
                        b'{' => depth += 1,
                        b'}' => depth -= 1,
                        b'"' => {
                            // an inner quoted string inside the interpolation
                            i += 1;
                            while i < b.len() && b[i] != b'"' {
                                if b[i] == b'\\' {
                                    i += 1;
                                }
                                i += 1;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                continue;
            }
            b'"' => return (Tok::Str { value, template }, i + 1),
            c => {
                value.push(c as char);
                i += 1;
            }
        }
    }
    (Tok::Str { value, template }, i)
}

/// Scan a heredoc starting at the tag (after `<<`); returns the index after
/// the terminating tag line. Content is dropped: a heredoc is never a
/// literal this lane inventories.
fn scan_heredoc(src: &str, b: &[u8], mut i: usize) -> usize {
    if i < b.len() && b[i] == b'-' {
        i += 1;
    }
    let tag_start = i;
    while i < b.len() && ((b[i] as char).is_ascii_alphanumeric() || b[i] == b'_') {
        i += 1;
    }
    let tag = &src[tag_start..i];
    if tag.is_empty() {
        return i;
    }
    // consume to end of the opening line, then whole lines until the tag
    while i < b.len() && b[i] != b'\n' {
        i += 1;
    }
    while i < b.len() {
        i += 1; // past the newline
        let line_start = i;
        while i < b.len() && b[i] != b'\n' {
            i += 1;
        }
        if src[line_start..i].trim() == tag {
            break;
        }
    }
    i
}

// --- bounded HCL subset: grammar ---

#[derive(Debug, Clone, PartialEq)]
enum Value {
    /// A literal scalar, canonically rendered: strings bare, bools and
    /// numbers as written.
    Lit(String),
    /// Exactly `var.<name>` — the one-hop resolvable reference.
    VarRef(String),
    /// An object literal `{ k = v, ... }` (a `required_providers` entry).
    Object(Vec<(String, Value)>),
    /// Anything needing evaluation: templates, functions, other references,
    /// lists, heredocs, operators. Never resolved, never guessed.
    Expr,
}

#[derive(Debug, Clone)]
enum Item {
    Attr(String, Value),
    Block(Block),
}

#[derive(Debug, Clone)]
struct Block {
    kind: String,
    labels: Vec<String>,
    body: Vec<Item>,
}

struct Parser {
    toks: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.i)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.i).cloned();
        if t.is_some() {
            self.i += 1;
        }
        t
    }

    fn skip_separators(&mut self) {
        while matches!(self.peek(), Some(Tok::Newline) | Some(Tok::Punct(','))) {
            self.i += 1;
        }
    }

    /// A body: attributes and nested blocks until `}` (or EOF when `top`).
    fn parse_body(&mut self, top: bool) -> Result<Vec<Item>, ()> {
        let mut items = Vec::new();
        loop {
            self.skip_separators();
            match self.peek() {
                None => return if top { Ok(items) } else { Err(()) },
                Some(Tok::Punct('}')) if !top => {
                    self.bump();
                    return Ok(items);
                }
                Some(Tok::Ident(_)) => {
                    let Some(Tok::Ident(name)) = self.bump() else {
                        unreachable!()
                    };
                    match self.peek() {
                        Some(Tok::Punct('=')) => {
                            self.bump();
                            let v = self.parse_value();
                            items.push(Item::Attr(name, v));
                        }
                        Some(Tok::Str { .. }) | Some(Tok::Punct('{')) => {
                            let mut labels = Vec::new();
                            while let Some(Tok::Str { .. }) = self.peek() {
                                let Some(Tok::Str { value, .. }) = self.bump() else {
                                    unreachable!()
                                };
                                labels.push(value);
                            }
                            if !matches!(self.peek(), Some(Tok::Punct('{'))) {
                                return Err(());
                            }
                            self.bump();
                            let body = self.parse_body(false)?;
                            items.push(Item::Block(Block {
                                kind: name,
                                labels,
                                body,
                            }));
                        }
                        _ => return Err(()),
                    }
                }
                _ => return Err(()),
            }
        }
    }

    /// True when the value that just ended is followed by a value
    /// terminator; anything else means the value continues as an expression.
    fn at_value_end(&self) -> bool {
        matches!(
            self.peek(),
            None | Some(Tok::Newline)
                | Some(Tok::Punct('}'))
                | Some(Tok::Punct(','))
                | Some(Tok::Punct(']'))
        )
    }

    fn parse_value(&mut self) -> Value {
        let candidate = match self.peek() {
            Some(Tok::Str { template, .. }) => {
                let template = *template;
                let Some(Tok::Str { value, .. }) = self.bump() else {
                    unreachable!()
                };
                if template {
                    Value::Expr
                } else {
                    Value::Lit(value)
                }
            }
            Some(Tok::Num(_)) => {
                let Some(Tok::Num(n)) = self.bump() else {
                    unreachable!()
                };
                Value::Lit(n)
            }
            Some(Tok::Ident(w)) if w == "true" || w == "false" || w == "null" => {
                let Some(Tok::Ident(w)) = self.bump() else {
                    unreachable!()
                };
                Value::Lit(w)
            }
            Some(Tok::Ident(w)) if w == "var" => {
                self.bump();
                if matches!(self.peek(), Some(Tok::Punct('.'))) {
                    self.bump();
                    if let Some(Tok::Ident(_)) = self.peek() {
                        let Some(Tok::Ident(name)) = self.bump() else {
                            unreachable!()
                        };
                        Value::VarRef(name)
                    } else {
                        Value::Expr
                    }
                } else {
                    Value::Expr
                }
            }
            Some(Tok::Punct('{')) => {
                self.bump();
                return self.parse_object();
            }
            _ => Value::Expr,
        };
        if matches!(candidate, Value::Expr) || !self.at_value_end() {
            self.consume_expr();
            return Value::Expr;
        }
        candidate
    }

    /// An object literal after its `{`: `key = value` pairs. Anything the
    /// subset does not recognize degrades the whole object to [`Value::Expr`]
    /// (balanced-brace skip), never a partial guess.
    fn parse_object(&mut self) -> Value {
        let mut attrs = Vec::new();
        loop {
            self.skip_separators();
            match self.peek() {
                Some(Tok::Punct('}')) => {
                    self.bump();
                    return Value::Object(attrs);
                }
                Some(Tok::Ident(_)) | Some(Tok::Str { .. }) => {
                    let key = match self.bump() {
                        Some(Tok::Ident(k)) => k,
                        Some(Tok::Str { value, .. }) => value,
                        _ => unreachable!(),
                    };
                    if !matches!(self.peek(), Some(Tok::Punct('='))) {
                        self.skip_balanced_brace();
                        return Value::Expr;
                    }
                    self.bump();
                    let v = self.parse_value();
                    attrs.push((key, v));
                }
                None => return Value::Expr,
                _ => {
                    self.skip_balanced_brace();
                    return Value::Expr;
                }
            }
        }
    }

    /// Consume the remainder of an expression: until a newline, `}`, `,` or
    /// `]` at nesting depth 0 (terminators are left in place; newlines
    /// inside brackets continue the expression).
    fn consume_expr(&mut self) {
        let mut depth = 0usize;
        while let Some(t) = self.peek() {
            match t {
                Tok::Newline if depth == 0 => return,
                Tok::Punct('}') | Tok::Punct(',') | Tok::Punct(']') if depth == 0 => return,
                Tok::Punct('(') | Tok::Punct('[') | Tok::Punct('{') => depth += 1,
                Tok::Punct(')') | Tok::Punct(']') | Tok::Punct('}') => {
                    depth = depth.saturating_sub(1)
                }
                _ => {}
            }
            self.bump();
        }
    }

    /// Skip to the `}` closing the CURRENT object (depth already inside it).
    fn skip_balanced_brace(&mut self) {
        let mut depth = 1usize;
        while let Some(t) = self.bump() {
            match t {
                Tok::Punct('{') => depth += 1,
                Tok::Punct('}') => {
                    depth -= 1;
                    if depth == 0 {
                        return;
                    }
                }
                _ => {}
            }
        }
    }
}

fn parse_file(src: &str) -> Result<Vec<Item>, ()> {
    Parser {
        toks: tokenize(src),
        i: 0,
    }
    .parse_body(true)
}

// --- the per-directory model ---

#[derive(Debug, Clone)]
enum VarDefault {
    Literal(String),
    NonLiteral,
    None,
}

/// The one-hop resolution table for a module directory.
#[derive(Debug, Default)]
struct VarTable {
    /// Declared variables: name → (declaring file, default state). First
    /// declaration wins (duplicates are a terraform error anyway).
    declared: BTreeMap<String, (String, VarDefault)>,
    /// The winning auto-loaded tfvars assignment: name → (file, literal or
    /// None for a non-literal winner — which still WINS, so it makes the
    /// value unresolvable rather than falling back to the default).
    tfvars: BTreeMap<String, (String, Option<String>)>,
}

/// Resolve one attribute value: a literal is authored; a `var.x` reference
/// resolves one hop through the table; everything else abstains. Returns
/// (value, resolution, provenance chain).
fn resolve_value(
    site_file: &str,
    key_path: &str,
    v: &Value,
    vars: &VarTable,
) -> (Option<String>, Resolution, Vec<ProvenanceStep>) {
    match v {
        Value::Lit(s) => (
            Some(s.clone()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(site_file, key_path, "explicit")],
        ),
        Value::VarRef(name) => {
            let mut chain = vec![ProvenanceStep::new(
                site_file,
                &format!("{key_path} = var.{name}"),
                "reference",
            )];
            let decl = vars.declared.get(name);
            if let Some((dfile, VarDefault::Literal(_))) = decl {
                chain.push(ProvenanceStep::new(
                    dfile,
                    &format!("variable.{name}.default"),
                    "default",
                ));
            }
            match vars.tfvars.get(name) {
                Some((tfile, Some(lit))) => {
                    chain.push(ProvenanceStep::new(tfile, name, "override"));
                    (Some(lit.clone()), Resolution::AsAuthored, chain)
                }
                Some((tfile, None)) => {
                    chain.push(ProvenanceStep::new(tfile, name, "non-literal"));
                    (None, Resolution::Unresolvable, chain)
                }
                None => match decl {
                    Some((_, VarDefault::Literal(d))) => {
                        (Some(d.clone()), Resolution::AsAuthored, chain)
                    }
                    Some((dfile, VarDefault::NonLiteral)) => {
                        chain.push(ProvenanceStep::new(
                            dfile,
                            &format!("variable.{name}.default"),
                            "non-literal",
                        ));
                        (None, Resolution::Unresolvable, chain)
                    }
                    Some((dfile, VarDefault::None)) => {
                        chain.push(ProvenanceStep::new(
                            dfile,
                            &format!("variable.{name}"),
                            "no-default",
                        ));
                        chain.push(ProvenanceStep::new(
                            "",
                            &format!("var.{name}"),
                            "project-setting",
                        ));
                        (None, Resolution::Unresolvable, chain)
                    }
                    None => {
                        chain.push(ProvenanceStep::new(
                            "",
                            &format!("var.{name}"),
                            "undeclared",
                        ));
                        (None, Resolution::Unresolvable, chain)
                    }
                },
            }
        }
        _ => (
            None,
            Resolution::Unresolvable,
            vec![ProvenanceStep::new(site_file, key_path, "expression")],
        ),
    }
}

/// Classify a module source address by Terraform's documented grammar. The
/// `//subdir` suffix never changes the class.
fn classify_source(source: &str) -> &'static str {
    if source.starts_with("./") || source.starts_with("../") {
        return "local";
    }
    if source.starts_with("git::")
        || source.starts_with("git@")
        || source.starts_with("github.com/")
        || source.starts_with("bitbucket.org/")
    {
        return "git";
    }
    if source.contains("::") || source.starts_with("http://") || source.starts_with("https://") {
        return "other"; // hg::, s3::, gcs::, plain archive URLs
    }
    let base = source.split("//").next().unwrap_or(source);
    let base = base.split('?').next().unwrap_or(base);
    let parts: Vec<&str> = base.split('/').collect();
    if (parts.len() == 3 || parts.len() == 4) && parts.iter().all(|p| !p.is_empty()) {
        return "registry"; // [host/]namespace/name/provider
    }
    "other"
}

/// The `?ref=` pin of a git source, if any.
fn git_ref(source: &str) -> Option<String> {
    let (_, query) = source.split_once('?')?;
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix("ref=").map(str::to_string))
}

/// Mechanical pin-shape of a version constraint: `exact` (a bare or
/// `=`-prefixed semver), `range` (any operator constraint), `floating`
/// (no constraint at all).
fn pin_class(constraint: &str) -> &'static str {
    let t = constraint.trim();
    if t.is_empty() {
        return "floating";
    }
    let t = t.strip_prefix('=').unwrap_or(t).trim();
    let exact = !t.is_empty()
        && t.split('.')
            .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()));
    if exact {
        "exact"
    } else {
        "range"
    }
}

fn get_attr<'a>(body: &'a [Item], name: &str) -> Option<&'a Value> {
    body.iter().find_map(|it| match it {
        Item::Attr(k, v) if k == name => Some(v),
        _ => None,
    })
}

fn get_blocks<'a>(body: &'a [Item], kind: &str) -> impl Iterator<Item = &'a Block> {
    let kind = kind.to_string();
    body.iter().filter_map(move |it| match it {
        Item::Block(b) if b.kind == kind => Some(b),
        _ => None,
    })
}

/// One provider's constraint fact and where it came from.
struct ProviderFact {
    file: String,
    value: Option<Value>,
    /// The consulted key path (for provenance).
    key_path: String,
}

/// Retrieve one module directory: `group` is path-sorted (rel, contents).
fn retrieve_dir(group: &[&(String, String)], snapshot_id: &str, out: &mut Retrieved) {
    // Partition and parse. tfvars overlay order is the documented one:
    // terraform.tfvars first, then *.auto.tfvars lexically, later wins.
    let mut parsed_tf: Vec<(&str, Vec<Item>)> = Vec::new();
    let mut vars = VarTable::default();
    let mut tfvars_files: Vec<&(String, String)> = group
        .iter()
        .copied()
        .filter(|(rel, _)| !rel.ends_with(".tf"))
        .collect();
    tfvars_files.sort_by_key(|(rel, _)| {
        let name = rel.rsplit('/').next().unwrap_or(rel);
        (name != "terraform.tfvars", rel.clone())
    });
    for (rel, contents) in group.iter().copied() {
        if !rel.ends_with(".tf") {
            continue;
        }
        match parse_file(contents) {
            Ok(items) => parsed_tf.push((rel, items)),
            Err(()) => out.unparseable += 1,
        }
    }
    for (rel, contents) in tfvars_files {
        match parse_file(contents) {
            Ok(items) => {
                for it in items {
                    if let Item::Attr(name, v) = it {
                        let lit = match v {
                            Value::Lit(s) => Some(s),
                            _ => None,
                        };
                        vars.tfvars.insert(name, (rel.clone(), lit));
                    }
                }
            }
            Err(()) => out.unparseable += 1,
        }
    }
    if parsed_tf.is_empty() {
        return; // a directory of only tfvars is not a module
    }

    // Variable declarations (first wins across path-sorted files).
    for (rel, items) in &parsed_tf {
        for b in items.iter().filter_map(|it| match it {
            Item::Block(b) if b.kind == "variable" => Some(b),
            _ => None,
        }) {
            let Some(name) = b.labels.first() else {
                continue;
            };
            let default = match get_attr(&b.body, "default") {
                None => VarDefault::None,
                Some(Value::Lit(s)) => VarDefault::Literal(s.clone()),
                Some(_) => VarDefault::NonLiteral,
            };
            vars.declared
                .entry(name.clone())
                .or_insert_with(|| (rel.to_string(), default));
        }
    }

    let packet = |file: &str,
                  unit: &str,
                  key: &str,
                  value: Option<String>,
                  resolution: Resolution,
                  provenance: Vec<ProvenanceStep>| ConfigPacket {
        snapshot_id: snapshot_id.to_string(),
        format: "terraform".to_string(),
        file_path: file.to_string(),
        line: 0,
        unit: unit.to_string(),
        key: key.to_string(),
        resolved_value: value,
        resolution,
        provenance,
    };

    // Module-level facts from the (first) terraform block(s); a module split
    // across versions.tf/backend.tf merges by first-found in sorted order.
    let tf_blocks: Vec<(&str, &Block)> = parsed_tf
        .iter()
        .flat_map(|(rel, items)| get_blocks(items, "terraform").map(move |b| (*rel, b)))
        .collect();
    let anchor = tf_blocks
        .first()
        .map(|(rel, _)| *rel)
        .unwrap_or(parsed_tf[0].0);

    // terraform.required_version
    match tf_blocks
        .iter()
        .find_map(|(rel, b)| get_attr(&b.body, "required_version").map(|v| (*rel, v)))
    {
        Some((rel, v)) => {
            let (value, resolution, prov) =
                resolve_value(rel, "terraform.required_version", v, &vars);
            out.packets.push(packet(
                rel,
                "module",
                "terraform.required_version",
                value,
                resolution,
                prov,
            ));
        }
        None => out.packets.push(packet(
            anchor,
            "module",
            "terraform.required_version",
            Some("none".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(anchor, "terraform.required_version", "absent"),
                ProvenanceStep::new("", "required_version", "platform-default"),
            ],
        )),
    }

    // terraform.backend: the TYPE only; a `cloud {}` block is type "cloud".
    let backend = tf_blocks.iter().find_map(|(rel, b)| {
        if let Some(be) = get_blocks(&b.body, "backend").next() {
            return Some((*rel, be.labels.first().cloned().unwrap_or_default(), true));
        }
        get_blocks(&b.body, "cloud")
            .next()
            .map(|_| (*rel, "cloud".to_string(), false))
    });
    match backend {
        Some((rel, ty, is_backend)) => {
            let key_path = if is_backend {
                format!("terraform.backend.{ty}")
            } else {
                "terraform.cloud".to_string()
            };
            out.packets.push(packet(
                rel,
                "module",
                "terraform.backend",
                Some(ty),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(rel, &key_path, "explicit")],
            ));
        }
        None => out.packets.push(packet(
            anchor,
            "module",
            "terraform.backend",
            Some("local".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(anchor, "terraform.backend", "absent"),
                ProvenanceStep::new("", "backend", "platform-default"),
            ],
        )),
    }

    // provider.version-constraint: required_providers is authoritative; a
    // legacy `provider` block's `version` attribute only fills gaps.
    let mut providers: BTreeMap<String, ProviderFact> = BTreeMap::new();
    for (rel, b) in &tf_blocks {
        let Some(rp) = get_blocks(&b.body, "required_providers").next() else {
            continue;
        };
        for it in &rp.body {
            let Item::Attr(name, v) = it else { continue };
            let (value, key_path) = match v {
                // full entry: aws = { source = "...", version = "..." }
                Value::Object(attrs) => (
                    attrs.iter().find(|(k, _)| k == "version").map(|(_, v)| v),
                    format!("terraform.required_providers.{name}.version"),
                ),
                // legacy shorthand: aws = ">= 2.7"
                other => (Some(other), format!("terraform.required_providers.{name}")),
            };
            // First declaration wins (a duplicate is a terraform error).
            providers
                .entry(name.clone())
                .or_insert_with(|| ProviderFact {
                    file: rel.to_string(),
                    value: value.cloned(),
                    key_path,
                });
        }
    }
    for (rel, items) in &parsed_tf {
        for b in items.iter().filter_map(|it| match it {
            Item::Block(b) if b.kind == "provider" => Some(b),
            _ => None,
        }) {
            let Some(name) = b.labels.first() else {
                continue;
            };
            if providers.contains_key(name) {
                continue;
            }
            providers.insert(
                name.clone(),
                ProviderFact {
                    file: rel.to_string(),
                    value: get_attr(&b.body, "version").cloned(),
                    key_path: format!("provider.{name}.version"),
                },
            );
        }
    }
    for (name, fact) in &providers {
        let unit = format!("provider:{name}");
        match &fact.value {
            Some(v) => {
                let (value, resolution, prov) = resolve_value(&fact.file, &fact.key_path, v, &vars);
                out.packets.push(packet(
                    &fact.file,
                    &unit,
                    "provider.version-constraint",
                    value,
                    resolution,
                    prov,
                ));
            }
            // No constraint anywhere: the platform floats to the newest
            // release — a documented default, and the pinning finding.
            None => out.packets.push(packet(
                &fact.file,
                &unit,
                "provider.version-constraint",
                Some(String::new()),
                Resolution::PlatformDefault,
                vec![
                    ProvenanceStep::new(&fact.file, &fact.key_path, "absent"),
                    ProvenanceStep::new("", "provider version selection", "platform-default"),
                ],
            )),
        }
    }

    // Module calls: source identity + class, and the pin facts by class.
    for (rel, items) in &parsed_tf {
        for b in items.iter().filter_map(|it| match it {
            Item::Block(b) if b.kind == "module" => Some(b),
            _ => None,
        }) {
            let Some(name) = b.labels.first() else {
                continue;
            };
            let unit = format!("module-call:{name}");
            let source_path = format!("module.{name}.source");
            let Some(source_val) = get_attr(&b.body, "source") else {
                continue; // no source: not a resolvable module call
            };
            let (source, resolution, prov) = resolve_value(rel, &source_path, source_val, &vars);
            out.packets.push(packet(
                rel,
                &unit,
                "module.source",
                source.clone(),
                resolution,
                prov.clone(),
            ));
            let Some(source) = source else {
                continue; // unresolvable source: class and pin are unknowable
            };
            let class = classify_source(&source);
            out.packets.push(packet(
                rel,
                &unit,
                "module.source-class",
                Some(class.to_string()),
                resolution,
                prov,
            ));
            match class {
                // A registry module resolves BY REGISTRY IDENTITY: the pin is
                // its `version` constraint. No fetch, ever.
                "registry" => {
                    let vpath = format!("module.{name}.version");
                    let (pin, resolution, prov) = match get_attr(&b.body, "version") {
                        Some(v) => resolve_value(rel, &vpath, v, &vars),
                        None => (
                            Some(String::new()),
                            Resolution::PlatformDefault,
                            vec![
                                ProvenanceStep::new(rel, &vpath, "absent"),
                                ProvenanceStep::new(
                                    "",
                                    "module version selection",
                                    "platform-default",
                                ),
                            ],
                        ),
                    };
                    out.packets.push(packet(
                        rel,
                        &unit,
                        "module.version-pin",
                        pin.clone(),
                        resolution,
                        prov.clone(),
                    ));
                    if let Some(pin) = pin {
                        out.packets.push(packet(
                            rel,
                            &unit,
                            "module.pin-class",
                            Some(pin_class(&pin).to_string()),
                            resolution,
                            prov,
                        ));
                    }
                }
                // A git module's pin is its `?ref=`.
                "git" => {
                    let rpath = format!("module.{name}.source ?ref");
                    let (pin, resolution, prov, class) = match git_ref(&source) {
                        Some(r) => (
                            r,
                            Resolution::AsAuthored,
                            vec![ProvenanceStep::new(rel, &rpath, "explicit")],
                            "ref-pinned",
                        ),
                        None => (
                            String::new(),
                            Resolution::PlatformDefault,
                            vec![
                                ProvenanceStep::new(rel, &rpath, "absent"),
                                ProvenanceStep::new("", "git ref selection", "platform-default"),
                            ],
                            "floating",
                        ),
                    };
                    out.packets.push(packet(
                        rel,
                        &unit,
                        "module.version-pin",
                        Some(pin),
                        resolution,
                        prov.clone(),
                    ));
                    out.packets.push(packet(
                        rel,
                        &unit,
                        "module.pin-class",
                        Some(class.to_string()),
                        resolution,
                        prov,
                    ));
                }
                // Local modules are repo-pinned by construction (their
                // directory is walked like any other); other sources carry
                // no pin identity this subset can vouch for.
                _ => {}
            }
        }
    }

    // resource.lifecycle.prevent_destroy
    for (rel, items) in &parsed_tf {
        for b in items.iter().filter_map(|it| match it {
            Item::Block(b) if b.kind == "resource" => Some(b),
            _ => None,
        }) {
            let (Some(ty), Some(name)) = (b.labels.first(), b.labels.get(1)) else {
                continue;
            };
            let unit = format!("resource:{ty}.{name}");
            let key_path = format!("resource.{ty}.{name}.lifecycle.prevent_destroy");
            let attr = get_blocks(&b.body, "lifecycle")
                .next()
                .and_then(|lc| get_attr(&lc.body, "prevent_destroy"));
            match attr {
                Some(v) => {
                    let (value, resolution, prov) = resolve_value(rel, &key_path, v, &vars);
                    out.packets.push(packet(
                        rel,
                        &unit,
                        "resource.lifecycle.prevent_destroy",
                        value,
                        resolution,
                        prov,
                    ));
                }
                None => out.packets.push(packet(
                    rel,
                    &unit,
                    "resource.lifecycle.prevent_destroy",
                    Some("false".to_string()),
                    Resolution::PlatformDefault,
                    vec![
                        ProvenanceStep::new(rel, &key_path, "absent"),
                        ProvenanceStep::new("", "prevent_destroy", "platform-default"),
                    ],
                )),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(files: &[(&str, &str)]) -> Retrieved {
        let files: Vec<(String, String)> = files
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        Terraform.retrieve_all(&files, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:#?}", got.packets))
    }

    #[test]
    fn matches_tf_and_autoloaded_tfvars_only() {
        let r = Terraform;
        assert!(r.matches("main.tf"));
        assert!(r.matches("infra/prod/versions.tf"));
        assert!(r.matches("terraform.tfvars"));
        assert!(r.matches("envs/prod/terraform.tfvars"));
        assert!(r.matches("envs/prod/db.auto.tfvars"));
        assert!(!r.matches("main.tf.json"), "JSON syntax is out of subset");
        assert!(
            !r.matches("prod.tfvars"),
            "-var-file only files never auto-load"
        );
        assert!(!r.matches("x.auto.tfvars.json"));
        assert!(!r.matches("terraform.txt"));
    }

    #[test]
    fn pinned_provider_emits_the_constraint_as_authored() {
        let got = one(&[(
            "versions.tf",
            r#"
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
"#,
        )]);
        let p = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(p.resolved_value.as_deref(), Some("~> 5.0"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.format, "terraform");
        assert_eq!(p.file_path, "versions.tf");
        assert_eq!(p.provenance.len(), 1);
        assert_eq!(
            p.provenance[0].key_path,
            "terraform.required_providers.aws.version"
        );
        assert_eq!(p.provenance[0].role, "explicit");
    }

    #[test]
    fn unpinned_provider_is_the_platform_floating_default() {
        // Both unpinned shapes: a required_providers entry without `version`,
        // and a bare legacy provider block.
        let got = one(&[(
            "main.tf",
            r#"
terraform {
  required_providers {
    aws = { source = "hashicorp/aws" }
  }
}
provider "google" {}
"#,
        )]);
        for name in ["aws", "google"] {
            let p = find(
                &got,
                &format!("provider:{name}"),
                "provider.version-constraint",
            );
            assert_eq!(p.resolved_value.as_deref(), Some(""), "{name}");
            assert_eq!(p.resolution, Resolution::PlatformDefault, "{name}");
            assert_eq!(p.provenance.last().unwrap().role, "platform-default");
        }
    }

    #[test]
    fn required_providers_shorthand_and_legacy_version_attr_both_carry() {
        let got = one(&[(
            "main.tf",
            "terraform {\n  required_providers {\n    aws = \">= 2.7.0\"\n  }\n}\nprovider \"google\" {\n  version = \"~> 4.0\"\n}\n",
        )]);
        let aws = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(aws.resolved_value.as_deref(), Some(">= 2.7.0"));
        assert_eq!(
            aws.provenance[0].key_path,
            "terraform.required_providers.aws"
        );
        let google = find(&got, "provider:google", "provider.version-constraint");
        assert_eq!(google.resolved_value.as_deref(), Some("~> 4.0"));
        assert_eq!(google.provenance[0].key_path, "provider.google.version");
    }

    #[test]
    fn required_providers_wins_over_a_legacy_provider_block() {
        let got = one(&[(
            "main.tf",
            "terraform {\n  required_providers {\n    aws = { version = \"~> 5.0\" }\n  }\n}\nprovider \"aws\" {\n  version = \"~> 4.0\"\n}\n",
        )]);
        let p = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(p.resolved_value.as_deref(), Some("~> 5.0"));
        assert_eq!(
            got.packets
                .iter()
                .filter(|q| q.unit == "provider:aws" && q.key == "provider.version-constraint")
                .count(),
            1,
            "one fact per provider, required_providers authoritative"
        );
    }

    #[test]
    fn registry_module_resolves_by_registry_identity_with_pin_shape() {
        let got = one(&[(
            "main.tf",
            r#"
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}
module "ranged" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"
}
module "floating" {
  source = "app.terraform.io/acme/net/aws"
}
"#,
        )]);
        let src = find(&got, "module-call:vpc", "module.source");
        assert_eq!(
            src.resolved_value.as_deref(),
            Some("terraform-aws-modules/vpc/aws"),
            "the registry identity IS the value; nothing is fetched"
        );
        assert_eq!(
            find(&got, "module-call:vpc", "module.source-class")
                .resolved_value
                .as_deref(),
            Some("registry")
        );
        assert_eq!(
            find(&got, "module-call:vpc", "module.pin-class")
                .resolved_value
                .as_deref(),
            Some("exact")
        );
        assert_eq!(
            find(&got, "module-call:ranged", "module.pin-class")
                .resolved_value
                .as_deref(),
            Some("range")
        );
        let floating = find(&got, "module-call:floating", "module.version-pin");
        assert_eq!(floating.resolved_value.as_deref(), Some(""));
        assert_eq!(floating.resolution, Resolution::PlatformDefault);
        assert_eq!(
            find(&got, "module-call:floating", "module.pin-class")
                .resolved_value
                .as_deref(),
            Some("floating"),
            "a private-registry host is still registry class"
        );
    }

    #[test]
    fn git_module_pin_is_the_ref_and_local_modules_emit_no_pin() {
        let got = one(&[(
            "main.tf",
            r#"
module "pinned" {
  source = "git::https://example.com/net.git//modules/vpc?ref=v1.2.0"
}
module "floating" {
  source = "github.com/acme/net"
}
module "local" {
  source = "./modules/db"
}
"#,
        )]);
        let pinned = find(&got, "module-call:pinned", "module.version-pin");
        assert_eq!(pinned.resolved_value.as_deref(), Some("v1.2.0"));
        assert_eq!(pinned.resolution, Resolution::AsAuthored);
        assert_eq!(
            find(&got, "module-call:pinned", "module.pin-class")
                .resolved_value
                .as_deref(),
            Some("ref-pinned")
        );
        assert_eq!(
            find(&got, "module-call:floating", "module.pin-class")
                .resolved_value
                .as_deref(),
            Some("floating")
        );
        assert_eq!(
            find(&got, "module-call:local", "module.source-class")
                .resolved_value
                .as_deref(),
            Some("local")
        );
        assert!(
            !got.packets.iter().any(|p| p.unit == "module-call:local"
                && (p.key == "module.version-pin" || p.key == "module.pin-class")),
            "a relative-source module is repo-pinned by construction: {:#?}",
            got.packets
        );
    }

    #[test]
    fn required_version_and_backend_resolve_with_documented_defaults() {
        let with = one(&[(
            "versions.tf",
            "terraform {\n  required_version = \">= 1.5\"\n  backend \"s3\" {\n    bucket = \"state\"\n  }\n}\n",
        )]);
        let rv = find(&with, "module", "terraform.required_version");
        assert_eq!(rv.resolved_value.as_deref(), Some(">= 1.5"));
        assert_eq!(rv.resolution, Resolution::AsAuthored);
        let be = find(&with, "module", "terraform.backend");
        assert_eq!(be.resolved_value.as_deref(), Some("s3"));
        assert_eq!(be.provenance[0].key_path, "terraform.backend.s3");

        let without = one(&[("main.tf", "resource \"a\" \"b\" {}\n")]);
        let rv = find(&without, "module", "terraform.required_version");
        assert_eq!(rv.resolved_value.as_deref(), Some("none"));
        assert_eq!(rv.resolution, Resolution::PlatformDefault);
        let be = find(&without, "module", "terraform.backend");
        assert_eq!(
            be.resolved_value.as_deref(),
            Some("local"),
            "no backend block: the documented local-state default governs"
        );
        assert_eq!(be.resolution, Resolution::PlatformDefault);

        let cloud = one(&[(
            "main.tf",
            "terraform {\n  cloud {\n    organization = \"acme\"\n  }\n}\n",
        )]);
        assert_eq!(
            find(&cloud, "module", "terraform.backend")
                .resolved_value
                .as_deref(),
            Some("cloud")
        );
    }

    #[test]
    fn prevent_destroy_explicit_and_defaulted() {
        let got = one(&[(
            "main.tf",
            "resource \"aws_db_instance\" \"main\" {\n  lifecycle {\n    prevent_destroy = true\n  }\n}\nresource \"aws_s3_bucket\" \"logs\" {}\n",
        )]);
        let on = find(
            &got,
            "resource:aws_db_instance.main",
            "resource.lifecycle.prevent_destroy",
        );
        assert_eq!(on.resolved_value.as_deref(), Some("true"));
        assert_eq!(on.resolution, Resolution::AsAuthored);
        let off = find(
            &got,
            "resource:aws_s3_bucket.logs",
            "resource.lifecycle.prevent_destroy",
        );
        assert_eq!(off.resolved_value.as_deref(), Some("false"));
        assert_eq!(off.resolution, Resolution::PlatformDefault);
        assert_eq!(off.provenance[0].role, "absent");
    }

    #[test]
    fn var_reference_resolves_one_hop_from_the_default() {
        let got = one(&[
            (
                "infra/main.tf",
                "resource \"aws_db_instance\" \"main\" {\n  lifecycle {\n    prevent_destroy = var.protect\n  }\n}\n",
            ),
            (
                "infra/variables.tf",
                "variable \"protect\" {\n  default = true\n}\n",
            ),
        ]);
        let p = find(
            &got,
            "resource:aws_db_instance.main",
            "resource.lifecycle.prevent_destroy",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("true"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        // The chain tells the whole story: reference, then the default that
        // supplied the value (the last step).
        assert_eq!(p.provenance.len(), 2);
        assert_eq!(p.provenance[0].role, "reference");
        assert_eq!(p.provenance[1].file, "infra/variables.tf");
        assert_eq!(p.provenance[1].key_path, "variable.protect.default");
        assert_eq!(p.provenance[1].role, "default");
    }

    #[test]
    fn tfvars_override_wins_over_the_default_with_a_recorded_chain() {
        let got = one(&[
            (
                "envs/prod/main.tf",
                "provider \"aws\" {\n  version = var.aws_version\n}\n",
            ),
            (
                "envs/prod/variables.tf",
                "variable \"aws_version\" {\n  default = \"~> 4.0\"\n}\n",
            ),
            ("envs/prod/terraform.tfvars", "aws_version = \"~> 5.0\"\n"),
        ]);
        let p = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(
            p.resolved_value.as_deref(),
            Some("~> 5.0"),
            "tfvars beats the variable default"
        );
        assert_eq!(p.resolution, Resolution::AsAuthored);
        let roles: Vec<&str> = p.provenance.iter().map(|s| s.role.as_str()).collect();
        assert_eq!(
            roles,
            vec!["reference", "default", "override"],
            "the chain records default vs override: {:#?}",
            p.provenance
        );
        assert_eq!(p.provenance[2].file, "envs/prod/terraform.tfvars");
    }

    #[test]
    fn later_auto_tfvars_wins_lexically() {
        let got = one(&[
            ("main.tf", "provider \"aws\" {\n  version = var.v\n}\n"),
            ("a.auto.tfvars", "v = \"1.0.0\"\n"),
            ("b.auto.tfvars", "v = \"2.0.0\"\n"),
            ("terraform.tfvars", "v = \"0.1.0\"\n"),
        ]);
        let p = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(
            p.resolved_value.as_deref(),
            Some("2.0.0"),
            "terraform.tfvars first, then *.auto.tfvars lexically, later wins"
        );
    }

    #[test]
    fn unresolvable_variables_abstain_never_guess() {
        let got = one(&[(
            "main.tf",
            "variable \"a\" {}\nprovider \"aws\" {\n  version = var.a\n}\nprovider \"google\" {\n  version = var.ghost\n}\n",
        )]);
        // declared, no default, no tfvars: the value arrives from -var/env —
        // outside the repo.
        let a = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(a.resolved_value, None);
        assert_eq!(a.resolution, Resolution::Unresolvable);
        assert_eq!(a.provenance.last().unwrap().role, "project-setting");
        // undeclared: still unresolvable, said differently.
        let g = find(&got, "provider:google", "provider.version-constraint");
        assert_eq!(g.resolution, Resolution::Unresolvable);
        assert_eq!(g.provenance.last().unwrap().role, "undeclared");
    }

    #[test]
    fn expression_valued_keys_are_unresolvable_never_guessed() {
        let got = one(&[(
            "main.tf",
            "terraform {\n  required_version = local.v\n}\nprovider \"aws\" {\n  version = \"${var.major}.0\"\n}\n",
        )]);
        let rv = find(&got, "module", "terraform.required_version");
        assert_eq!(rv.resolved_value, None);
        assert_eq!(rv.resolution, Resolution::Unresolvable);
        assert_eq!(rv.provenance[0].role, "expression");
        let p = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(
            p.resolution,
            Resolution::Unresolvable,
            "a template string is an expression, not a literal"
        );
    }

    #[test]
    fn non_literal_tfvars_winner_is_unresolvable_not_a_fallback() {
        // The tfvars assignment WINS the precedence even when it is not a
        // literal — so the value is unresolvable, not the default.
        let got = one(&[
            (
                "main.tf",
                "variable \"v\" {\n  default = \"1.0.0\"\n}\nprovider \"aws\" {\n  version = var.v\n}\n",
            ),
            ("terraform.tfvars", "v = [\"not\", \"a\", \"scalar\"]\n"),
        ]);
        let p = find(&got, "provider:aws", "provider.version-constraint");
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.provenance.last().unwrap().role, "non-literal");
    }

    #[test]
    fn one_module_merges_across_files_and_dirs_stay_separate() {
        let got = one(&[
            (
                "envs/prod/backend.tf",
                "terraform {\n  backend \"gcs\" {\n    bucket = \"b\"\n  }\n}\n",
            ),
            (
                "envs/prod/versions.tf",
                "terraform {\n  required_version = \">= 1.5\"\n}\n",
            ),
            ("envs/dev/main.tf", "resource \"a\" \"b\" {}\n"),
        ]);
        // prod merges the two terraform blocks: backend from one file,
        // required_version from the other.
        let prod_backend = got
            .packets
            .iter()
            .find(|p| p.file_path == "envs/prod/backend.tf" && p.key == "terraform.backend")
            .expect("prod backend packet");
        assert_eq!(prod_backend.resolved_value.as_deref(), Some("gcs"));
        let prod_rv = got
            .packets
            .iter()
            .find(|p| {
                p.file_path == "envs/prod/versions.tf" && p.key == "terraform.required_version"
            })
            .expect("prod required_version packet");
        assert_eq!(prod_rv.resolved_value.as_deref(), Some(">= 1.5"));
        // dev is its own module with its own defaults.
        let dev_backend = got
            .packets
            .iter()
            .find(|p| p.file_path == "envs/dev/main.tf" && p.key == "terraform.backend")
            .expect("dev backend packet");
        assert_eq!(dev_backend.resolved_value.as_deref(), Some("local"));
    }

    #[test]
    fn comments_heredocs_and_unknown_constructs_do_not_derail_parsing() {
        let got = one(&[(
            "main.tf",
            r#"
# leading comment
terraform {
  required_version = ">= 1.5" // trailing comment
}
/* block
   comment */
resource "aws_instance" "web" {
  user_data = <<-EOT
    #!/bin/sh
    echo "not = config" { }
  EOT
  count     = length(var.azs)
  tags = {
    Name = "web"
  }
  lifecycle {
    prevent_destroy = false
  }
}
"#,
        )]);
        assert_eq!(got.unparseable, 0, "the subset parses around what it skips");
        assert_eq!(
            find(&got, "module", "terraform.required_version")
                .resolved_value
                .as_deref(),
            Some(">= 1.5")
        );
        let p = find(
            &got,
            "resource:aws_instance.web",
            "resource.lifecycle.prevent_destroy",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("false"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn malformed_hcl_degrades_to_an_unparseable_count() {
        let got = one(&[
            ("bad.tf", "resource \"a\" \"b\" {\n  never = closed\n"),
            ("good.tf", "resource \"c\" \"d\" {}\n"),
        ]);
        assert_eq!(got.unparseable, 1);
        assert!(
            got.packets.iter().any(|p| p.unit == "resource:c.d"),
            "one bad file degrades coverage, never the directory: {:#?}",
            got.packets
        );
    }

    #[test]
    fn a_tfvars_only_directory_is_not_a_module() {
        let got = one(&[("shared/terraform.tfvars", "region = \"us-east1\"\n")]);
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 0);
    }

    #[test]
    fn source_classification_follows_the_documented_grammar() {
        assert_eq!(classify_source("./modules/db"), "local");
        assert_eq!(classify_source("../shared/net"), "local");
        assert_eq!(classify_source("terraform-aws-modules/vpc/aws"), "registry");
        assert_eq!(classify_source("app.terraform.io/acme/net/aws"), "registry");
        assert_eq!(
            classify_source("terraform-aws-modules/vpc/aws//modules/sub"),
            "registry"
        );
        assert_eq!(classify_source("git::https://x.com/r.git"), "git");
        assert_eq!(classify_source("git@github.com:acme/net.git"), "git");
        assert_eq!(classify_source("github.com/acme/net"), "git");
        assert_eq!(classify_source("s3::https://bucket/x.zip"), "other");
        assert_eq!(classify_source("https://example.com/x.zip"), "other");
    }
}
