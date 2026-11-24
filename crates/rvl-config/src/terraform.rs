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
//!   * the RESOURCE-ATTRIBUTE lane (po-pk3fp.13) — a fixed table
//!     ([`RESOURCE_ATTRS`]) of attributes the control frames ask about, each
//!     with the provider-documented default for an absent attribute:
//!     `resource.aws_db_instance.backup_retention_period` (`0`),
//!     `resource.aws_rds_cluster.backup_retention_period` (`1`), and
//!     `resource.google_sql_database_instance.backup_configuration.enabled` /
//!     `.point_in_time_recovery_enabled` (`false`). The zone-spread facts
//!     (RC-017): `resource.aws_db_instance.multi_az` (`false`),
//!     `resource.google_sql_database_instance.settings.availability_type`
//!     (`ZONAL`), `resource.google_container_cluster.location-shape`
//!     (`region` | `zone`, from the `location` name) and
//!     `resource.google_container_node_pool.node_locations-count` (the
//!     length of a literal list). The last two have no default an absent
//!     attribute can take: the provider block or the parent cluster supplies
//!     it, so they are Unresolvable. No other resource attribute is read. A
//!     `dynamic` block on the path is Unresolvable.
//!   * the LEAST-PRIVILEGE facts (RC-044), one per resource of the kinds
//!     that carry one: `resource.google_service_account_key.declared` and
//!     `resource.aws_iam_access_key.declared` (a static key exists;
//!     `count`/`for_each` can make it `false` or Unresolvable),
//!     `resource.google_iam.role-class` (`primitive` | `viewer` | `custom` |
//!     `predefined`), `resource.aws_iam.statement-wildcard` (`none` |
//!     `resource` | `action` | `action-and-resource`, read from a
//!     `jsonencode({...})`, heredoc or string policy, or a
//!     `data "aws_iam_policy_document"`), and
//!     `resource.google_container_node_pool.node-identity`
//!     (`default-account` | `cloud-platform-scope` | `dedicated`, for a node
//!     pool or a cluster's inline `node_config`). A value that needs
//!     evaluation is Unresolvable, never a guess.
//!   * `terraform.module-kind` (`root` | `reusable` | `indeterminate`) and,
//!     for roots only, `terraform.root-backend` — the same fact as
//!     `terraform.backend`, emitted where a missing backend is a finding and
//!     nowhere else (see [`emit_module_kinds`]).
//!
//! What a spec must not judge is carried as [`crate::UNDECIDED_PREFIX`] and
//! why (see [`gate_undeployed`]): every fact of a file that is not deployed
//! to production ([`crate::non_production`]); a resource attribute a
//! reusable module takes from a variable or leaves unset; and the backup
//! and availability facts of a Cloud SQL read replica.
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
        self.retrieve_all(std::path::Path::new(""), &files, snapshot_id)
    }

    /// Directory-scoped retrieval: Terraform's unit of configuration is the
    /// module DIRECTORY, so resolution (variable defaults, tfvars overlays)
    /// spans the files the walk claimed. Local (relative-source) modules need
    /// no special following: their directory is a group here like any other.
    fn retrieve_all(
        &self,
        root: &std::path::Path,
        files: &[(String, String)],
        snapshot_id: &str,
    ) -> Retrieved {
        let mut out = Retrieved::default();
        let mut dirs: BTreeMap<&str, Vec<&(String, String)>> = BTreeMap::new();
        for f in files {
            dirs.entry(dir_of(&f.0)).or_default().push(f);
        }
        // Whether a module is a root or a reusable one depends on who calls
        // it, so the kind is settled only after every directory is read.
        let mut modules: Vec<ModuleFacts> = Vec::new();
        for (dir, mut group) in dirs {
            group.sort_by(|a, b| a.0.cmp(&b.0));
            modules.extend(retrieve_dir(dir, &group, snapshot_id, &mut out));
        }
        let reusable = emit_module_kinds(&modules, snapshot_id, &mut out);
        gate_undeployed(root, &reusable, &mut out);
        out
    }
}

/// Undecide what a spec must not judge here (see [`crate::non_production`]).
///
///   * Every packet of a file that is not deployed to production, but
///     `terraform.module-kind`: that says what a module IS, not a setting.
///   * In a reusable module, a resource attribute the module takes from a
///     variable or leaves unset: the caller sets it, so the module's
///     default is no fact about any deployment. A literal the module
///     authors stays a fact, and so does `lifecycle.prevent_destroy`,
///     which no caller can set.
fn gate_undeployed(root: &std::path::Path, reusable: &[&str], out: &mut Retrieved) {
    let repo = crate::non_production::root_token(root);
    for p in &mut out.packets {
        if p.key != "terraform.module-kind" {
            if let Some(why) = crate::non_production::reason(repo, &p.file_path) {
                crate::non_production::undecide(p, &why);
            }
        }
        let caller_sets = p.resolution == Resolution::PlatformDefault
            || p.provenance.first().is_some_and(|s| s.role == "reference");
        if caller_sets
            && p.unit.starts_with("resource:")
            && p.key != "resource.lifecycle.prevent_destroy"
            && reusable.contains(&dir_of(&p.file_path))
        {
            crate::non_production::undecide(p, "reusable module: the caller sets this");
        }
    }
}

/// The repo-relative directory a LOCAL module source names, resolved against
/// the calling module's directory. `None` when the path climbs out of the
/// repo: nothing committed here says what is there.
fn local_module_dir(caller_dir: &str, source: &str) -> Option<String> {
    let mut parts: Vec<&str> = caller_dir.split('/').filter(|p| !p.is_empty()).collect();
    for seg in source.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            seg => parts.push(seg),
        }
    }
    Some(parts.join("/"))
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
    /// A heredoc's body. Only a policy document is ever read from one
    /// ([`policy_wildcard_fact`]); everywhere else it is expression-grade.
    Heredoc(String),
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
                let (ni, body) = scan_heredoc(src, b, i + 2);
                toks.push(Tok::Heredoc(body));
                i = ni;
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
/// the terminating tag line and the body between the two. The body is never
/// a literal this lane inventories, only a document it may read.
fn scan_heredoc(src: &str, b: &[u8], mut i: usize) -> (usize, String) {
    if i < b.len() && b[i] == b'-' {
        i += 1;
    }
    let tag_start = i;
    while i < b.len() && ((b[i] as char).is_ascii_alphanumeric() || b[i] == b'_') {
        i += 1;
    }
    let tag = &src[tag_start..i];
    if tag.is_empty() {
        return (i, String::new());
    }
    // consume to end of the opening line, then whole lines until the tag
    while i < b.len() && b[i] != b'\n' {
        i += 1;
    }
    let body_start = (i + 1).min(b.len());
    let mut body_end = b.len();
    while i < b.len() {
        i += 1; // past the newline
        let line_start = i;
        while i < b.len() && b[i] != b'\n' {
            i += 1;
        }
        if src[line_start..i].trim() == tag {
            body_end = line_start;
            break;
        }
    }
    (i, src[body_start..body_end.max(body_start)].to_string())
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
    /// A list literal `[a, b, ...]` whose items are all literal scalars.
    List(Vec<String>),
    /// `jsonencode(...)` of a literal structure: read as a document.
    Json(Doc),
    /// A heredoc's body.
    Heredoc(String),
    /// Anything needing evaluation: templates, functions, other references,
    /// lists, heredocs, operators. Never resolved, never guessed.
    Expr,
}

/// A JSON-shaped document: the argument of `jsonencode(...)`, or a policy
/// string or heredoc. A part that needs evaluation is [`Doc::Unknown`], so
/// the rest of the document stays readable.
#[derive(Debug, Clone, PartialEq)]
enum Doc {
    Str(String),
    List(Vec<Doc>),
    Map(Vec<(String, Doc)>),
    Unknown,
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
            Some(Tok::Heredoc(_)) => {
                let Some(Tok::Heredoc(body)) = self.bump() else {
                    unreachable!()
                };
                Value::Heredoc(body)
            }
            Some(Tok::Ident(w))
                if w == "jsonencode"
                    && matches!(self.toks.get(self.i + 1), Some(Tok::Punct('('))) =>
            {
                self.i += 2;
                let doc = self.parse_doc();
                while matches!(self.peek(), Some(Tok::Newline)) {
                    self.bump();
                }
                if matches!(self.peek(), Some(Tok::Punct(')'))) {
                    self.bump();
                    Value::Json(doc)
                } else {
                    // More than one argument: skip to the call's `)`.
                    self.consume_list();
                    Value::Expr
                }
            }
            Some(Tok::Punct('{')) => {
                self.bump();
                return self.parse_object();
            }
            Some(Tok::Punct('[')) => {
                self.bump();
                self.parse_list()
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

    /// A list literal after its `[`. Only literal scalar items count: any
    /// other item (a reference, a call, a nested list) degrades the whole
    /// list to [`Value::Expr`], and the rest is consumed as an expression.
    fn parse_list(&mut self) -> Value {
        let mut items = Vec::new();
        loop {
            while matches!(self.peek(), Some(Tok::Newline)) {
                self.bump();
            }
            if matches!(self.peek(), Some(Tok::Punct(']'))) {
                self.bump();
                return Value::List(items);
            }
            let lit = match self.peek() {
                Some(Tok::Str {
                    template: false, ..
                })
                | Some(Tok::Num(_)) => match self.bump() {
                    Some(Tok::Str { value, .. }) | Some(Tok::Num(value)) => value,
                    _ => unreachable!(),
                },
                _ => {
                    self.consume_list();
                    return Value::Expr;
                }
            };
            items.push(lit);
            while matches!(self.peek(), Some(Tok::Newline)) {
                self.bump();
            }
            match self.peek() {
                Some(Tok::Punct(',')) => {
                    self.bump();
                }
                Some(Tok::Punct(']')) => {}
                _ => {
                    self.consume_list();
                    return Value::Expr;
                }
            }
        }
    }

    /// One document value inside `jsonencode(...)`. Anything but a plain
    /// string, an object or a list is consumed as an expression and read as
    /// [`Doc::Unknown`]; every path consumes at least one token or stops at a
    /// closer its caller owns.
    fn parse_doc(&mut self) -> Doc {
        while matches!(self.peek(), Some(Tok::Newline)) {
            self.bump();
        }
        let doc = match self.peek() {
            Some(Tok::Str {
                template: false, ..
            }) => {
                let Some(Tok::Str { value, .. }) = self.bump() else {
                    unreachable!()
                };
                Doc::Str(value)
            }
            Some(Tok::Punct('{')) => {
                self.bump();
                self.parse_doc_map()
            }
            Some(Tok::Punct('[')) => {
                self.bump();
                self.parse_doc_list()
            }
            _ => {
                self.consume_doc_expr();
                return Doc::Unknown;
            }
        };
        let ends = matches!(
            self.peek(),
            None | Some(Tok::Newline)
                | Some(Tok::Punct('}'))
                | Some(Tok::Punct(','))
                | Some(Tok::Punct(']'))
                | Some(Tok::Punct(')'))
        );
        if !ends {
            self.consume_doc_expr();
            return Doc::Unknown;
        }
        doc
    }

    /// A document object after its `{`: `key = value` or `key: value`.
    fn parse_doc_map(&mut self) -> Doc {
        let mut fields = Vec::new();
        loop {
            self.skip_separators();
            match self.peek() {
                Some(Tok::Punct('}')) => {
                    self.bump();
                    return Doc::Map(fields);
                }
                Some(Tok::Ident(_))
                | Some(Tok::Str {
                    template: false, ..
                }) => {
                    let key = match self.bump() {
                        Some(Tok::Ident(k)) | Some(Tok::Str { value: k, .. }) => k,
                        _ => unreachable!(),
                    };
                    if !matches!(self.peek(), Some(Tok::Punct('=')) | Some(Tok::Punct(':'))) {
                        self.skip_balanced_brace();
                        return Doc::Unknown;
                    }
                    self.bump();
                    let v = self.parse_doc();
                    fields.push((key, v));
                }
                None => return Doc::Unknown,
                _ => {
                    self.skip_balanced_brace();
                    return Doc::Unknown;
                }
            }
        }
    }

    /// A document list after its `[`.
    fn parse_doc_list(&mut self) -> Doc {
        let mut items = Vec::new();
        loop {
            self.skip_separators();
            match self.peek() {
                Some(Tok::Punct(']')) => {
                    self.bump();
                    return Doc::List(items);
                }
                // Malformed: leave the closer to the caller that owns it.
                None | Some(Tok::Punct('}')) | Some(Tok::Punct(')')) => return Doc::Unknown,
                _ => items.push(self.parse_doc()),
            }
        }
    }

    /// Skip to just past the `]` closing the CURRENT list (depth already
    /// inside it).
    fn consume_list(&mut self) {
        let mut depth = 1usize;
        while let Some(t) = self.bump() {
            match t {
                Tok::Punct('(') | Tok::Punct('[') | Tok::Punct('{') => depth += 1,
                Tok::Punct(')') | Tok::Punct(']') | Tok::Punct('}') => {
                    depth -= 1;
                    if depth == 0 {
                        return;
                    }
                }
                _ => {}
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

    /// [`Self::consume_expr`] inside `jsonencode(...)`: an unmatched `)` is
    /// the call's own and ends the expression too.
    fn consume_doc_expr(&mut self) {
        let mut depth = 0usize;
        while let Some(t) = self.peek() {
            match t {
                Tok::Newline if depth == 0 => return,
                Tok::Punct('}') | Tok::Punct(',') | Tok::Punct(']') | Tok::Punct(')')
                    if depth == 0 =>
                {
                    return
                }
                Tok::Punct('(') | Tok::Punct('[') | Tok::Punct('{') => depth += 1,
                Tok::Punct(')') | Tok::Punct(']') | Tok::Punct('}') => depth -= 1,
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

/// One documented fact about a resource type: the resource-attribute lane
/// (po-pk3fp.13). A TABLE, not a generic attribute dump: every row is a key a
/// control frame asks about, with the default the provider documents for an
/// absent attribute. Anything not listed here is never read.
struct ResourceAttr {
    resource_type: &'static str,
    packet_key: &'static str,
    /// Nested blocks from the resource body down to the attribute.
    blocks: &'static [&'static str],
    attr: &'static str,
    absent: Absent,
    shape: Shape,
    /// An attribute whose presence means this fact does not describe the
    /// resource, so no packet is emitted.
    unless_attr: Option<&'static str>,
}

/// What an absent attribute means.
enum Absent {
    /// The default the provider documents.
    Default(&'static str),
    /// The value comes from somewhere this resource body does not say (the
    /// provider configuration, a parent resource): the packet abstains, and
    /// the provenance names where the value lives.
    Elsewhere(&'static str),
}

/// What the packet value is, given the attribute's resolved value.
enum Shape {
    /// The attribute's value itself.
    AsWritten,
    /// `region` or `zone`, from a GCP location name ([`location_shape`]).
    Location,
    /// How many items a literal list holds; a non-empty list only, since an
    /// empty one means "not set" to the provider.
    ListCount,
}

const RESOURCE_ATTRS: &[ResourceAttr] = &[
    // RC-030 / RC-054: 0 disables automated backups, and with them
    // point-in-time recovery. A read replica is excluded: its source carries
    // the backup posture, and the documented 0 would flag every replica.
    ResourceAttr {
        resource_type: "aws_db_instance",
        packet_key: "resource.aws_db_instance.backup_retention_period",
        blocks: &[],
        attr: "backup_retention_period",
        absent: Absent::Default("0"),
        shape: Shape::AsWritten,
        unless_attr: Some("replicate_source_db"),
    },
    ResourceAttr {
        resource_type: "aws_rds_cluster",
        packet_key: "resource.aws_rds_cluster.backup_retention_period",
        blocks: &[],
        attr: "backup_retention_period",
        absent: Absent::Default("1"),
        shape: Shape::AsWritten,
        unless_attr: None,
    },
    ResourceAttr {
        resource_type: "google_sql_database_instance",
        packet_key: "resource.google_sql_database_instance.backup_configuration.enabled",
        blocks: &["settings", "backup_configuration"],
        attr: "enabled",
        absent: Absent::Default("false"),
        shape: Shape::AsWritten,
        unless_attr: None,
    },
    ResourceAttr {
        resource_type: "google_sql_database_instance",
        packet_key: "resource.google_sql_database_instance.backup_configuration.point_in_time_recovery_enabled",
        blocks: &["settings", "backup_configuration"],
        attr: "point_in_time_recovery_enabled",
        absent: Absent::Default("false"),
        shape: Shape::AsWritten,
        unless_attr: None,
    },
    // RC-017: a single-AZ instance has no standby in another zone.
    ResourceAttr {
        resource_type: "aws_db_instance",
        packet_key: "resource.aws_db_instance.multi_az",
        blocks: &[],
        attr: "multi_az",
        absent: Absent::Default("false"),
        shape: Shape::AsWritten,
        unless_attr: None,
    },
    // RC-017: ZONAL has no failover replica in a second zone.
    ResourceAttr {
        resource_type: "google_sql_database_instance",
        packet_key: "resource.google_sql_database_instance.settings.availability_type",
        blocks: &["settings"],
        attr: "availability_type",
        absent: Absent::Default("ZONAL"),
        shape: Shape::AsWritten,
        unless_attr: None,
    },
    // RC-017: a zone location is a zonal cluster (one control-plane zone); a
    // region location is a regional one. An absent location falls back to
    // the provider block's, which this lane does not read.
    ResourceAttr {
        resource_type: "google_container_cluster",
        packet_key: "resource.google_container_cluster.location-shape",
        blocks: &[],
        attr: "location",
        absent: Absent::Elsewhere("provider-setting"),
        shape: Shape::Location,
        unless_attr: None,
    },
    // RC-017: how many zones the pool's nodes spread over. An absent list
    // inherits the cluster's zones, which the pool body does not name.
    ResourceAttr {
        resource_type: "google_container_node_pool",
        packet_key: "resource.google_container_node_pool.node_locations-count",
        blocks: &[],
        attr: "node_locations",
        absent: Absent::Elsewhere("inherited"),
        shape: Shape::ListCount,
        unless_attr: None,
    },
];

/// The Cloud SQL facts a read replica (`master_instance_name` set) carries
/// undecided: its primary holds the backups, and the replica's own
/// availability type is not the instance's failover posture.
const REPLICA_UNDECIDED: &[&str] = &[
    "resource.google_sql_database_instance.backup_configuration.enabled",
    "resource.google_sql_database_instance.backup_configuration.point_in_time_recovery_enabled",
    "resource.google_sql_database_instance.settings.availability_type",
];

/// The shape of a GCP location name: `region` (`us-central1`) or `zone`
/// (`us-central1-a`). Anything else is `None`, never a guess.
fn location_shape(location: &str) -> Option<&'static str> {
    let is_region = |area: &str, place: &str| {
        !area.is_empty()
            && area.bytes().all(|c| c.is_ascii_lowercase())
            && place.bytes().take_while(|c| c.is_ascii_lowercase()).count() > 0
            && place
                .trim_start_matches(|c: char| c.is_ascii_lowercase())
                .bytes()
                .all(|c| c.is_ascii_digit())
            && place.ends_with(|c: char| c.is_ascii_digit())
    };
    match location.split('-').collect::<Vec<_>>()[..] {
        [area, place] if is_region(area, place) => Some("region"),
        [area, place, zone]
            if is_region(area, place)
                && zone.len() == 1
                && zone.bytes().all(|c| c.is_ascii_lowercase()) =>
        {
            Some("zone")
        }
        _ => None,
    }
}

/// Turn one attribute lookup into a packet's (value, resolution, provenance)
/// for `row`.
fn resolve_row(
    row: &ResourceAttr,
    rel: &str,
    key_path: &str,
    found: AttrLookup<'_>,
    vars: &VarTable,
) -> (Option<String>, Resolution, Vec<ProvenanceStep>) {
    let unresolvable = |mut chain: Vec<ProvenanceStep>, role: &str| {
        chain.push(ProvenanceStep::new(rel, key_path, role));
        (None, Resolution::Unresolvable, chain)
    };
    let v = match found {
        AttrLookup::Found(v) => v,
        AttrLookup::Absent => {
            let absent = ProvenanceStep::new(rel, key_path, "absent");
            return match row.absent {
                Absent::Default(d) => (
                    Some(d.to_string()),
                    Resolution::PlatformDefault,
                    vec![
                        absent,
                        ProvenanceStep::new("", row.attr, "platform-default"),
                    ],
                ),
                Absent::Elsewhere(role) => (
                    None,
                    Resolution::Unresolvable,
                    vec![absent, ProvenanceStep::new("", row.attr, role)],
                ),
            };
        }
        AttrLookup::Dynamic => return unresolvable(Vec::new(), "expression"),
    };
    match row.shape {
        Shape::AsWritten => resolve_value(rel, key_path, v, vars),
        Shape::Location => match resolve_value(rel, key_path, v, vars) {
            (Some(loc), res, chain) => match location_shape(&loc) {
                Some(shape) => (Some(shape.to_string()), res, chain),
                None => unresolvable(chain, "unrecognized"),
            },
            unresolved => unresolved,
        },
        Shape::ListCount => match v {
            Value::List(items) if !items.is_empty() => (
                Some(items.len().to_string()),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(rel, key_path, "explicit")],
            ),
            Value::List(_) => unresolvable(Vec::new(), "empty"),
            // A list from a variable never resolves: one-hop resolution
            // carries scalar literals only.
            _ => match resolve_value(rel, key_path, v, vars) {
                (_, Resolution::Unresolvable, chain) => (None, Resolution::Unresolvable, chain),
                (_, _, chain) => unresolvable(chain, "not-a-list"),
            },
        },
    }
}

/// What a walk down a resource body for one [`ResourceAttr`] found.
enum AttrLookup<'a> {
    Found(&'a Value),
    /// Decidably not authored: the documented default governs.
    Absent,
    /// A `dynamic` block stands where the path continues. Whether it renders
    /// the block at all needs evaluation, so the default would be a guess.
    Dynamic,
}

fn lookup_attr<'a>(body: &'a [Item], blocks: &[&str], attr: &str) -> AttrLookup<'a> {
    let mut body = body;
    for block in blocks {
        if get_blocks(body, "dynamic").any(|d| d.labels.first().is_some_and(|l| l == block)) {
            return AttrLookup::Dynamic;
        }
        match get_blocks(body, block).next() {
            Some(b) => body = &b.body,
            None => return AttrLookup::Absent,
        }
    }
    match get_attr(body, attr) {
        Some(v) => AttrLookup::Found(v),
        None => AttrLookup::Absent,
    }
}

// --- the least-privilege facts (RC-044) ---

/// One packet's (value, resolution, provenance chain).
type Fact = (Option<String>, Resolution, Vec<ProvenanceStep>);

fn unresolved(mut chain: Vec<ProvenanceStep>, rel: &str, key_path: &str, role: &str) -> Fact {
    chain.push(ProvenanceStep::new(rel, key_path, role));
    (None, Resolution::Unresolvable, chain)
}

/// The IAM grants whose `role` is classed by [`role_class`].
const GOOGLE_IAM_GRANTS: &[&str] = &[
    "google_project_iam_member",
    "google_project_iam_binding",
    "google_folder_iam_member",
    "google_folder_iam_binding",
    "google_organization_iam_member",
    "google_organization_iam_binding",
];

/// The AWS resources whose `policy` is an IAM policy document.
const AWS_IAM_POLICIES: &[&str] = &[
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
];

/// The least-privilege fact one resource carries, if its type has one:
/// (packet key, fact).
fn least_privilege_fact(
    ty: &str,
    name: &str,
    body: &[Item],
    rel: &str,
    vars: &VarTable,
) -> Option<(&'static str, Fact)> {
    let base = format!("resource.{ty}.{name}");
    let key = match ty {
        "google_service_account_key" => "resource.google_service_account_key.declared",
        "aws_iam_access_key" => "resource.aws_iam_access_key.declared",
        ty if GOOGLE_IAM_GRANTS.contains(&ty) => "resource.google_iam.role-class",
        ty if AWS_IAM_POLICIES.contains(&ty) => "resource.aws_iam.statement-wildcard",
        "google_container_node_pool" => "resource.google_container_node_pool.node-identity",
        // A cluster's nodes are described here only by an inline node_config;
        // without one they are a separate node pool's.
        "google_container_cluster"
            if get_blocks(body, "node_config").next().is_some()
                || get_blocks(body, "dynamic")
                    .any(|d| d.labels.first().is_some_and(|l| l == "node_config")) =>
        {
            "resource.google_container_node_pool.node-identity"
        }
        _ => return None,
    };
    let fact = match key {
        "resource.google_iam.role-class" => role_class_fact(body, rel, &base, vars),
        "resource.aws_iam.statement-wildcard" => policy_wildcard_fact(
            get_attr(body, "policy"),
            rel,
            &format!("{base}.policy"),
            vars,
        ),
        "resource.google_container_node_pool.node-identity" => {
            node_identity_fact(body, rel, &base, vars)
        }
        _ => declared_fact(body, rel, &base, vars),
    };
    Some((key, fact))
}

/// Whether the resource exists: `true` unless `count` or `for_each` can make
/// it zero instances. A literal zero (or an empty literal collection) is
/// `false`; one that needs evaluation (`var.create ? 1 : 0`) abstains.
fn declared_fact(body: &[Item], rel: &str, base: &str, vars: &VarTable) -> Fact {
    if let Some(v) = get_attr(body, "count") {
        let key_path = format!("{base}.count");
        return match resolve_value(rel, &key_path, v, vars) {
            (Some(n), res, chain) => match n.parse::<u64>() {
                Ok(n) => (Some((n > 0).to_string()), res, chain),
                Err(_) => unresolved(chain, rel, &key_path, "not-a-count"),
            },
            unknown => unknown,
        };
    }
    if let Some(v) = get_attr(body, "for_each") {
        let key_path = format!("{base}.for_each");
        let explicit = vec![ProvenanceStep::new(rel, &key_path, "explicit")];
        return match v {
            Value::List(items) => (
                Some((!items.is_empty()).to_string()),
                Resolution::AsAuthored,
                explicit,
            ),
            Value::Object(attrs) => (
                Some((!attrs.is_empty()).to_string()),
                Resolution::AsAuthored,
                explicit,
            ),
            _ => unresolved(Vec::new(), rel, &key_path, "expression"),
        };
    }
    (
        Some("true".to_string()),
        Resolution::AsAuthored,
        vec![ProvenanceStep::new(rel, base, "explicit")],
    )
}

/// The class of a GCP IAM role name: the basic roles owner and editor are
/// `primitive`, viewer is `viewer`, a project or organization role is
/// `custom`, any other `roles/...` is `predefined`. Anything else is `None`.
fn role_class(role: &str) -> Option<&'static str> {
    match role {
        "roles/owner" | "roles/editor" => Some("primitive"),
        "roles/viewer" => Some("viewer"),
        r if r.starts_with("projects/") || r.starts_with("organizations/") => Some("custom"),
        r if r.len() > "roles/".len() && r.starts_with("roles/") => Some("predefined"),
        _ => None,
    }
}

fn role_class_fact(body: &[Item], rel: &str, base: &str, vars: &VarTable) -> Fact {
    let key_path = format!("{base}.role");
    let Some(v) = get_attr(body, "role") else {
        return unresolved(Vec::new(), rel, &key_path, "absent");
    };
    match resolve_value(rel, &key_path, v, vars) {
        (Some(role), res, chain) => match role_class(&role) {
            Some(class) => (Some(class.to_string()), res, chain),
            None => unresolved(chain, rel, &key_path, "unrecognized"),
        },
        unknown => unknown,
    }
}

/// The scope that grants a node every API its service account may call.
const CLOUD_PLATFORM_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";

/// Who the nodes act as. `default-account`: no `service_account` (the
/// Compute Engine default account), or that account named outright.
/// `cloud-platform-scope`: a custom account holding the all-APIs scope.
/// `dedicated`: a custom account with narrower scopes; an absent
/// `oauth_scopes` is the provider's default set, which excludes
/// cloud-platform.
fn node_identity_fact(body: &[Item], rel: &str, base: &str, vars: &VarTable) -> Fact {
    let account_path = format!("{base}.node_config.service_account");
    let (account, res, mut chain) = match lookup_attr(body, &["node_config"], "service_account") {
        AttrLookup::Dynamic => {
            return unresolved(
                Vec::new(),
                rel,
                &format!("{base}.node_config"),
                "expression",
            )
        }
        AttrLookup::Absent => {
            return (
                Some("default-account".to_string()),
                Resolution::PlatformDefault,
                vec![
                    ProvenanceStep::new(rel, &account_path, "absent"),
                    ProvenanceStep::new("", "service_account", "platform-default"),
                ],
            )
        }
        AttrLookup::Found(v) => match resolve_value(rel, &account_path, v, vars) {
            (Some(a), res, chain) => (a, res, chain),
            unknown => return unknown,
        },
    };
    if account.is_empty()
        || account == "default"
        || account.ends_with("-compute@developer.gserviceaccount.com")
    {
        return (Some("default-account".to_string()), res, chain);
    }
    let scopes_path = format!("{base}.node_config.oauth_scopes");
    let identity = match lookup_attr(body, &["node_config"], "oauth_scopes") {
        AttrLookup::Absent => {
            chain.push(ProvenanceStep::new(rel, &scopes_path, "absent"));
            "dedicated"
        }
        AttrLookup::Found(Value::List(scopes)) => {
            chain.push(ProvenanceStep::new(rel, &scopes_path, "explicit"));
            if scopes
                .iter()
                .any(|s| s == CLOUD_PLATFORM_SCOPE || s == "cloud-platform")
            {
                "cloud-platform-scope"
            } else {
                "dedicated"
            }
        }
        // A scope list never resolves through a variable: one-hop resolution
        // carries scalar literals only.
        _ => return unresolved(chain, rel, &scopes_path, "expression"),
    };
    (Some(identity.to_string()), res, chain)
}

/// How wide a policy's Allow statements reach, narrowest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Wildcard {
    None,
    Resource,
    Action,
    ActionAndResource,
}

impl Wildcard {
    fn as_str(self) -> &'static str {
        match self {
            Wildcard::None => "none",
            Wildcard::Resource => "resource",
            Wildcard::Action => "action",
            Wildcard::ActionAndResource => "action-and-resource",
        }
    }

    /// One statement: every action on every resource; else any action
    /// wildcard (`*` or a whole service, `s3:*`), whatever the resource;
    /// else every resource.
    fn of(actions: &[String], resources: &[String]) -> Wildcard {
        let all_actions = actions.iter().any(|a| a == "*" || a == "*:*");
        let all_resources = resources.iter().any(|r| r == "*");
        if all_actions && all_resources {
            Wildcard::ActionAndResource
        } else if all_actions || actions.iter().any(|a| a.ends_with(":*")) {
            Wildcard::Action
        } else if all_resources {
            Wildcard::Resource
        } else {
            Wildcard::None
        }
    }
}

/// A statement's actions or resources as read: the literal strings, and
/// whether some part needs evaluation (and so might be `*`).
#[derive(Default)]
struct Part {
    known: Vec<String>,
    unknown: bool,
}

impl Part {
    fn unread() -> Part {
        Part {
            known: Vec::new(),
            unknown: true,
        }
    }

    /// The widest the part could evaluate to.
    fn widest(&self) -> Vec<String> {
        let mut all = self.known.clone();
        if self.unknown {
            all.push("*".to_string());
        }
        all
    }
}

/// One policy statement as read; `allow` is `None` when the effect needs
/// evaluation.
struct Statement {
    allow: Option<bool>,
    actions: Part,
    resources: Part,
}

impl Statement {
    fn unread() -> Statement {
        Statement {
            allow: None,
            actions: Part::unread(),
            resources: Part::unread(),
        }
    }
}

/// The widest wildcard among the Allow statements, when the parts that need
/// evaluation cannot change it: the class of what is read must equal the
/// class if every unknown part were `*`. `s3:*` on a referenced bucket is
/// `action` either way; `s3:GetObject` on one is open.
fn widest_wildcard(statements: &[Statement]) -> Option<Wildcard> {
    let (mut least, mut most) = (Wildcard::None, Wildcard::None);
    for s in statements {
        if s.allow == Some(false) {
            continue;
        }
        most = most.max(Wildcard::of(&s.actions.widest(), &s.resources.widest()));
        if s.allow == Some(true) {
            least = least.max(Wildcard::of(&s.actions.known, &s.resources.known));
        }
    }
    (least == most).then_some(least)
}

/// A JSON policy string as a [`Doc`]; a string with a template in it is a
/// part that needs evaluation.
fn json_doc(src: &str) -> Option<Doc> {
    fn conv(v: &serde_json::Value) -> Doc {
        match v {
            serde_json::Value::String(s) if !s.contains("${") && !s.contains("%{") => {
                Doc::Str(s.clone())
            }
            serde_json::Value::Array(items) => Doc::List(items.iter().map(conv).collect()),
            serde_json::Value::Object(m) => {
                Doc::Map(m.iter().map(|(k, v)| (k.clone(), conv(v))).collect())
            }
            _ => Doc::Unknown,
        }
    }
    serde_json::from_str(src).ok().map(|v| conv(&v))
}

/// The statements of a JSON policy document. `Statement` may be one object
/// or a list; `Action` and `Resource` one string or a list. A statement
/// without them (`NotAction`, `NotResource`) is unread, never assumed narrow.
fn json_statements(doc: &Doc) -> Option<Vec<Statement>> {
    fn field<'a>(m: &'a [(String, Doc)], key: &str) -> Option<&'a Doc> {
        m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    fn part(d: Option<&Doc>) -> Part {
        match d {
            Some(Doc::Str(s)) => Part {
                known: vec![s.clone()],
                unknown: false,
            },
            Some(Doc::List(items)) => Part {
                known: items
                    .iter()
                    .filter_map(|i| match i {
                        Doc::Str(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect(),
                unknown: items.iter().any(|i| !matches!(i, Doc::Str(_))),
            },
            _ => Part::unread(),
        }
    }
    let Doc::Map(top) = doc else { return None };
    let statements = match field(top, "Statement")? {
        Doc::List(items) => items.iter().collect(),
        one @ Doc::Map(_) => vec![one],
        _ => return None,
    };
    Some(
        statements
            .into_iter()
            .map(|s| {
                let Doc::Map(s) = s else {
                    return Statement::unread();
                };
                Statement {
                    allow: match field(s, "Effect") {
                        Some(Doc::Str(e)) => Some(e == "Allow"),
                        _ => None,
                    },
                    actions: part(field(s, "Action")),
                    resources: part(field(s, "Resource")),
                }
            })
            .collect(),
    )
}

/// `resource.aws_iam.statement-wildcard` of a resource's `policy`: a
/// `jsonencode({...})` structure, a heredoc, or a string (literal or one
/// variable hop) holding JSON. `file()`, `templatefile()` and other
/// references abstain.
fn policy_wildcard_fact(v: Option<&Value>, rel: &str, key_path: &str, vars: &VarTable) -> Fact {
    let Some(v) = v else {
        return unresolved(Vec::new(), rel, key_path, "absent");
    };
    let explicit = || vec![ProvenanceStep::new(rel, key_path, "explicit")];
    let (doc, res, chain) = match v {
        Value::Json(doc) => (Some(doc.clone()), Resolution::AsAuthored, explicit()),
        Value::Heredoc(body) => (json_doc(body), Resolution::AsAuthored, explicit()),
        other => match resolve_value(rel, key_path, other, vars) {
            (Some(s), res, chain) => (json_doc(&s), res, chain),
            unknown => return unknown,
        },
    };
    match doc
        .as_ref()
        .and_then(json_statements)
        .and_then(|s| widest_wildcard(&s))
    {
        Some(w) => (Some(w.as_str().to_string()), res, chain),
        None => unresolved(chain, rel, key_path, "unreadable"),
    }
}

/// `resource.aws_iam.statement-wildcard` of a `data "aws_iam_policy_document"`
/// block. `effect` defaults to Allow; a statement with no `resources` and no
/// `not_resources` (a trust policy's) names no resource. A `dynamic`
/// statement, or a document merged from others, leaves the answer open.
fn policy_document_fact(body: &[Item], rel: &str, base: &str, vars: &VarTable) -> Fact {
    let key_path = format!("{base}.statement");
    let mut statements: Vec<Statement> = get_blocks(body, "statement")
        .map(|s| Statement {
            allow: match get_attr(&s.body, "effect") {
                None => Some(true),
                Some(v) => resolve_value(rel, &key_path, v, vars)
                    .0
                    .map(|e| e == "Allow"),
            },
            actions: match get_attr(&s.body, "actions") {
                Some(Value::List(items)) => Part {
                    known: items.clone(),
                    unknown: false,
                },
                _ => Part::unread(),
            },
            resources: match (
                get_attr(&s.body, "resources"),
                get_attr(&s.body, "not_resources"),
            ) {
                (Some(Value::List(items)), _) => Part {
                    known: items.clone(),
                    unknown: false,
                },
                (None, None) => Part::default(),
                _ => Part::unread(),
            },
        })
        .collect();
    let merged = [
        "source_policy_documents",
        "override_policy_documents",
        "source_json",
        "override_json",
    ]
    .iter()
    .any(|a| get_attr(body, a).is_some());
    if merged
        || get_blocks(body, "dynamic").any(|d| d.labels.first().is_some_and(|l| l == "statement"))
    {
        statements.push(Statement::unread());
    }
    match widest_wildcard(&statements) {
        Some(w) => (
            Some(w.as_str().to_string()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(rel, &key_path, "explicit")],
        ),
        None => unresolved(Vec::new(), rel, &key_path, "unreadable"),
    }
}

/// What [`retrieve_dir`] learned about one module directory that only the
/// whole claim can turn into a module kind.
struct ModuleFacts {
    dir: String,
    /// The file module-level packets anchor to.
    anchor: String,
    /// The first sign this directory is applied directly: (file, key path).
    root_signal: Option<(String, String)>,
    /// The `terraform.backend` fact, re-emitted as `terraform.root-backend`
    /// when the module turns out to be a root.
    backend: ConfigPacket,
    /// Local module calls made from here: (file, key path, target directory).
    local_calls: Vec<(String, String, String)>,
}

/// Emit `terraform.module-kind` for every module, and `terraform.root-backend`
/// for the roots (RC-016).
///
/// `terraform.backend = local` is a finding only where state is actually
/// kept, and a reusable module legitimately declares no backend. So:
///
///   * called through a local `source` from another directory → `reusable`.
///     This outranks every root signal: a legacy child module that configures
///     its own provider is still a child.
///   * otherwise a backend/cloud block, a provider configuration block, or an
///     auto-loaded tfvars file → `root`. Terraform's own guidance is that a
///     shared module declares no provider configuration.
///   * neither → `indeterminate`, and NO root-backend packet: abstaining
///     beats flagging a published module for lacking a backend.
///
/// Returns the directories of the reusable modules.
fn emit_module_kinds<'a>(
    modules: &'a [ModuleFacts],
    snapshot_id: &str,
    out: &mut Retrieved,
) -> Vec<&'a str> {
    let mut reusable = Vec::new();
    // Target directory → the first call that names it from ANOTHER directory.
    let mut callers: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
    for m in modules {
        for (file, key_path, target) in &m.local_calls {
            if *target != m.dir {
                callers.entry(target).or_insert((file, key_path));
            }
        }
    }
    for m in modules {
        let (kind, step) = match (callers.get(m.dir.as_str()), &m.root_signal) {
            (Some((file, key_path)), _) => {
                ("reusable", ProvenanceStep::new(file, key_path, "explicit"))
            }
            (None, Some((file, key_path))) => {
                ("root", ProvenanceStep::new(file, key_path, "explicit"))
            }
            (None, None) => (
                "indeterminate",
                ProvenanceStep::new(&m.anchor, "provider / backend / tfvars", "absent"),
            ),
        };
        out.packets.push(ConfigPacket {
            snapshot_id: snapshot_id.to_string(),
            format: "terraform".to_string(),
            file_path: m.anchor.clone(),
            line: 0,
            unit: "module".to_string(),
            key: crate::key_ledger::declared("terraform", "terraform.module-kind"),
            resolved_value: Some(kind.to_string()),
            resolution: Resolution::AsAuthored,
            provenance: vec![step],
        });
        if kind == "root" {
            out.packets.push(ConfigPacket {
                key: crate::key_ledger::declared("terraform", "terraform.root-backend"),
                ..m.backend.clone()
            });
        }
        if kind == "reusable" {
            reusable.push(m.dir.as_str());
        }
    }
    reusable
}

/// Retrieve one module directory: `group` is path-sorted (rel, contents).
/// Returns the facts the module-kind pass needs, or `None` when the directory
/// is not a module.
fn retrieve_dir(
    dir: &str,
    group: &[&(String, String)],
    snapshot_id: &str,
    out: &mut Retrieved,
) -> Option<ModuleFacts> {
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
    let mut tfvars_signal: Option<(String, String)> = None;
    for (rel, contents) in tfvars_files {
        match parse_file(contents) {
            Ok(items) => {
                // Auto-loaded values apply only to the module terraform is
                // run in, so their presence marks a root.
                tfvars_signal.get_or_insert_with(|| (rel.clone(), "tfvars".to_string()));
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
        return None; // a directory of only tfvars is not a module
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
        key: crate::key_ledger::declared("terraform", key),
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
    let mut root_signal: Option<(String, String)> = None;
    let backend_packet = match backend {
        Some((rel, ty, is_backend)) => {
            let key_path = if is_backend {
                format!("terraform.backend.{ty}")
            } else {
                "terraform.cloud".to_string()
            };
            root_signal = Some((rel.to_string(), key_path.clone()));
            packet(
                rel,
                "module",
                "terraform.backend",
                Some(ty),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(rel, &key_path, "explicit")],
            )
        }
        None => packet(
            anchor,
            "module",
            "terraform.backend",
            Some("local".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(anchor, "terraform.backend", "absent"),
                ProvenanceStep::new("", "backend", "platform-default"),
            ],
        ),
    };
    out.packets.push(backend_packet.clone());

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
            // A provider CONFIGURATION block: what a root module carries
            // and a shared module is documented not to.
            root_signal.get_or_insert_with(|| (rel.to_string(), format!("provider.{name}")));
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

    let root_signal = root_signal.or(tfvars_signal);
    let mut local_calls: Vec<(String, String, String)> = Vec::new();

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
                // directory is walked like any other); the call is recorded
                // because it is what makes the target a reusable module.
                "local" => {
                    if let Some(target) = local_module_dir(dir, &source) {
                        local_calls.push((rel.to_string(), source_path.clone(), target));
                    }
                }
                // Other sources carry no pin identity this subset can vouch
                // for.
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

            // The resource-attribute lane: only the rows of RESOURCE_ATTRS.
            let replica = ty == "google_sql_database_instance"
                && get_attr(&b.body, "master_instance_name").is_some();
            for row in RESOURCE_ATTRS.iter().filter(|r| r.resource_type == ty) {
                if row
                    .unless_attr
                    .is_some_and(|a| get_attr(&b.body, a).is_some())
                {
                    continue;
                }
                let key_path = std::iter::once(format!("resource.{ty}.{name}"))
                    .chain(row.blocks.iter().map(|s| s.to_string()))
                    .chain(std::iter::once(row.attr.to_string()))
                    .collect::<Vec<_>>()
                    .join(".");
                let found = lookup_attr(&b.body, row.blocks, row.attr);
                let (value, resolution, prov) = resolve_row(row, rel, &key_path, found, &vars);
                let mut p = packet(rel, &unit, row.packet_key, value, resolution, prov);
                if replica && REPLICA_UNDECIDED.contains(&row.packet_key) {
                    crate::non_production::undecide(&mut p, "read replica");
                }
                out.packets.push(p);
            }

            if let Some((key, (value, resolution, prov))) =
                least_privilege_fact(ty, name, &b.body, rel, &vars)
            {
                out.packets
                    .push(packet(rel, &unit, key, value, resolution, prov));
            }
        }
    }

    // The policy-document data source is where most IAM policies are
    // written; its JSON is what an aws_iam_* `policy` then references.
    for (rel, items) in &parsed_tf {
        for b in get_blocks(items, "data") {
            let (Some(ty), Some(name)) = (b.labels.first(), b.labels.get(1)) else {
                continue;
            };
            if ty != "aws_iam_policy_document" {
                continue;
            }
            let (value, resolution, prov) =
                policy_document_fact(&b.body, rel, &format!("data.{ty}.{name}"), &vars);
            out.packets.push(packet(
                rel,
                &format!("data:{ty}.{name}"),
                "resource.aws_iam.statement-wildcard",
                value,
                resolution,
                prov,
            ));
        }
    }

    Some(ModuleFacts {
        dir: dir.to_string(),
        anchor: anchor.to_string(),
        root_signal,
        backend: backend_packet,
        local_calls,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(files: &[(&str, &str)]) -> Retrieved {
        let files: Vec<(String, String)> = files
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        Terraform.retrieve_all(std::path::Path::new(""), &files, "snap")
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

    // --- the resource-attribute lane (po-pk3fp.13) ---

    #[test]
    fn rds_backup_retention_is_authored_or_the_documented_default() {
        let got = one(&[(
            "db.tf",
            "resource \"aws_db_instance\" \"main\" {\n  backup_retention_period = 7\n}\n\
             resource \"aws_db_instance\" \"bare\" {\n  engine = \"postgres\"\n}\n\
             resource \"aws_rds_cluster\" \"aurora\" {}\n",
        )]);
        let key = "resource.aws_db_instance.backup_retention_period";
        let set = find(&got, "resource:aws_db_instance.main", key);
        assert_eq!(set.resolved_value.as_deref(), Some("7"));
        assert_eq!(set.resolution, Resolution::AsAuthored);
        assert_eq!(
            set.provenance[0].key_path,
            "resource.aws_db_instance.main.backup_retention_period"
        );
        let bare = find(&got, "resource:aws_db_instance.bare", key);
        assert_eq!(
            bare.resolved_value.as_deref(),
            Some("0"),
            "the provider documents 0: no automated backups"
        );
        assert_eq!(bare.resolution, Resolution::PlatformDefault);
        assert_eq!(bare.provenance.last().unwrap().role, "platform-default");
        let aurora = find(
            &got,
            "resource:aws_rds_cluster.aurora",
            "resource.aws_rds_cluster.backup_retention_period",
        );
        assert_eq!(aurora.resolved_value.as_deref(), Some("1"));
        assert_eq!(aurora.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn a_resource_attribute_resolves_one_hop_through_a_variable() {
        let got = one(&[
            (
                "db.tf",
                "resource \"aws_db_instance\" \"main\" {\n  backup_retention_period = var.retention\n}\n",
            ),
            (
                "variables.tf",
                "variable \"retention\" {\n  default = 14\n}\n",
            ),
        ]);
        let p = find(
            &got,
            "resource:aws_db_instance.main",
            "resource.aws_db_instance.backup_retention_period",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("14"));
        assert_eq!(p.provenance.last().unwrap().role, "default");
    }

    #[test]
    fn a_read_replica_emits_no_backup_retention_packet() {
        // A replica's own retention is not the backup posture of the data:
        // the source instance carries it. Emitting the documented 0 here
        // would flag every replica.
        let got = one(&[(
            "db.tf",
            "resource \"aws_db_instance\" \"replica\" {\n  replicate_source_db = aws_db_instance.main.identifier\n}\n",
        )]);
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key == "resource.aws_db_instance.backup_retention_period"),
            "{:#?}",
            got.packets
        );
    }

    #[test]
    fn a_module_under_a_non_production_path_carries_its_facts_undecided() {
        let got = one(&[(
            "course/infra/labs/gcp/02-wordpress/main.tf",
            "provider \"google\" {}\nresource \"google_sql_database_instance\" \"db\" {\n  settings {\n    tier = \"db-f1-micro\"\n  }\n}\n",
        )]);
        let enabled = find(
            &got,
            "resource:google_sql_database_instance.db",
            "resource.google_sql_database_instance.backup_configuration.enabled",
        );
        assert_eq!(
            enabled.resolved_value.as_deref(),
            Some("undecided: non-production path: course")
        );
        for p in got
            .packets
            .iter()
            .filter(|p| p.key != "terraform.module-kind")
        {
            let v = p.resolved_value.as_deref().unwrap_or("undecided: ");
            assert!(v.starts_with("undecided: "), "{}: {v}", p.key);
        }
        // What the module IS stays a fact.
        assert_eq!(
            module_kind(&got, "course/infra/labs/gcp/02-wordpress/main.tf"),
            "root"
        );
        let got = one(&[(
            "infra/staging/db.tf",
            "resource \"aws_db_instance\" \"db\" {}\n",
        )]);
        let p = find(
            &got,
            "resource:aws_db_instance.db",
            "resource.aws_db_instance.backup_retention_period",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("0"));
    }

    #[test]
    fn a_cloud_sql_read_replica_carries_backup_and_availability_undecided() {
        let got = one(&[(
            "db.tf",
            "resource \"google_sql_database_instance\" \"replica\" {\n  master_instance_name = google_sql_database_instance.main.name\n  settings {\n    tier = \"db-custom-2-7680\"\n  }\n}\n",
        )]);
        for key in [
            "resource.google_sql_database_instance.backup_configuration.enabled",
            "resource.google_sql_database_instance.backup_configuration.point_in_time_recovery_enabled",
            "resource.google_sql_database_instance.settings.availability_type",
        ] {
            let p = find(&got, "resource:google_sql_database_instance.replica", key);
            assert_eq!(p.resolved_value.as_deref(), Some("undecided: read replica"), "{key}");
        }
        // The primary is still judged.
        let got = one(&[(
            "db.tf",
            "resource \"google_sql_database_instance\" \"main\" {\n  settings {\n    tier = \"db-custom-2-7680\"\n  }\n}\n",
        )]);
        let p = find(
            &got,
            "resource:google_sql_database_instance.main",
            "resource.google_sql_database_instance.settings.availability_type",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("ZONAL"));
    }

    #[test]
    fn a_reusable_module_leaves_to_its_caller_what_it_does_not_author() {
        const REUSABLE: &str = "undecided: reusable module: the caller sets this";
        let got = one(&[
            (
                "envs/prod/main.tf",
                "provider \"aws\" {}\nmodule \"db\" {\n  source = \"../../modules/postgresql\"\n}\n",
            ),
            (
                "modules/postgresql/main.tf",
                "variable \"multi_az\" {\n  default = false\n}\nresource \"aws_db_instance\" \"db\" {\n  multi_az = var.multi_az\n  backup_retention_period = 7\n}\n",
            ),
        ]);
        assert_eq!(module_kind(&got, "modules/postgresql/main.tf"), "reusable");
        let value = |key: &str| {
            find(&got, "resource:aws_db_instance.db", key)
                .resolved_value
                .clone()
                .unwrap_or_default()
        };
        // From a variable: the caller sets it.
        assert_eq!(value("resource.aws_db_instance.multi_az"), REUSABLE);
        // A literal the module authors stays a fact.
        assert_eq!(
            value("resource.aws_db_instance.backup_retention_period"),
            "7"
        );
        // No caller can set a lifecycle, so its default stays a fact.
        assert_eq!(value("resource.lifecycle.prevent_destroy"), "false");

        // Unset, in a module the caller configures.
        let got = one(&[
            (
                "main.tf",
                "provider \"google\" {}\nmodule \"sql\" {\n  source = \"./modules/cloudsql-instance\"\n}\n",
            ),
            (
                "modules/cloudsql-instance/main.tf",
                "resource \"google_sql_database_instance\" \"db\" {\n  settings {\n    tier = \"db-f1-micro\"\n  }\n}\n",
            ),
        ]);
        let p = find(
            &got,
            "resource:google_sql_database_instance.db",
            "resource.google_sql_database_instance.backup_configuration.enabled",
        );
        assert_eq!(p.resolved_value.as_deref(), Some(REUSABLE));
    }

    #[test]
    fn cloud_sql_backup_facts_read_through_nested_blocks() {
        let enabled = "resource.google_sql_database_instance.backup_configuration.enabled";
        let pitr = "resource.google_sql_database_instance.backup_configuration.point_in_time_recovery_enabled";
        let got = one(&[(
            "sql.tf",
            "resource \"google_sql_database_instance\" \"main\" {\n  settings {\n    tier = \"db-f1-micro\"\n    backup_configuration {\n      enabled = true\n    }\n  }\n}\n\
             resource \"google_sql_database_instance\" \"bare\" {\n  settings {\n    tier = \"db-f1-micro\"\n  }\n}\n",
        )]);
        let unit = "resource:google_sql_database_instance.main";
        let e = find(&got, unit, enabled);
        assert_eq!(e.resolved_value.as_deref(), Some("true"));
        assert_eq!(e.resolution, Resolution::AsAuthored);
        assert_eq!(
            e.provenance[0].key_path,
            "resource.google_sql_database_instance.main.settings.backup_configuration.enabled"
        );
        let p = find(&got, unit, pitr);
        assert_eq!(p.resolved_value.as_deref(), Some("false"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        let bare = find(&got, "resource:google_sql_database_instance.bare", enabled);
        assert_eq!(bare.resolved_value.as_deref(), Some("false"));
        assert_eq!(bare.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn a_dynamic_block_on_the_path_is_unresolvable_never_the_default() {
        // `dynamic "backup_configuration"` may or may not render the block;
        // answering with the documented default would be a guess.
        let got = one(&[(
            "sql.tf",
            "resource \"google_sql_database_instance\" \"main\" {\n  settings {\n    dynamic \"backup_configuration\" {\n      for_each = var.backups\n      content {\n        enabled = true\n      }\n    }\n  }\n}\n",
        )]);
        let p = find(
            &got,
            "resource:google_sql_database_instance.main",
            "resource.google_sql_database_instance.backup_configuration.enabled",
        );
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.provenance.last().unwrap().role, "expression");
    }

    #[test]
    fn resources_outside_the_attribute_table_emit_no_attribute_packets() {
        let got = one(&[(
            "main.tf",
            "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"logs\"\n}\n",
        )]);
        let keys: Vec<&str> = got
            .packets
            .iter()
            .filter(|p| p.unit == "resource:aws_s3_bucket.logs")
            .map(|p| p.key.as_str())
            .collect();
        assert_eq!(keys, vec!["resource.lifecycle.prevent_destroy"]);
    }

    // --- the zone-spread facts (RC-017) ---

    /// The zone-spread fixture module, read as one directory.
    fn zone_spread() -> Retrieved {
        let got = one(&[
            (
                "rds.tf",
                include_str!("../testdata/terraform/zone_spread/rds.tf"),
            ),
            (
                "cloud_sql.tf",
                include_str!("../testdata/terraform/zone_spread/cloud_sql.tf"),
            ),
            (
                "gke.tf",
                include_str!("../testdata/terraform/zone_spread/gke.tf"),
            ),
            (
                "variables.tf",
                include_str!("../testdata/terraform/zone_spread/variables.tf"),
            ),
        ]);
        assert_eq!(got.unparseable, 0, "the fixture module must parse");
        got
    }

    /// (value, resolution, last provenance role) of one packet.
    fn fact(got: &Retrieved, unit: &str, key: &str) -> (Option<String>, Resolution, String) {
        let p = find(got, unit, key);
        (
            p.resolved_value.clone(),
            p.resolution,
            p.provenance.last().unwrap().role.clone(),
        )
    }

    fn some(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn rds_multi_az_is_authored_defaulted_or_unresolved() {
        let got = zone_spread();
        let key = "resource.aws_db_instance.multi_az";
        let at = |name: &str| fact(&got, &format!("resource:aws_db_instance.{name}"), key);
        assert_eq!(
            at("spread"),
            (some("true"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("single"),
            (some("false"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("bare"),
            (
                some("false"),
                Resolution::PlatformDefault,
                "platform-default".into()
            ),
            "the provider documents false: a single-AZ instance"
        );
        assert_eq!(
            at("from_var"),
            (None, Resolution::Unresolvable, "project-setting".into())
        );
        assert_eq!(
            at("from_expr"),
            (None, Resolution::Unresolvable, "expression".into())
        );
    }

    #[test]
    fn cloud_sql_availability_type_is_authored_defaulted_or_unresolved() {
        let got = zone_spread();
        let key = "resource.google_sql_database_instance.settings.availability_type";
        let at = |name: &str| {
            fact(
                &got,
                &format!("resource:google_sql_database_instance.{name}"),
                key,
            )
        };
        assert_eq!(
            at("regional"),
            (some("REGIONAL"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("zonal"),
            (some("ZONAL"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("bare"),
            (
                some("ZONAL"),
                Resolution::PlatformDefault,
                "platform-default".into()
            ),
            "the provider documents ZONAL"
        );
        assert_eq!(
            at("from_var"),
            (None, Resolution::Unresolvable, "project-setting".into())
        );
        assert_eq!(
            at("from_expr"),
            (None, Resolution::Unresolvable, "expression".into())
        );
        assert_eq!(
            find(&got, "resource:google_sql_database_instance.regional", key).provenance[0]
                .key_path,
            "resource.google_sql_database_instance.regional.settings.availability_type"
        );
    }

    #[test]
    fn gke_cluster_location_shape_is_region_or_zone_or_unresolved() {
        let got = zone_spread();
        let key = "resource.google_container_cluster.location-shape";
        let at = |name: &str| {
            fact(
                &got,
                &format!("resource:google_container_cluster.{name}"),
                key,
            )
        };
        assert_eq!(
            at("regional"),
            (some("region"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("zonal"),
            (some("zone"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("bare"),
            (None, Resolution::Unresolvable, "provider-setting".into()),
            "an absent location is the provider block's, never a default"
        );
        assert_eq!(
            at("from_var"),
            (None, Resolution::Unresolvable, "project-setting".into())
        );
        assert_eq!(
            at("from_expr"),
            (None, Resolution::Unresolvable, "expression".into())
        );
    }

    #[test]
    fn gke_location_names_classify_by_their_documented_shape() {
        for (loc, want) in [
            ("us-central1", Some("region")),
            ("northamerica-northeast2", Some("region")),
            ("us-central1-f", Some("zone")),
            ("europe-west4-b", Some("zone")),
            ("us", None),
            ("us-central", None),
            ("us-central1-ab", None),
            ("US-CENTRAL1", None),
            ("", None),
        ] {
            assert_eq!(location_shape(loc), want, "{loc}");
        }
        let got = one(&[(
            "gke.tf",
            "resource \"google_container_cluster\" \"odd\" {\n  location = \"us\"\n}\n",
        )]);
        assert_eq!(
            fact(
                &got,
                "resource:google_container_cluster.odd",
                "resource.google_container_cluster.location-shape"
            ),
            (None, Resolution::Unresolvable, "unrecognized".into())
        );
    }

    #[test]
    fn gke_node_pool_node_locations_count_is_a_literal_list_length_or_unresolved() {
        let got = zone_spread();
        let key = "resource.google_container_node_pool.node_locations-count";
        let at = |name: &str| {
            fact(
                &got,
                &format!("resource:google_container_node_pool.{name}"),
                key,
            )
        };
        assert_eq!(
            at("three_zones"),
            (some("3"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("one_zone"),
            (some("1"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("bare"),
            (None, Resolution::Unresolvable, "inherited".into()),
            "an absent list inherits the cluster's zones, never a default"
        );
        assert_eq!(
            at("from_var"),
            (None, Resolution::Unresolvable, "non-literal".into()),
            "a list default is not a one-hop literal"
        );
        assert_eq!(
            at("from_expr"),
            (None, Resolution::Unresolvable, "expression".into())
        );
        assert_eq!(
            at("mixed"),
            (None, Resolution::Unresolvable, "expression".into()),
            "one non-literal item makes the whole count a guess"
        );
    }

    #[test]
    fn an_empty_node_locations_list_is_unset_not_zero() {
        let got = one(&[(
            "gke.tf",
            "resource \"google_container_node_pool\" \"p\" {\n  node_locations = []\n}\n",
        )]);
        assert_eq!(
            fact(
                &got,
                "resource:google_container_node_pool.p",
                "resource.google_container_node_pool.node_locations-count"
            ),
            (None, Resolution::Unresolvable, "empty".into())
        );
    }

    // --- least privilege (RC-044) ---

    /// The least-privilege fixture module, read as one directory.
    fn least_privilege() -> Retrieved {
        let got = one(&[
            (
                "keys.tf",
                include_str!("../testdata/terraform/least_privilege/keys.tf"),
            ),
            (
                "iam.tf",
                include_str!("../testdata/terraform/least_privilege/iam.tf"),
            ),
            (
                "policies.tf",
                include_str!("../testdata/terraform/least_privilege/policies.tf"),
            ),
            (
                "nodes.tf",
                include_str!("../testdata/terraform/least_privilege/nodes.tf"),
            ),
            (
                "variables.tf",
                include_str!("../testdata/terraform/least_privilege/variables.tf"),
            ),
        ]);
        assert_eq!(got.unparseable, 0, "the fixture module must parse");
        got
    }

    #[test]
    fn a_google_service_account_key_is_declared_unless_count_says_otherwise() {
        let got = least_privilege();
        let key = "resource.google_service_account_key.declared";
        let at = |name: &str| {
            fact(
                &got,
                &format!("resource:google_service_account_key.{name}"),
                key,
            )
        };
        assert_eq!(
            at("ci"),
            (some("true"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("none"),
            (some("false"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("maybe"),
            (None, Resolution::Unresolvable, "expression".into()),
            "a conditional count may be zero"
        );
    }

    #[test]
    fn an_aws_access_key_is_declared_unless_for_each_says_otherwise() {
        let got = least_privilege();
        let key = "resource.aws_iam_access_key.declared";
        let at = |name: &str| fact(&got, &format!("resource:aws_iam_access_key.{name}"), key);
        assert_eq!(
            at("deploy"),
            (some("true"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("none"),
            (some("false"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("per_user"),
            (None, Resolution::Unresolvable, "expression".into())
        );
    }

    #[test]
    fn a_gcp_role_grant_is_classed_or_unresolved() {
        let got = least_privilege();
        let key = "resource.google_iam.role-class";
        let at = |unit: &str| fact(&got, &format!("resource:{unit}"), key);
        assert_eq!(
            at("google_project_iam_member.owner"),
            (some("primitive"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("google_folder_iam_binding.editor"),
            (some("primitive"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("google_organization_iam_member.viewer"),
            (some("viewer"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("google_project_iam_member.custom"),
            (some("custom"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("google_project_iam_binding.predefined"),
            (some("predefined"), Resolution::AsAuthored, "default".into()),
            "one variable hop to a literal default"
        );
        assert_eq!(
            at("google_project_iam_member.from_each"),
            (None, Resolution::Unresolvable, "expression".into())
        );
        for (role, want) in [
            ("roles/storage.admin", Some("predefined")),
            ("organizations/1/roles/x", Some("custom")),
            ("roles/", None),
            ("owner", None),
        ] {
            assert_eq!(role_class(role), want, "{role}");
        }
    }

    #[test]
    fn an_aws_policy_wildcard_is_read_from_jsonencode_heredoc_and_documents() {
        let got = least_privilege();
        let key = "resource.aws_iam.statement-wildcard";
        let at = |unit: &str| fact(&got, unit, key);
        assert_eq!(
            at("resource:aws_iam_policy.admin"),
            (
                some("action-and-resource"),
                Resolution::AsAuthored,
                "explicit".into()
            )
        );
        assert_eq!(
            at("resource:aws_iam_role_policy.s3_all"),
            (some("action"), Resolution::AsAuthored, "explicit".into()),
            "a whole-service action is `action` whatever the referenced resource is"
        );
        assert_eq!(
            at("resource:aws_iam_user_policy.describe"),
            (some("resource"), Resolution::AsAuthored, "explicit".into()),
            "a heredoc is read, and a Deny statement grants nothing"
        );
        assert_eq!(
            at("resource:aws_iam_group_policy.scoped"),
            (some("none"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("resource:aws_iam_policy.from_file"),
            (None, Resolution::Unresolvable, "expression".into())
        );
        assert_eq!(
            at("resource:aws_iam_policy.from_doc"),
            (None, Resolution::Unresolvable, "expression".into()),
            "the referenced document carries its own packet"
        );
        assert_eq!(
            at("resource:aws_iam_role_policy.templated"),
            (None, Resolution::Unresolvable, "unreadable".into()),
            "variable actions on every resource could be anything"
        );
        assert_eq!(
            at("data:aws_iam_policy_document.wide"),
            (
                some("action-and-resource"),
                Resolution::AsAuthored,
                "explicit".into()
            ),
            "effect defaults to Allow"
        );
        assert_eq!(
            at("data:aws_iam_policy_document.scoped"),
            (some("none"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("data:aws_iam_policy_document.assume"),
            (some("none"), Resolution::AsAuthored, "explicit".into()),
            "a statement with no resources names none"
        );
        assert_eq!(
            at("data:aws_iam_policy_document.dynamic"),
            (None, Resolution::Unresolvable, "unreadable".into())
        );
    }

    #[test]
    fn a_policy_string_with_unknown_parts_decides_only_when_they_cannot_matter() {
        let wild = |json: &str| {
            json_doc(json)
                .as_ref()
                .and_then(json_statements)
                .and_then(|s| widest_wildcard(&s))
        };
        let st = |body: &str| format!(r#"{{"Statement": [{body}]}}"#);
        assert_eq!(
            wild(&st(
                r#"{"Effect": "Allow", "Action": "*", "Resource": "${var.arn}"}"#
            )),
            None,
            "the template might be `*`"
        );
        assert_eq!(
            wild(&st(
                r#"{"Effect": "Allow", "Action": "*", "Resource": "*"}, {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}"#
            )),
            Some(Wildcard::ActionAndResource),
            "an unread statement cannot outrank the widest class"
        );
        assert_eq!(
            wild(&st(
                r#"{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}"#
            )),
            None,
            "NotAction is never assumed narrow"
        );
        assert_eq!(
            wild(r#"{"Statement": {"Effect": "Allow", "Action": "*:*", "Resource": "*"}}"#),
            Some(Wildcard::ActionAndResource),
            "Statement may be one object"
        );
        assert_eq!(wild("not json"), None);
    }

    #[test]
    fn gke_node_identity_is_default_scoped_dedicated_or_unresolved() {
        let got = least_privilege();
        let key = "resource.google_container_node_pool.node-identity";
        let at = |unit: &str| fact(&got, &format!("resource:{unit}"), key);
        assert_eq!(
            at("google_container_node_pool.bare"),
            (
                some("default-account"),
                Resolution::PlatformDefault,
                "platform-default".into()
            ),
            "no service_account is the Compute Engine default account"
        );
        assert_eq!(
            at("google_container_node_pool.compute_default"),
            (
                some("default-account"),
                Resolution::AsAuthored,
                "explicit".into()
            )
        );
        assert_eq!(
            at("google_container_node_pool.broad_scope"),
            (
                some("cloud-platform-scope"),
                Resolution::AsAuthored,
                "explicit".into()
            )
        );
        assert_eq!(
            at("google_container_node_pool.dedicated"),
            (some("dedicated"), Resolution::AsAuthored, "explicit".into())
        );
        assert_eq!(
            at("google_container_node_pool.from_ref"),
            (None, Resolution::Unresolvable, "expression".into()),
            "a referenced account might be the default one"
        );
        assert_eq!(
            at("google_container_cluster.inline"),
            (
                some("default-account"),
                Resolution::PlatformDefault,
                "platform-default".into()
            )
        );
        assert!(
            !got.packets
                .iter()
                .any(|p| p.key == key && p.unit == "resource:google_container_cluster.pools_only"),
            "a cluster without an inline node_config describes no nodes"
        );
    }

    #[test]
    fn jsonencode_and_heredocs_do_not_derail_the_attributes_after_them() {
        let got = one(&[(
            "main.tf",
            "resource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode(merge(local.a, {\n    x = [1, 2]\n  }))\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n\
             resource \"aws_iam_policy\" \"q\" {\n  policy = <<EOF\n{\"Statement\": []}\nEOF\n  lifecycle {\n    prevent_destroy = true\n  }\n}\n",
        )]);
        assert_eq!(got.unparseable, 0);
        for unit in ["resource:aws_iam_policy.p", "resource:aws_iam_policy.q"] {
            assert_eq!(
                find(&got, unit, "resource.lifecycle.prevent_destroy").resolved_value,
                some("true"),
                "{unit}"
            );
        }
        assert_eq!(
            fact(
                &got,
                "resource:aws_iam_policy.q",
                "resource.aws_iam.statement-wildcard"
            ),
            (some("none"), Resolution::AsAuthored, "explicit".into())
        );
    }

    // --- root vs reusable modules (po-pk3fp.13, RC-016) ---

    fn module_kind(got: &Retrieved, file: &str) -> String {
        got.packets
            .iter()
            .find(|p| p.key == "terraform.module-kind" && p.file_path == file)
            .unwrap_or_else(|| panic!("no module-kind anchored at {file} in {:#?}", got.packets))
            .resolved_value
            .clone()
            .unwrap()
    }

    fn root_backend<'a>(got: &'a Retrieved, file: &str) -> Option<&'a ConfigPacket> {
        got.packets
            .iter()
            .find(|p| p.key == "terraform.root-backend" && p.file_path == file)
    }

    #[test]
    fn a_provider_block_marks_a_root_module_and_its_missing_backend_is_judgeable() {
        let got = one(&[(
            "envs/prod/main.tf",
            "provider \"aws\" {\n  region = \"us-east-1\"\n}\nresource \"a\" \"b\" {}\n",
        )]);
        assert_eq!(module_kind(&got, "envs/prod/main.tf"), "root");
        let be = root_backend(&got, "envs/prod/main.tf").expect("a root module emits root-backend");
        assert_eq!(be.resolved_value.as_deref(), Some("local"));
        assert_eq!(be.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn a_backend_block_or_an_auto_loaded_tfvars_file_marks_a_root_module() {
        let backend = one(&[(
            "versions.tf",
            "terraform {\n  backend \"gcs\" {\n    bucket = \"state\"\n  }\n}\n",
        )]);
        assert_eq!(module_kind(&backend, "versions.tf"), "root");
        let be = root_backend(&backend, "versions.tf").unwrap();
        assert_eq!(be.resolved_value.as_deref(), Some("gcs"));
        assert_eq!(be.resolution, Resolution::AsAuthored);

        let tfvars = one(&[
            ("stack/main.tf", "resource \"a\" \"b\" {}\n"),
            ("stack/terraform.tfvars", "region = \"us-east-1\"\n"),
        ]);
        assert_eq!(module_kind(&tfvars, "stack/main.tf"), "root");
        assert!(root_backend(&tfvars, "stack/main.tf").is_some());
    }

    #[test]
    fn a_locally_called_module_is_reusable_and_emits_no_root_backend() {
        // The migration-257 abstention: a reusable module legitimately has no
        // backend, so `terraform.backend = local` there is not a finding.
        let got = one(&[
            (
                "examples/basic/main.tf",
                "provider \"aws\" {}\nmodule \"vpc\" {\n  source = \"../..\"\n}\n",
            ),
            ("main.tf", "resource \"aws_vpc\" \"this\" {}\n"),
            (
                "modules/subnet/main.tf",
                "provider \"aws\" {}\nresource \"aws_subnet\" \"this\" {}\n",
            ),
            (
                "outputs.tf",
                "module \"subnet\" {\n  source = \"./modules/subnet\"\n}\n",
            ),
        ]);
        assert_eq!(module_kind(&got, "main.tf"), "reusable");
        assert!(root_backend(&got, "main.tf").is_none());
        // Being called outranks a provider block: a legacy child module that
        // configures its own provider is still a child.
        assert_eq!(module_kind(&got, "modules/subnet/main.tf"), "reusable");
        assert!(root_backend(&got, "modules/subnet/main.tf").is_none());
        assert_eq!(module_kind(&got, "examples/basic/main.tf"), "root");
        // terraform.backend itself is unchanged for every module.
        assert_eq!(
            got.packets
                .iter()
                .filter(|p| p.key == "terraform.backend")
                .count(),
            3
        );
    }

    #[test]
    fn a_module_with_no_signal_either_way_is_indeterminate() {
        let got = one(&[("main.tf", "resource \"a\" \"b\" {}\n")]);
        assert_eq!(module_kind(&got, "main.tf"), "indeterminate");
        assert!(
            root_backend(&got, "main.tf").is_none(),
            "no root signal, no root-backend: abstaining beats flagging a reusable module"
        );
    }

    #[test]
    fn local_module_paths_normalize_against_the_calling_directory() {
        assert_eq!(
            local_module_dir("envs/prod", "../../modules/vpc"),
            Some("modules/vpc".into())
        );
        assert_eq!(
            local_module_dir("", "./modules/vpc"),
            Some("modules/vpc".into())
        );
        assert_eq!(
            local_module_dir("examples/basic", "../.."),
            Some(String::new())
        );
        assert_eq!(local_module_dir("a", "./b//sub"), Some("a/b/sub".into()));
        assert_eq!(local_module_dir("", "../outside"), None, "escapes the repo");
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
            ("envs/staging/main.tf", "resource \"a\" \"b\" {}\n"),
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
        // staging is its own module with its own defaults.
        let dev_backend = got
            .packets
            .iter()
            .find(|p| p.file_path == "envs/staging/main.tf" && p.key == "terraform.backend")
            .expect("staging backend packet");
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
