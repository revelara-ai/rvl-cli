//! `rvl scan digest <engine-doc>`: the residual-scoping digest of an engine
//! scan document (`rvl scan --out`).
//!
//! The scan skill reads this text, not the JSON, to scope its lens pass: what
//! the engine settled (`ENGINE_DIGEST`, `COVERED_CLASSES`), what it looked at
//! and abstained on (`UNDECIDED`), and the capped slice of those sites that
//! the lenses adjudicate (`ADJUDICATION_LIST`). The lines are a contract with
//! the skill, so they are the ones its Python script printed, down to the
//! Python rendering of a map (`{'runtime': 3}`).

use anyhow::{anyhow, bail, Context, Result};
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;
use std::fmt::Write as _;
use std::io::Write;
use std::path::Path;

/// The one scan-document schema these commands read.
pub const SCHEMA: &str = "rvl-scan/v1";

/// The adjudication list holds this many sites at most, across the whole scan.
const ADJUDICATION_CAP: usize = 20;

pub(crate) fn read_json(path: &Path) -> Result<Value> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

/// A scan document of another schema is refused, never guessed at: a field
/// that moved or changed meaning would be read as if it had not.
pub(crate) fn check_schema(doc: &Value, path: &Path) -> Result<()> {
    match doc.get("schema") {
        Some(Value::String(s)) if s == SCHEMA => Ok(()),
        other => bail!(
            "{}: unexpected schema {}; this command reads {SCHEMA} and does not guess at another",
            path.display(),
            other.map_or_else(|| "(none)".to_string(), py_str)
        ),
    }
}

/// `v[key]`, or an error that names the field and where it was expected.
pub(crate) fn field<'a>(v: &'a Value, key: &str, what: &str) -> Result<&'a Value> {
    v.get(key).ok_or_else(|| anyhow!("{what} has no \"{key}\""))
}

pub(crate) fn list<'a>(v: &'a Value, key: &str, what: &str) -> Result<&'a [Value]> {
    field(v, key, what)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| anyhow!("\"{key}\" of {what} is not an array"))
}

/// Python's truth value of a JSON value: `x or default` in the reference
/// scripts falls through on null, false, zero and anything empty.
pub(crate) fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// A value as Python's `str()` writes it into a line: a string bare, anything
/// else as its literal.
pub(crate) fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => py_repr(&other.to_string()),
    }
}

fn py_quote(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// Renders JSON text the way Python prints the value it decodes to. Written
/// as a visitor over the text because the key order of a map is part of the
/// line, and `serde_json::Value` does not keep it.
struct PyRepr;

impl<'de> DeserializeSeed<'de> for PyRepr {
    type Value = String;
    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<String, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for PyRepr {
    type Value = String;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }
    fn visit_unit<E>(self) -> Result<String, E> {
        Ok("None".to_string())
    }
    fn visit_bool<E>(self, b: bool) -> Result<String, E> {
        Ok(if b { "True" } else { "False" }.to_string())
    }
    fn visit_i64<E>(self, n: i64) -> Result<String, E> {
        Ok(n.to_string())
    }
    fn visit_u64<E>(self, n: u64) -> Result<String, E> {
        Ok(n.to_string())
    }
    fn visit_f64<E>(self, f: f64) -> Result<String, E> {
        Ok(format!("{f:?}"))
    }
    fn visit_str<E>(self, s: &str) -> Result<String, E> {
        Ok(py_quote(s))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<String, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(PyRepr)? {
            items.push(item);
        }
        Ok(format!("[{}]", items.join(", ")))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<String, A::Error> {
        let mut items = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let value = map.next_value_seed(PyRepr)?;
            items.push(format!("{}: {value}", py_quote(&key)));
        }
        Ok(format!("{{{}}}", items.join(", ")))
    }
}

fn py_repr(json: &str) -> String {
    let mut de = serde_json::Deserializer::from_str(json);
    // The text is JSON that serde_json has parsed or written already.
    PyRepr
        .deserialize(&mut de)
        .unwrap_or_else(|_| json.to_string())
}

/// Counts in first-seen order, which is the order Python's `Counter` prints.
fn count(keys: impl Iterator<Item = String>) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for key in keys {
        match counts.iter_mut().find(|(k, _)| *k == key) {
            Some((_, n)) => *n += 1,
            None => counts.push((key, 1)),
        }
    }
    counts
}

fn py_counts(counts: &[(String, usize)]) -> String {
    let items: Vec<String> = counts
        .iter()
        .map(|(k, n)| format!("{}: {n}", py_quote(k)))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// `coverage.abstain` as it stands in the file. The engine writes a map of
/// counts by lever there, and the digest shows it in the file's key order.
#[derive(Deserialize)]
struct AbstainProbe<'a> {
    #[serde(borrow)]
    coverage: CoverageProbe<'a>,
}

#[derive(Deserialize)]
struct CoverageProbe<'a> {
    #[serde(borrow)]
    abstain: &'a RawValue,
}

/// One undecided site, with the fields the digest needs proven present.
struct Undecided {
    site: String,
    class: String,
    lever: String,
    scope: String,
}

/// Print the digest of `engine_doc` to `out`. Nothing is printed when the
/// document is refused.
pub fn run(engine_doc: &Path, out: &mut dyn Write) -> Result<()> {
    let text = std::fs::read_to_string(engine_doc)
        .with_context(|| format!("read {}", engine_doc.display()))?;
    let doc: Value =
        serde_json::from_str(&text).with_context(|| format!("parse {}", engine_doc.display()))?;
    check_schema(&doc, engine_doc)?;

    const DOC: &str = "the scan document";
    let findings = list(&doc, "findings", DOC)?;
    let cov = field(&doc, "coverage", DOC)?;
    let str_of = |v: &Value, key: &str, what: &str| field(v, key, what).map(py_str);
    let abstain = match serde_json::from_str::<AbstainProbe>(&text) {
        Ok(probe) => py_repr(probe.coverage.abstain.get()),
        Err(_) => bail!("\"coverage\" of {DOC} has no \"abstain\""),
    };

    let mut blocking = Vec::new();
    let mut advisory = Vec::new();
    for (i, x) in findings.iter().enumerate() {
        let what = format!("finding {} of {DOC}", i + 1);
        match field(x, "severity", &what)?.as_str() {
            Some("blocking") => blocking.push((x, what)),
            Some("advisory") => advisory.push((x, what)),
            _ => {}
        }
    }

    let mut s = String::new();
    writeln!(
        s,
        "ENGINE_DIGEST exit={} blocking={} advisory={} resolved={}/{} abstain={abstain}",
        str_of(&doc, "exit", DOC)?,
        blocking.len(),
        advisory.len(),
        str_of(cov, "resolved", "\"coverage\"")?,
        str_of(cov, "total", "\"coverage\"")?,
    )?;
    for (x, what) in &blocking {
        writeln!(
            s,
            "  BLOCK [{}] {} — {} · {} · fix: {}",
            str_of(x, "id", what)?,
            str_of(x, "class", what)?,
            str_of(x, "site", what)?,
            str_of(x, "control", what)?,
            str_of(x, "fix", what)?,
        )?;
    }
    for (x, what) in &advisory {
        writeln!(
            s,
            "  ADV   [{}] {} — {} · {}",
            str_of(x, "id", what)?,
            str_of(x, "class", what)?,
            str_of(x, "site", what)?,
            str_of(x, "control", what)?,
        )?;
    }

    let covered: Vec<String> = list(&doc, "covered_classes", DOC)?
        .iter()
        .map(py_str)
        .collect();
    writeln!(
        s,
        "COVERED_CLASSES (engine-settled; lenses must NOT re-report these):"
    )?;
    writeln!(s, "  {}", covered.join(", "))?;

    let undecided = list(&doc, "undecided", DOC)?
        .iter()
        .enumerate()
        .map(|(i, u)| {
            let what = format!("undecided site {} of {DOC}", i + 1);
            Ok(Undecided {
                site: str_of(u, "site", &what)?,
                class: str_of(u, "class", &what)?,
                lever: str_of(u, "lever", &what)?,
                scope: str_of(u, "scope", &what)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    // Every other scope (test_support, dev_only, migration, backfill) is
    // scaffolding and never enters the adjudication list.
    let runtime: Vec<&Undecided> = undecided.iter().filter(|u| u.scope == "runtime").collect();
    writeln!(
        s,
        "UNDECIDED total={} by_scope={} runtime_by_lever={}",
        undecided.len(),
        py_counts(&count(undecided.iter().map(|u| u.scope.clone()))),
        py_counts(&count(runtime.iter().map(|u| u.lever.clone()))),
    )?;

    writeln!(s, "UNDECIDED_CLASS_CENSUS (runtime, top 10):")?;
    let mut census = count(runtime.iter().map(|u| u.class.clone()));
    // Stable, so classes of one count keep the order the engine listed them.
    census.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (class, n) in census.iter().take(10) {
        writeln!(s, "  {n:5}  {class}")?;
    }

    // A per-site judgment is what closes a `judge` site, so those go first,
    // then `bounds`, then `no_spec`. Stable within a lever.
    let mut adjudicate = runtime;
    adjudicate.sort_by_key(|u| (u.lever != "judge", u.lever != "bounds"));
    adjudicate.truncate(ADJUDICATION_CAP);
    writeln!(
        s,
        "ADJUDICATION_LIST ({} sites, cap {ADJUDICATION_CAP}):",
        adjudicate.len()
    )?;
    for u in adjudicate {
        writeln!(s, "  {} · {} · {}", u.site, u.class, u.lever)?;
    }

    out.write_all(s.as_bytes())?;
    Ok(())
}
