//! `rvl scan finalize <scan-dir>`: every mechanical step between what the
//! lenses wrote and what `rvl scan --scan-dir` submits.
//!
//! The scan skill keeps three things beside its submit directory `<scan-dir>`:
//! the raw lens outputs in `<scan-dir>.lens/*.json`, the engine scan document,
//! and a patch that carries the orchestrator's judgments (grounding, drops,
//! register matches). This command rebuilds every `03-findings-*.json` in the
//! submit directory from those on each run: one file per lens, plus
//! `03-findings-engine.json`. It never changes the lens files, so a run with
//! another patch starts from the same input.
//!
//! The transform is a port of the Python script the skill carried, and the
//! lines it prints (`Written:`, `UNKNOWN`, `DUP`, `INVALID`, `LENS_DIGEST`)
//! are the ones the skill reads. It differs from the script in one way that a
//! caller can see: every input is read and checked BEFORE the old findings
//! files are removed, so a run that fails leaves the submit directory as it
//! was.

use crate::scan_digest::{check_schema, field, list, py_str, read_json, truthy};
use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Control codes the catalog retired. A lens can still name one.
const RETIRED: [&str; 2] = ["RC-035", "RC-037"];

/// STPA fields a lens finding carries to the submission unchanged.
const STPA_FIELDS: [&str; 5] = [
    "uca_type",
    "loss_scenario",
    "loss_category",
    "estimated_fix_complexity",
    "constraint_type",
];

const FINDINGS_PREFIX: &str = "03-findings-";

pub struct FinalizeArgs {
    pub scan_dir: PathBuf,
    pub engine: Option<PathBuf>,
    pub patch: Option<PathBuf>,
    pub register: Option<PathBuf>,
    /// `quick` or `deep`; written to every findings file as `scan_mode`.
    pub mode: String,
    /// Business criticality, written to every findings file and a factor of
    /// each lens score.
    pub crit: f64,
}

fn level(v: &Value) -> i64 {
    match v.as_str() {
        Some("low") => 4,
        Some("high") => 10,
        _ => 7,
    }
}

/// Likelihood and impact of a lens severity.
fn lens_scale(severity: &str) -> (&'static str, &'static str) {
    match severity {
        "critical" => ("high", "high"),
        "high" => ("high", "medium"),
        "low" => ("low", "medium"),
        _ => ("medium", "medium"),
    }
}

/// Likelihood, impact, score and priority of an engine row. A fixed scale
/// that exists only because the submission schema asks for these fields: the
/// engine's own scale is blocking or advisory, and no report converts one to
/// the other.
fn engine_scale(key: Option<&str>) -> (&'static str, &'static str, i64, &'static str) {
    match key {
        Some("blocking") => ("high", "high", 75, "high"),
        Some("medium") => ("medium", "medium", 45, "medium"),
        _ => ("low", "medium", 25, "low"),
    }
}

fn priority(score: i64) -> &'static str {
    match score {
        80.. => "critical",
        60.. => "high",
        40.. => "medium",
        _ => "low",
    }
}

/// A category as the catalog spells it: lower case, runs of anything else
/// become one underscore. No category at all is `availability`.
fn slug(v: Option<&Value>) -> String {
    let text = v.filter(|v| truthy(v)).map(py_str).unwrap_or_default();
    let mut out = String::new();
    for c in text.to_lowercase().chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('_') {
            out.push('_');
        }
    }
    let out = out.trim_end_matches('_');
    if out.is_empty() {
        "availability".to_string()
    } else {
        out.to_string()
    }
}

/// `path:line` into its halves. A site with no line number is all path.
fn split_site(s: &str) -> (&str, Option<u64>) {
    if let Some((path, line)) = s.rsplit_once(':') {
        if !line.is_empty() && line.bytes().all(|b| b.is_ascii_digit()) {
            if let Ok(n) = line.parse() {
                return (path, Some(n));
            }
        }
    }
    (s, None)
}

fn rel(p: &str) -> &str {
    p.strip_prefix("./").unwrap_or(p)
}

/// The component of `01-stack.json` that owns `path`: the one with the
/// longest path prefix, where a prefix ends at a path separator. A root
/// component (`.`) matches what no other prefix does, and with no match at
/// all the first component takes the finding.
fn component<'a>(comps: &'a [Value], path: &str) -> Option<&'a Value> {
    let p = rel(path);
    let mut best = comps.first()?.get("name");
    // The length of the best prefix so far; a root component counts as 0.
    let mut longest: Option<usize> = None;
    for c in comps {
        let Some(raw) = c.get("path").and_then(Value::as_str) else {
            continue;
        };
        let pre = rel(raw).trim_end_matches('/');
        let root = raw == "." || raw == "./";
        if pre.is_empty() && !root {
            continue;
        }
        let len = if root { 0 } else { pre.chars().count() };
        let owns = root
            || p == pre
            || p.strip_prefix(pre)
                .is_some_and(|rest| rest.starts_with('/'));
        if owns && longest.is_none_or(|n| len > n) {
            best = c.get("name");
            longest = Some(len);
        }
    }
    best.filter(|name| truthy(name))
}

fn object<'a>(v: Option<&'a Value>, empty: &'a Map<String, Value>) -> &'a Map<String, Value> {
    v.and_then(Value::as_object).unwrap_or(empty)
}

/// `<scan-dir>` with `suffix` appended to its name: where the skill keeps the
/// lens directory beside the submit directory.
fn sibling(scan_dir: &Path, suffix: &str) -> PathBuf {
    // Rebuilt from its components so a trailing separator is not kept.
    let mut s: OsString = scan_dir.components().collect::<PathBuf>().into_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// What the patch and the register say, and what the lens pass has decided so
/// far.
struct Lenses<'a> {
    patch_findings: &'a Map<String, Value>,
    drop: HashSet<&'a str>,
    register: HashMap<&'a str, &'a Value>,
    comps: &'a [Value],
    crit: f64,
    /// Register risk code to the ref of the finding that extends it. The
    /// server applies the first finding on a risk and rejects the second as a
    /// conflict, so one submission sends one.
    claimed: HashMap<String, String>,
    digest: Vec<(i64, String)>,
    log: String,
}

impl Lenses<'_> {
    /// The submission row of lens finding `f`, or `None` when it is dropped.
    fn row(
        &mut self,
        agent: &str,
        lens_ref: &str,
        f: &Map<String, Value>,
    ) -> Result<Option<Value>> {
        let empty = Map::new();
        let get = |key: &str| f.get(key).filter(|v| truthy(v));
        let pt = object(self.patch_findings.get(lens_ref), &empty);
        let patched = |key: &str| pt.get(key).filter(|v| truthy(v));

        let (mut path, line) = match f.get("location") {
            Some(Value::Object(loc)) => {
                let at = |key: &str| loc.get(key).filter(|v| truthy(v));
                (
                    at("file").or(at("path")).map(py_str).unwrap_or_default(),
                    at("line").cloned(),
                )
            }
            loc => {
                let site = loc.filter(|v| truthy(v)).map(py_str).unwrap_or_default();
                let (path, line) = split_site(&site);
                (path.to_string(), line.filter(|n| *n != 0).map(Value::from))
            }
        };

        // Evidence is a list of objects on the wire. A lens may write one
        // string, one object, or a list that mixes both.
        let mut evidence: Vec<Value> = match f.get("evidence") {
            Some(Value::Array(items)) => items.clone(),
            Some(one @ (Value::String(_) | Value::Object(_))) => vec![one.clone()],
            _ => Vec::new(),
        }
        .into_iter()
        .filter(truthy)
        .filter_map(|e| match e {
            Value::String(s) => Some(json!({"type": "code", "description": s})),
            Value::Object(_) => Some(e),
            _ => None,
        })
        .collect();
        let evidence_path = |e: &Value| e.get("path").filter(|v| truthy(v)).map(py_str);
        if path.is_empty() {
            path = evidence.iter().find_map(evidence_path).unwrap_or_default();
        }
        let title = f.get("title").cloned().unwrap_or_else(|| json!(""));
        if !path.is_empty() && !evidence.iter().any(|e| evidence_path(e).is_some()) {
            let mut e = json!({"type": "code", "path": path, "description": title});
            if let Some(line) = &line {
                e["line_number"] = line.clone();
            }
            evidence.insert(0, e);
        }

        let severity = f.get("severity").map(py_str).unwrap_or_default();
        let (li, im) = lens_scale(&severity.to_lowercase());
        let li = get("likelihood").cloned().unwrap_or_else(|| json!(li));
        let im = get("impact").cloned().unwrap_or_else(|| json!(im));

        let mut codes: Vec<Value> = match patched("control_codes").or(get("control_codes")) {
            Some(Value::Array(codes)) => codes.clone(),
            Some(one @ Value::String(_)) => vec![one.clone()],
            Some(_) => Vec::new(),
            None => get("control_code").cloned().into_iter().collect(),
        };

        // A register rediscovery takes the identity the server matches on:
        // the risk's title and control codes. The lens's wording stays in the
        // narrative.
        let mut row_title = title.clone();
        let mut extends = patched("extends").and_then(Value::as_str);
        if let Some(code) = extends {
            if !self.register.contains_key(code) {
                writeln!(self.log, "UNKNOWN {lens_ref} extends {code}: kept as new")?;
                extends = None;
            }
        }
        if let Some(code) = extends {
            if let Some(keeper) = self.claimed.get(code) {
                writeln!(
                    self.log,
                    "DUP {lens_ref} extends {code}, kept by {keeper}: dropped"
                )?;
                return Ok(None);
            }
            self.claimed.insert(code.to_string(), lens_ref.to_string());
            let risk = self.register[code];
            if let Some(t) = risk.get("title").filter(|v| truthy(v)) {
                row_title = t.clone();
            }
            if let Some(Value::Array(c)) = risk.get("control_codes").filter(|v| truthy(v)) {
                codes = c.clone();
            }
        }
        codes.retain(|c| !c.as_str().is_some_and(|c| RETIRED.contains(&c)));

        // Grounding comes from the patch alone. A lens has no retrieval
        // mechanism, so corroboration it wrote itself is not carried.
        let corroboration: &[Value] = patched("corroboration")
            .and_then(Value::as_array)
            .map_or(&[], Vec::as_slice);
        let strength = match pt.get("corroboration_strength").and_then(Value::as_f64) {
            Some(cs) => cs,
            None => {
                let top = corroboration
                    .iter()
                    .filter_map(|c| c.get("relevance_score").and_then(Value::as_f64))
                    .fold(0.0, f64::max);
                (corroboration.len() as f64 / 5.0 * 0.3 + top * 0.4).min(1.0)
            }
        };
        let substantiated = pt
            .get("substantiation_strength")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        // The factor order and the rounding (half to even) are the reference
        // script's, so a score on a boundary lands on the same side.
        let raw = (level(&li) * level(&im)) as f64
            * (1.0 + strength * 0.3)
            * (1.0 + substantiated * 0.2)
            * (1.0 + self.crit * 0.25);
        let score = (raw.round_ties_even() as i64).min(100);

        let narrative = get("narrative").cloned().unwrap_or_else(|| {
            let parts: Vec<String> = [
                get("description").map(py_str),
                get("remediation").map(|r| format!("Remediation: {}", py_str(r))),
            ]
            .into_iter()
            .flatten()
            .collect();
            json!(parts.join(" "))
        });

        let category = slug(get("category").or(get("risk_category")));
        let prio = priority(score);
        let mut row = json!({
            "provenance": format!("agent:{agent}"),
            "title": row_title,
            "category": category,
            "likelihood": li,
            "impact": im,
            "narrative": narrative,
            "control_codes": codes,
            "corroboration": corroboration,
            "substantiation": [],
            "evidence": evidence,
            "risk_score": score,
            "priority": prio,
            "graph_evidence": pt.get("graph_evidence"),
        });
        if !path.is_empty() {
            let mut at = json!({"type": "code_location", "location": path});
            if let Some(line) = &line {
                at["line"] = line.clone();
            }
            row["substantiation"] = json!([at]);
        }
        match f.get("causal_factors") {
            None | Some(Value::Null) => {}
            Some(one @ Value::String(_)) => row["causal_factors"] = json!([one]),
            Some(many) => row["causal_factors"] = many.clone(),
        }
        for key in STPA_FIELDS {
            if let Some(v) = get(key) {
                row[key] = v.clone();
            }
        }
        if let Some(name) = component(self.comps, &path) {
            row["component"] = name.clone();
        }

        let site = if path.is_empty() { "PROJECT" } else { &path };
        let at_line = line.map(|l| format!(":{}", py_str(&l))).unwrap_or_default();
        let codes: Vec<String> = row["control_codes"]
            .as_array()
            .into_iter()
            .flatten()
            .map(py_str)
            .collect();
        let short_title: String = py_str(&title).chars().take(70).collect();
        let extends = extends.map(|c| format!(" extends {c}")).unwrap_or_default();
        let tag: String = prio.to_uppercase().chars().take(4).collect();
        self.digest.push((
            score,
            format!(
                "{lens_ref} {tag} {score} {category} {site}{at_line} [{}] {short_title}{extends}",
                codes.join(",")
            ),
        ));
        Ok(Some(row))
    }
}

/// The submission row of engine finding `x`: title and control verbatim.
fn engine_row(
    x: &Value,
    what: &str,
    categories: &Map<String, Value>,
    comps: &[Value],
) -> Result<Value> {
    let text = |key: &str| field(x, key, what).map(py_str);
    let (description, class, site, fix) = (
        text("description")?,
        text("class")?,
        text("site")?,
        text("fix")?,
    );
    let control = field(x, "control", what)?;
    let severity = field(x, "severity", what)?;

    let (path, line) = split_site(&site);
    // A repo-level row has no file to point at.
    let repo = path == "repo";
    let key = if severity == "blocking" {
        Some("blocking")
    } else {
        x.get("base_severity").and_then(Value::as_str)
    };
    let (li, im, score, prio) = engine_scale(key);
    let sites = x.get("site_count").map_or_else(|| "1".to_string(), py_str);
    let mut narrative =
        format!("{description}. Engine class {class} at {site} ({sites} sites). Fix: {fix}");
    if x.get("gate_exempt").is_some_and(truthy) {
        narrative.push_str(" (gate-exempt)");
    }
    let mut evidence = json!({"type": "code", "description": "engine-resolved site"});
    if !repo {
        evidence["path"] = json!(path);
        evidence["line_number"] = json!(line);
    }
    let category = control.as_str().and_then(|c| categories.get(c));
    let mut row = json!({
        "provenance": "engine",
        "title": description,
        "narrative": narrative,
        "category": slug(category),
        // An engine row with no control sends no code, not an empty one.
        "control_codes": if truthy(control) { json!([control]) } else { json!([]) },
        "likelihood": li,
        "impact": im,
        "risk_score": score,
        "priority": prio,
        "substantiation": if repo { json!([]) } else { json!([{"type": "engine_site", "location": path, "line": line}]) },
        "evidence": [evidence],
    });
    if let Some(name) = component(comps, if repo { "" } else { path }) {
        row["component"] = name.clone();
    }
    Ok(row)
}

/// The lens output files of `lens_dir`, in name order. A directory that does
/// not exist holds none: a scan can run with the engine alone.
fn lens_files(lens_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let entries = match std::fs::read_dir(lens_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", lens_dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("read {}", lens_dir.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        // Hidden files are an editor's or a tool's, never a lens output.
        if let Some(agent) = name
            .strip_suffix(".json")
            .filter(|_| !name.starts_with('.'))
        {
            files.push((agent.to_string(), lens_dir.join(name)));
        }
    }
    files.sort();
    Ok(files)
}

fn stale_findings(scan_dir: &Path) -> Result<Vec<PathBuf>> {
    let mut stale = Vec::new();
    for entry in
        std::fs::read_dir(scan_dir).with_context(|| format!("read {}", scan_dir.display()))?
    {
        let entry = entry.with_context(|| format!("read {}", scan_dir.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(FINDINGS_PREFIX) && name.ends_with(".json") {
            stale.push(entry.path());
        }
    }
    Ok(stale)
}

/// Written to a temporary name and renamed, so a submit that reads the
/// directory never finds half a file. The temporary name is not `*.json`,
/// which is what a submit reads.
fn write_doc(path: &Path, doc: &Value) -> Result<()> {
    let mut buf = Vec::new();
    let fmt = serde_json::ser::PrettyFormatter::with_indent(b" ");
    doc.serialize(&mut serde_json::Serializer::with_formatter(&mut buf, fmt))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, buf).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))
}

/// Rebuild the findings files of `a.scan_dir` and print what was written,
/// then the lens digest, to `out`.
pub fn run(a: &FinalizeArgs, out: &mut dyn Write) -> Result<()> {
    if !a.crit.is_finite() {
        bail!("--crit must be a finite number, got {}", a.crit);
    }
    if !a.scan_dir.is_dir() {
        bail!("{} is not a directory", a.scan_dir.display());
    }
    let empty = Map::new();

    // Read and check every input first. Nothing in the submit directory is
    // touched until all of the output exists in memory.
    let patch = match &a.patch {
        Some(path) => {
            let patch = read_json(path)?;
            if !patch.is_object() {
                bail!("{}: the patch is not a JSON object", path.display());
            }
            patch
        }
        None => json!({}),
    };
    let register = match &a.register {
        Some(path) => read_json(path)?,
        None => Value::Null,
    };
    let engine = match &a.engine {
        Some(path) => {
            let doc = read_json(path)?;
            check_schema(&doc, path)?;
            Some(doc)
        }
        None => None,
    };
    // The stack file is optional: with none, no row carries a component.
    let stack = read_json(&a.scan_dir.join("01-stack.json")).unwrap_or(Value::Null);
    let comps: &[Value] = stack
        .get("components")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);

    let mut lenses = Lenses {
        patch_findings: object(patch.get("findings"), &empty),
        drop: patch
            .get("drop")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect(),
        register: register
            .get("risks")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|r| Some((r.get("risk_code")?.as_str()?, r)))
            .collect(),
        comps,
        crit: a.crit,
        claimed: HashMap::new(),
        digest: Vec::new(),
        log: String::new(),
    };

    let mut files: Vec<(String, Vec<Value>)> = Vec::new();
    for (agent, path) in lens_files(&sibling(&a.scan_dir, ".lens"))? {
        let doc = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))
            .and_then(|text| Ok(serde_json::from_str::<Value>(&text)?));
        let doc = match doc {
            Ok(doc) if doc.is_object() => doc,
            Ok(_) => {
                writeln!(lenses.log, "INVALID {}: not a JSON object", path.display())?;
                continue;
            }
            Err(e) if e.is::<serde_json::Error>() => {
                writeln!(lenses.log, "INVALID {}: {e}", path.display())?;
                continue;
            }
            Err(e) => return Err(e),
        };
        let findings = doc
            .get("findings")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        let mut rows = Vec::new();
        // The patch addresses a finding by `{agent}#{n}`, counted from 1 over
        // the lens file as written, so a drop never renumbers the rest.
        for (i, f) in findings.iter().enumerate() {
            let lens_ref = format!("{agent}#{}", i + 1);
            if lenses.drop.contains(lens_ref.as_str()) {
                continue;
            }
            let Some(f) = f.as_object() else {
                writeln!(lenses.log, "INVALID {lens_ref}: not a JSON object")?;
                continue;
            };
            if let Some(row) = lenses.row(&agent, &lens_ref, f)? {
                rows.push(row);
            }
        }
        writeln!(
            lenses.log,
            "Written: {FINDINGS_PREFIX}{agent}.json ({} findings)",
            rows.len()
        )?;
        files.push((agent, rows));
    }

    let Lenses {
        mut digest,
        mut log,
        ..
    } = lenses;

    if let (Some(doc), Some(path)) = (&engine, &a.engine) {
        let what = path.display().to_string();
        let categories = object(patch.get("control_categories"), &empty);
        let mut rows = Vec::new();
        for (i, x) in list(doc, "findings", &what)?.iter().enumerate() {
            // A waived row is not a risk to register.
            if x.get("suppressed").is_some_and(truthy) {
                continue;
            }
            let what = format!("finding {} of {what}", i + 1);
            rows.push(engine_row(x, &what, categories, comps)?);
        }
        writeln!(
            log,
            "Written: {FINDINGS_PREFIX}engine.json ({} findings)",
            rows.len()
        )?;
        files.push(("engine".to_string(), rows));
    }

    writeln!(
        log,
        "LENS_DIGEST ({} findings, score desc; ref PRIO score category site [controls] title):",
        digest.len()
    )?;
    // Stable, so findings of one score keep lens and file order.
    digest.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    for (_, line) in &digest {
        writeln!(log, "  {line}")?;
    }

    for old in stale_findings(&a.scan_dir)? {
        std::fs::remove_file(&old).with_context(|| format!("remove {}", old.display()))?;
    }
    let catalog_meta = patch.get("catalog_meta").filter(|v| truthy(v));
    for (name, rows) in files {
        // Every file carries the same scalars: `--scan-dir` merges them last
        // writer wins, which is only safe when every writer agrees.
        let mut doc = json!({
            "findings": rows,
            "business_criticality": a.crit,
            "scan_mode": a.mode,
        });
        if let Some(meta) = catalog_meta {
            doc["catalog_meta"] = meta.clone();
        }
        write_doc(
            &a.scan_dir.join(format!("{FINDINGS_PREFIX}{name}.json")),
            &doc,
        )?;
    }

    out.write_all(log.as_bytes())
        .map_err(|e| anyhow!("write the digest: {e}"))
}
