//! Score the RC-027 error-reporting verdict against its answer key: real
//! repositories at pinned commits, each labelled by hand with the verdict a
//! correct lane would give (`testdata/rc027-key/README.md`).
//!
//!     crates/rvl-structure/testdata/rc027-key/fetch.sh <checkouts>
//!     cargo run --release -p rvl-structure --example rc027_key -- \
//!         crates/rvl-structure/testdata/rc027-key/key.jsonl <checkouts>
//!
//! Each repository is read from `<checkouts>/<owner>/<name>`, which must be
//! a git checkout at the key's commit: a missing or moved checkout refuses
//! the run instead of scoring a different tree.
//!
//! Per decided verdict (`violates`, `satisfies`), precision is the share of
//! the lane's verdicts whose label is the same verdict, with its Wilson 95%
//! lower bound. The serving gate is a lower bound of at least 0.90. Exit 0
//! when every decided verdict with any rows passes, 1 when one fails, 2 on a
//! refusal (a bad key row, a missing or moved checkout).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{bail, Context as _, Result};
use rvl_core::Verdict;
use serde::Deserialize;

/// The precision the lower bound must reach for RC-027 to be served.
const GATE: f64 = 0.90;
/// The two-sided 95% normal quantile.
const Z95: f64 = 1.959_963_984_540_054;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Service,
    Library,
    Cli,
    Tool,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Truth {
    Violates,
    Satisfies,
    Abstain,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Row {
    repo: String,
    commit: String,
    kind: Kind,
    truth: Truth,
    why: String,
}

fn load(path: &str) -> Result<Vec<Row>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    let mut rows: Vec<Row> = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, line) in text
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
    {
        let row: Row = serde_json::from_str(line).with_context(|| format!("{path}:{}", i + 1))?;
        let parts: Vec<&str> = row.repo.split('/').collect();
        if parts.len() != 2 || parts.iter().any(|p| p.is_empty() || p.starts_with('.')) {
            bail!("{path}:{}: repo {:?} is not owner/name", i + 1, row.repo);
        }
        if row.commit.len() != 40 || !row.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "{path}:{}: commit {:?} is not a full sha",
                i + 1,
                row.commit
            );
        }
        if row.truth != Truth::Abstain && row.kind != Kind::Service {
            bail!(
                "{path}:{}: {} is decided but not a service",
                i + 1,
                row.repo
            );
        }
        if row.why.trim().is_empty() {
            bail!("{path}:{}: {} has no why", i + 1, row.repo);
        }
        if !seen.insert(row.repo.clone()) {
            bail!("{path}:{}: {} twice", i + 1, row.repo);
        }
        rows.push(row);
    }
    Ok(rows)
}

fn head(dir: &Path) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The Wilson score interval's lower bound for `k` successes in `n`. With
/// every verdict right it is `n / (n + z^2)`, so the gate needs at least 35
/// verdicts, all right, before it can pass.
fn wilson_lower(k: usize, n: usize) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let (k, n) = (k as f64, n as f64);
    let p = k / n;
    let z2 = Z95 * Z95;
    let centre = p + z2 / (2.0 * n);
    let margin = Z95 * (p * (1.0 - p) / n + z2 / (4.0 * n * n)).sqrt();
    (centre - margin) / (1.0 + z2 / n)
}

fn run() -> Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [key, checkouts] = &args[..] else {
        bail!("usage: rc027_key <key.jsonl> <checkouts-dir>");
    };
    let rows = load(key)?;
    let mut refused = Vec::new();
    for row in &rows {
        let dir = Path::new(checkouts).join(&row.repo);
        match head(&dir) {
            Some(h) if h == row.commit => {}
            Some(h) => refused.push(format!(
                "{}: checkout at {h}, key pins {}",
                row.repo, row.commit
            )),
            None => refused.push(format!(
                "{}: no git checkout at {}",
                row.repo,
                dir.display()
            )),
        }
    }
    if !refused.is_empty() {
        for r in &refused {
            eprintln!("refused: {r}");
        }
        return Ok(ExitCode::from(2));
    }

    // (verdict, label) per repository; then per decided verdict, the rows
    // it got right and wrong.
    let mut confusion: BTreeMap<(&str, &str), usize> = BTreeMap::new();
    let mut wrong: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut right: BTreeMap<&str, usize> = BTreeMap::new();
    for row in &rows {
        let dir = Path::new(checkouts).join(&row.repo);
        let facts = rvl_structure::retrieve(&dir, &row.commit);
        // The scan date only dates RC-006's advisory note; RC-027 ignores it.
        let found = rvl_structure::evaluate(&facts, "1970-01-01")
            .into_iter()
            .find(|f| f.control == "RC-027")
            .context("the lane returned no RC-027 row")?;
        let verdict = found.verdict.as_str();
        let label = match row.truth {
            Truth::Violates => "violates",
            Truth::Satisfies => "satisfies",
            Truth::Abstain => "abstain",
        };
        *confusion.entry((verdict, label)).or_default() += 1;
        let mark = if !found.verdict.is_decided() {
            "  "
        } else if verdict == label {
            *right.entry(verdict).or_default() += 1;
            "ok"
        } else {
            wrong.entry(verdict).or_default().push(format!(
                "{} ({:?}, labelled {label}): lane says {}; key says {}",
                row.repo, row.kind, found.reason, row.why
            ));
            "XX"
        };
        println!(
            "{mark} {verdict:<9} {label:<9} {:<8} {}",
            format!("{:?}", row.kind),
            row.repo
        );
    }

    println!("\nlane verdict x label:");
    for ((v, l), n) in &confusion {
        println!("  {v:<9} {l:<9} {n}");
    }
    let mut pass = true;
    for v in [Verdict::Violates, Verdict::Satisfies] {
        let v = v.as_str();
        let k = right.get(v).copied().unwrap_or(0);
        let bad = wrong.get(v).map_or(&[][..], |w| &w[..]);
        let n = k + bad.len();
        if n == 0 {
            println!("\n{v}: no verdicts, precision unmeasured");
            continue;
        }
        let lb = wilson_lower(k, n);
        let ok = lb >= GATE;
        pass &= ok;
        println!(
            "\n{v}: precision {k}/{n} = {:.3}, Wilson 95% lower bound {lb:.3}: {} the {GATE:.2} gate",
            k as f64 / n as f64,
            if ok { "meets" } else { "below" },
        );
        for w in bad {
            println!("  wrong: {w}");
        }
    }
    Ok(if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("refused: {e:#}");
            ExitCode::from(2)
        }
    }
}
