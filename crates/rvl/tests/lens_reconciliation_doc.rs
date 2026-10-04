//! THE LENS RECONCILIATION MUST STAY CHECKABLE (po-6c0v8.1).
//!
//! `docs/lens-reconciliation.md` re-issues the ranked top-20 lens candidates
//! with a status column, and the porting epic reads it to decide what NOT to
//! build. A status with no evidence behind it is the stale list the bead was
//! filed to retire, so the table is held to its own contract here:
//!
//!   * every rank from 1 to 20 is present;
//!   * every row carries exactly one of the three statuses;
//!   * every row cites a `path:line` that resolves in this repo;
//!   * every row that is not SHIPPED names the bead that would close it;
//!   * every config key the document names is one a retriever really emits.
//!
//! Line numbers are checked for existence, not for content: the document is a
//! dated snapshot, and a test that broke on every unrelated edit to a cited
//! file would be deleted rather than maintained.

use std::collections::BTreeSet;
use std::path::PathBuf;

const STATUSES: &[&str] = &["SHIPPED", "LANE-WIRED-NEEDS-CORPUS", "GENUINELY-NEW"];

/// The crate directory, read at run time. `cargo test` sets CARGO_MANIFEST_DIR
/// for every test process; a binary reused from a shared CARGO_TARGET_DIR still
/// carries the compile-time path of whichever checkout built it, which may be gone.
fn manifest_dir() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

fn repo_root() -> PathBuf {
    manifest_dir().join("../..")
}

fn doc() -> String {
    let path = repo_root().join("docs/lens-reconciliation.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// One row of the reconciled table: `| rank | class | status | evidence | bead | notes |`.
struct Row {
    /// The rank cell as written: `8` or, for a split candidate, `8a`.
    label: String,
    rank: u32,
    status: String,
    evidence: String,
    bead: String,
}

fn rows(doc: &str) -> Vec<Row> {
    doc.lines()
        .filter_map(|line| {
            let cells: Vec<&str> = line.trim().strip_prefix('|')?.split('|').collect();
            let label = cells.first()?.trim();
            let digits: String = label.chars().take_while(char::is_ascii_digit).collect();
            let rank = digits.parse().ok()?;
            assert!(
                cells.len() >= 6,
                "row {label} must have rank, class, status, evidence, bead and notes cells"
            );
            Some(Row {
                label: label.to_string(),
                rank,
                status: cells[2].trim().to_string(),
                evidence: cells[3].to_string(),
                bead: cells[4].to_string(),
            })
        })
        .collect()
}

/// The text of every `backticked` span in `s`.
fn code_spans(s: &str) -> Vec<&str> {
    s.split('`').skip(1).step_by(2).collect()
}

/// A code span of the form `path:line`, split. Anything else is not a citation.
fn citation(span: &str) -> Option<(&str, usize)> {
    let (path, line) = span.rsplit_once(':')?;
    Some((path, line.parse().ok()?))
}

#[test]
fn every_rank_from_1_to_20_is_reconciled() {
    let ranks: BTreeSet<u32> = rows(&doc()).iter().map(|r| r.rank).collect();
    assert_eq!(ranks, (1..=20).collect::<BTreeSet<u32>>());
}

#[test]
fn every_row_carries_one_of_the_three_statuses() {
    for row in rows(&doc()) {
        assert!(
            STATUSES.contains(&row.status.as_str()),
            "row {} has status {:?}, want one of {STATUSES:?}",
            row.label,
            row.status
        );
    }
}

#[test]
fn every_row_cites_a_line_that_exists() {
    let root = repo_root();
    for row in rows(&doc()) {
        let cited: Vec<(&str, usize)> = code_spans(&row.evidence)
            .into_iter()
            .filter_map(citation)
            .collect();
        assert!(!cited.is_empty(), "row {} cites no file:line", row.label);
        for (path, line) in cited {
            let text = std::fs::read_to_string(root.join(path))
                .unwrap_or_else(|e| panic!("row {} cites {path}: {e}", row.label));
            let len = text.lines().count();
            assert!(
                (1..=len).contains(&line),
                "row {} cites {path}:{line}, but the file has {len} lines",
                row.label
            );
        }
    }
}

#[test]
fn every_row_that_is_not_shipped_names_a_bead() {
    for row in rows(&doc()) {
        if row.status == "SHIPPED" {
            continue;
        }
        assert!(
            code_spans(&row.bead).iter().any(|b| b.starts_with("po-")),
            "row {} is {} and names no bead",
            row.label,
            row.status
        );
    }
}

#[test]
fn every_config_key_the_document_names_is_emitted() {
    let ledger = rvl_config::key_ledger::EMITTED_KEYS;
    let doc = doc();
    let mut named = 0;
    for span in code_spans(&doc) {
        let Some((format, key)) = span.split_once(' ') else {
            continue;
        };
        if key.contains(' ') || !ledger.iter().any(|k| k.format == format) {
            continue;
        }
        named += 1;
        assert!(
            ledger.iter().any(|k| k.format == format && k.key == key),
            "the document names config key `{span}`, which no retriever emits"
        );
    }
    assert!(named > 0, "the config rows must name the keys they rest on");
}
