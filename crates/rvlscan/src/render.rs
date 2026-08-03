//! Human-facing scan output (po-3t3oj.9): the severity-ladder hook default and
//! the per-finding explain view. The raw verdict-count dump was correct but
//! unreadable; this groups findings by effective severity, says WHY each one
//! rises to blocking, and reserves the noisy detail for `rvlscan explain`.
//!
//! Two shapes:
//!   - ladder (hook default): findings grouped BLOCKING / ADVISORY, a coverage
//!     line, and a blocked-or-pass footer. Incident detail is counts only.
//!   - explain: one finding as an evidence block with the snippet, named
//!     incident citations, control, and fix. Invoked via `rvlscan explain`.

use std::fmt::Write as _;

/// When to emit ANSI color. Auto honors NO_COLOR and a non-tty stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    Always,
    Never,
    Auto,
}

impl ColorMode {
    /// Resolve Auto against the environment: NO_COLOR set OR stdout not a tty
    /// means no color. `tty` is passed in so this stays pure and testable.
    pub fn resolve(self, no_color_env: bool, tty: bool) -> bool {
        match self {
            ColorMode::Always => true,
            ColorMode::Never => false,
            ColorMode::Auto => !no_color_env && tty,
        }
    }
}

/// Effective severity after weighting. Base severity can be ELEVATED by
/// incident evidence: a medium finding that matches critical corpus incidents
/// becomes blocking, because the corpus says this shape actually takes
/// systems down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Blocking,
    Advisory,
    /// Judged not worth surfacing (low_value); folded into coverage, not shown.
    Suppressed,
}

/// One finding as the renderer sees it: a class plus the site and evidence to
/// display. Built from a triaged item; the fields the incident corpus would
/// enrich are optional so the output degrades gracefully when they are absent.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Stable short id for `rvlscan explain <id>` and durable suppression.
    pub id: String,
    /// Primary site "file:line" shown in the ladder.
    pub site: String,
    /// One-line human description of the risk.
    pub description: String,
    /// The judged disposition: surface | rollup | low_value | depends | unjudged.
    pub disposition: String,
    /// Base severity string: high | medium | low | "" (unknown).
    pub severity: String,
    pub incident_count: u32,
    pub critical_count: u32,
    /// Control reference (e.g. "RC-019"), empty if none.
    pub control: String,
    /// The suggested fix, for the explain view.
    pub fix: String,
    pub site_count: usize,
    /// Extra example sites for the explain view.
    pub example_sites: Vec<String>,
    /// The waiver key for this finding: the class key `client_type.method`
    /// (e.g. `db.RLSPool.QueryRow`). Matched case-insensitively against
    /// `.revelara.yaml` waivers; also the value written by `rvlscan suppress`.
    pub class_rule: String,
    /// Set when a `.revelara.yaml` waiver suppresses this finding. Folded into
    /// the Suppressed section like `low_value`, kept out of BLOCKING/ADVISORY.
    pub suppressed: bool,
}

/// Coverage summary for the footer/coverage section.
#[derive(Debug, Clone, Copy)]
pub struct Coverage {
    pub decided: usize,
    pub total: usize,
    /// Unknown API surfaces (no spec) queued for the factory.
    pub unknown: usize,
}

/// A short, stable id for a finding class, for explain/suppress references.
/// Deterministic so the same finding keeps the same id across scans.
pub fn finding_id(class_key: &str) -> String {
    // FNV-1a over the class key, rendered base36, 4 chars. Collisions across a
    // single scan's handful of classes are vanishingly unlikely and cosmetic.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in class_key.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    let digits = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = [0u8; 4];
    for slot in out.iter_mut() {
        *slot = digits[(h % 36) as usize];
        h /= 36;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

/// The effective severity section for a finding: base severity elevated by
/// incident evidence. Only `surface`/`rollup`/`depends` findings are shown;
/// `low_value` is suppressed; anything unjudged is advisory (surfaced, not
/// blocking — an un-triaged finding must not block a commit).
pub fn classify(f: &Finding) -> Section {
    if f.suppressed || f.disposition == "low_value" {
        return Section::Suppressed;
    }
    let base_blocking = f.severity == "high";
    let elevated = f.critical_count > 0;
    if (base_blocking || elevated) && f.disposition == "surface" {
        Section::Blocking
    } else {
        Section::Advisory
    }
}

fn paint(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Render the severity-ladder hook output. `elapsed` is a caller-formatted
/// timing string (e.g. "0.4s (warm)").
pub fn render_ladder(findings: &[Finding], cov: Coverage, elapsed: &str, color: bool) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{} {}",
        paint("rvlscan", "1", color),
        paint(elapsed, "2", color)
    );
    o.push('\n');

    let blocking: Vec<&Finding> = findings
        .iter()
        .filter(|f| classify(f) == Section::Blocking)
        .collect();
    let advisory: Vec<&Finding> = findings
        .iter()
        .filter(|f| classify(f) == Section::Advisory)
        .collect();

    if !blocking.is_empty() {
        let _ = writeln!(
            o,
            "{} {}",
            paint("\u{25a0} BLOCKING", "31", color),
            paint("(base severity elevated by incident evidence)", "2", color)
        );
        for f in &blocking {
            write_finding_line(&mut o, f, color);
        }
        o.push('\n');
    }
    if !advisory.is_empty() {
        let _ = writeln!(o, "{}", paint("\u{25a0} ADVISORY", "33", color));
        for f in &advisory {
            write_finding_line(&mut o, f, color);
        }
        o.push('\n');
    }

    let _ = writeln!(o, "{}", paint("\u{25a0} COVERAGE", "32", color));
    let mut cline = format!("  {}/{} API surfaces decided", cov.decided, cov.total);
    if cov.unknown > 0 {
        let _ = write!(
            cline,
            " \u{00b7} {} unknown queued for the spec factory",
            cov.unknown
        );
    }
    let _ = writeln!(o, "{}", paint(&cline, "2", color));
    o.push('\n');

    let suppressed = findings
        .iter()
        .filter(|f| classify(f) == Section::Suppressed)
        .count();

    if blocking.is_empty() {
        let mut foot = format!(
            "{} {} advisory",
            paint("\u{2713}", "32", color),
            advisory.len()
        );
        if suppressed > 0 {
            let _ = write!(foot, " \u{00b7} {suppressed} suppressed");
        }
        let _ = writeln!(o, "{foot} \u{00b7} commit clean");
    } else {
        let _ = writeln!(
            o,
            "{} blocked \u{2014} fix or suppress {} blocking finding{} to commit",
            paint("\u{2717}", "31", color),
            blocking.len(),
            if blocking.len() == 1 { "" } else { "s" }
        );
    }
    o
}

fn write_finding_line(o: &mut String, f: &Finding, color: bool) {
    let _ = writeln!(o, "  {} \u{2014} {}", f.site, f.description);
    let sev = if f.severity.is_empty() {
        "unjudged".to_string()
    } else {
        f.severity.clone()
    };
    let mut ev = String::new();
    if f.incident_count > 0 {
        ev = format!(
            "  evidence: {} corpus incident{}",
            f.incident_count,
            if f.incident_count == 1 { "" } else { "s" }
        );
        if f.critical_count > 0 {
            let _ = write!(ev, ", {} critical", f.critical_count);
        }
    }
    let mut meta = format!("severity: {sev}{ev}");
    if f.site_count > 1 {
        let _ = write!(meta, "  \u{00b7} {} sites", f.site_count);
    }
    let _ = writeln!(o, "    {}", paint(&meta, "2", color));
    let mut tail = String::new();
    if !f.control.is_empty() {
        let _ = write!(tail, "control {} \u{00b7} ", f.control);
    }
    let _ = write!(tail, "explain: rvlscan explain {}", f.id);
    let _ = writeln!(o, "    {}", paint(&tail, "2", color));
}

/// Render one finding as an evidence block (the explain view).
pub fn render_explain(f: &Finding, incidents: &[(String, bool, String)], color: bool) -> String {
    let mut o = String::new();
    let sev_label = if classify(f) == Section::Blocking {
        "block"
    } else {
        "warn"
    };
    let sev_color = if sev_label == "block" { "31" } else { "33" };
    let _ = writeln!(
        o,
        "{}: {}",
        paint(&format!("{sev_label}[{}]", f.id), sev_color, color),
        f.description
    );
    let _ = writeln!(o, "  {} {}", paint("-->", "36", color), f.site);
    if f.incident_count > 0 {
        let _ = writeln!(
            o,
            "  {}: this shape is linked to {}",
            paint("why this matters", "1", color),
            paint(&format!("{} incidents", f.incident_count), "1", color)
        );
        for (name, critical, url) in incidents {
            let tag = if *critical { " (critical)" } else { "" };
            let _ = writeln!(o, "    \u{00b7} {}{} {}", name, tag, paint(url, "2", color));
        }
    }
    if !f.control.is_empty() {
        let _ = writeln!(o, "  {}: {}", paint("control", "1", color), f.control);
    }
    if !f.fix.is_empty() {
        let _ = writeln!(o, "  {}: {}", paint("fix", "1", color), f.fix);
    }
    let _ = writeln!(
        o,
        "  {}",
        paint(
            &format!(
                "suppress: rvlscan suppress {} --reason=\"...\"  (writes .revelara.yaml, shared via git)",
                f.id
            ),
            "2",
            color
        )
    );
    if f.site_count > 1 {
        let _ = writeln!(
            o,
            "  {}",
            paint(
                &format!("{} sites total; examples:", f.site_count),
                "2",
                color
            )
        );
        for s in f.example_sites.iter().take(5) {
            let _ = writeln!(o, "    {}", paint(s, "2", color));
        }
    }
    o
}
