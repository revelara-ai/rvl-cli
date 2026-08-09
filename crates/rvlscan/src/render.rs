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
/// Serde is derived because `scan` persists the rendered ladder to the
/// last-scan state file that `explain`/`suppress` resolve ids from.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

/// Coverage summary for the coverage section.
///
/// `resolved` counts every site the scanner reached a conclusion on: a bounded
/// blocking call, an unbounded one, OR a non-blocking call (`NotApplicable`).
/// The older "decided" number counted only blocking conclusions and so buried
/// the large set of calls the specs correctly resolve as non-blocking, making
/// coverage read far worse than it is. The remaining sites `abstain`, broken
/// out by lever so the reader sees WHY each is unresolved.
// No longer `Copy`: `degraded` is a Vec. Default is derived so a caller can
// build one with `..Default::default()` rather than restating every abstain
// bucket, which is how a new bucket gets silently forgotten at a call site.
#[derive(Debug, Clone, Default)]
pub struct Coverage {
    pub resolved: usize,
    pub total: usize,
    /// No spec for the API — the mint/coverage lever.
    pub abstain_no_spec: usize,
    /// Spec present but boundedness couldn't be established (search truncated)
    /// — the retrieval-depth / out-of-code-bound lever.
    pub abstain_bounds: usize,
    /// Spec says blocking "depends" per call site — the per-site-judge lever.
    pub abstain_judge: usize,
    /// Any other undecided outcome.
    pub abstain_other: usize,
    /// A whole-pass degradation: the incremental path retrieved only part of
    /// the tree because a helper failed, so `total` describes the reused
    /// portion and NOT the repo (po-av01j.139). Distinct from `degraded`
    /// below, which names individual languages during a full retrieval.
    ///
    /// Load-bearing when the lane is EMPTY: "no call sites in scope" and "the
    /// retriever failed so we never looked" are opposite statements, and the
    /// first one printed over the second is the exact confusion this bead
    /// exists to remove.
    pub degraded_note: Option<String>,
    /// Languages that contributed no packets at all (po-av01j.102). Distinct
    /// from the abstain buckets above, which count SITES the scanner reached
    /// and could not decide. These are languages it never got to look at, so
    /// the resolved/total ratio says nothing about them.
    pub degraded: Vec<DegradedLang>,
    /// Per-language outcome for every language SEEN, including the ones that
    /// ran cleanly and the ones nothing can read (po-av01j.128 / .132).
    pub lang_status: Vec<LangStatus>,
}

/// The one-line per-language roll-call. Rendered whenever anything was seen, so
/// a lane that ran is visibly a lane that ran.
pub fn render_lang_status(cov: &Coverage, color: bool) -> String {
    use std::fmt::Write as _;
    if cov.lang_status.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = cov
        .lang_status
        .iter()
        .map(|s| match s.state {
            LangState::Scanned => format!("{} {} sites", s.lang, s.detail),
            LangState::Abstained => format!("{} abstained", s.lang),
            LangState::Failed => format!("{} FAILED", s.lang),
            LangState::Unsupported => format!("{} not supported ({})", s.lang, s.detail),
        })
        .collect();
    let mut o = String::new();
    // Yellow when anything failed: a failure changes what the numbers above it
    // mean, an abstention or an unsupported language does not.
    let any_failed = cov.lang_status.iter().any(|s| s.state == LangState::Failed);
    let line = format!("  languages: {}", parts.join(" \u{00b7} "));
    let _ = writeln!(
        o,
        "{}",
        paint(&line, if any_failed { "33" } else { "2" }, color)
    );
    o
}

/// The COVERAGE lines naming languages that contributed no packets
/// (po-av01j.102). Split out as a pure function so the abstained/failed
/// distinction is testable without building a whole ladder.
///
/// Rendered in yellow, not the dim grey the abstain buckets use: an abstain
/// bucket is a normal scan outcome, whereas a whole language going unscanned
/// changes what the resolved percentage above it means.
pub fn render_coverage_degradations(cov: &Coverage, color: bool) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    for d in &cov.degraded {
        let line = if d.abstained {
            format!("  {}: abstained \u{2014} {}", d.lang, d.reason)
        } else {
            format!("  {}: retriever failed \u{2014} {}", d.lang, d.reason)
        };
        let _ = writeln!(o, "{}", paint(&line, "33", color));
    }
    o
}

/// What happened to one language in this scan, as rendered to the user.
///
/// The point is that SILENCE IS NEVER AMBIGUOUS (po-av01j.128 / po-av01j.132).
/// Before this, a language that ran and found nothing, a language whose helper
/// declined, and a language nothing here can read all produced the same output:
/// none. On a Rust repo with four C files, cindex parsed all four, found no I/O
/// correctly, and the report mentioned C nowhere -- a reader could not tell it
/// had been looked at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LangStatus {
    pub lang: String,
    pub state: LangState,
    /// Site count for Scanned; the reason for the others.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LangState {
    /// The helper ran to completion. `detail` carries the packet count, which
    /// may legitimately be zero.
    Scanned,
    /// The helper ran and declined, with a reason. Working as intended.
    Abstained,
    /// The helper could not run or errored. NOT working as intended.
    Failed,
    /// Sources are present and nothing here can read them. The third state,
    /// which used to be reported as nothing at all.
    Unsupported,
}

/// One language that produced no packets, as rendered to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DegradedLang {
    pub lang: String,
    /// The helper ran and declined, as opposed to failing. Kept as a flag
    /// rather than folded into `reason` because the two must not read alike:
    /// an abstention is the tool working correctly, a failure is not.
    pub abstained: bool,
    pub reason: String,
}

impl Coverage {
    pub fn abstain_total(&self) -> usize {
        self.abstain_no_spec + self.abstain_bounds + self.abstain_judge + self.abstain_other
    }
}

/// Coverage for the G6 config lane, rendered inside the COVERAGE section when
/// the lane saw anything. Mirrors [`Coverage`]'s lever-based abstain
/// breakdown, plus the identity-only sightings of unsupported config formats
/// (format id + file count, nothing else — the privacy contract).
#[derive(Debug, Clone, Default)]
pub struct ConfigCoverage {
    /// Config settings the lane reached a conclusion on.
    pub resolved: usize,
    pub total: usize,
    /// No spec for the (format, key) — the factory's authoring lever.
    pub abstain_no_spec: usize,
    /// The effective value lives outside the repo (org/project setting).
    pub abstain_outside_repo: usize,
    /// Any other undecided outcome (low-confidence spec, unknown pattern).
    pub abstain_other: usize,
    /// Config files a retriever claimed but could not parse.
    pub unparseable_files: usize,
    /// Sightings: (format identity, file count, a retriever for the format
    /// exists). The last field separates the authoring queue from files a
    /// supported retriever simply had nothing to take (po-av01j.136).
    pub sightings: Vec<(String, usize, bool)>,
}

impl ConfigCoverage {
    pub fn abstain_total(&self) -> usize {
        self.abstain_no_spec + self.abstain_outside_repo + self.abstain_other
    }
    /// Nothing to render: the lane saw no config at all.
    pub fn is_empty(&self) -> bool {
        self.total == 0 && self.unparseable_files == 0 && self.sightings.is_empty()
    }
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

/// How many findings land in BLOCKING after waivers/dispositions — i.e.
/// whether the ladder's footer says "blocked". The scan's exit code is derived
/// from this same function the footer uses, so the printed verdict and the
/// process status can never disagree (po-av01j.94: they did, for months).
pub fn blocking_count(findings: &[Finding]) -> usize {
    findings
        .iter()
        .filter(|f| classify(f) == Section::Blocking)
        .count()
}

fn paint(s: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{s}\x1b[0m")
    } else {
        s.to_string()
    }
}

/// Render the severity-ladder hook output. `elapsed` is a caller-formatted
/// timing string (e.g. "0.4s (warm)"). `config` is the G6 config lane's
/// coverage (None or empty renders nothing extra); config FINDINGS themselves
/// ride in `findings` like any other finding, only the coverage lines differ.
pub fn render_ladder(
    findings: &[Finding],
    cov: Coverage,
    config: Option<&ConfigCoverage>,
    elapsed: &str,
    color: bool,
) -> String {
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
    // No call sites in scope at all (po-av01j.139). "0/0 API surfaces resolved
    // (0%)" is arithmetically fine and tells the reader nothing; under
    // --changed-only this is the ordinary case and the useful statement is that
    // the scan RAN and had nothing to look at. Said plainly so a developer
    // whose commit touched no call site does not read a silent zero as either a
    // pass they did not earn or a failure they did not cause.
    if cov.total == 0 {
        // "I found nothing" and "I could not look" must never print alike.
        match &cov.degraded_note {
            Some(note) => {
                let line =
                    format!("  call-site lane INCOMPLETE \u{2014} no sites were scanned: {note}");
                let _ = writeln!(o, "{}", paint(&line, "33", color));
            }
            None => {
                let line = "  no API call sites in scope \u{2014} nothing to resolve";
                let _ = writeln!(o, "{}", paint(line, "2", color));
            }
        }
    } else {
        let total = cov.total.max(1);
        let pct = 100 * cov.resolved / total;
        let cline = format!(
            "  {}/{} API surfaces resolved ({}%)",
            cov.resolved, cov.total, pct
        );
        let _ = writeln!(o, "{}", paint(&cline, "2", color));
        // Abstain breakdown, each bucket tied to the lever that closes it.
        let ab = cov.abstain_total();
        if ab > 0 {
            let mut parts: Vec<String> = Vec::new();
            if cov.abstain_no_spec > 0 {
                parts.push(format!("{} no spec", cov.abstain_no_spec));
            }
            if cov.abstain_bounds > 0 {
                parts.push(format!("{} unresolved bounds", cov.abstain_bounds));
            }
            if cov.abstain_judge > 0 {
                parts.push(format!("{} need per-site judge", cov.abstain_judge));
            }
            if cov.abstain_other > 0 {
                parts.push(format!("{} other", cov.abstain_other));
            }
            let aline = format!("  {} abstain \u{2014} {}", ab, parts.join(" \u{00b7} "));
            let _ = writeln!(o, "{}", paint(&aline, "2", color));
        }
    }
    // Outside the branch on purpose. A degraded language is the reason the G1
    // lane can be empty, so it must be reported precisely when total == 0; and
    // the config and structure lanes have their own findings, which the old
    // abort discarded along with everything else.
    if cov.total > 0 {
        if let Some(note) = &cov.degraded_note {
            let line = format!("  coverage is PARTIAL \u{2014} {note}");
            let _ = writeln!(o, "{}", paint(&line, "33", color));
        }
    }
    o.push_str(&render_lang_status(&cov, color));
    o.push_str(&render_coverage_degradations(&cov, color));
    if let Some(cc) = config.filter(|cc| !cc.is_empty()) {
        if cc.total > 0 {
            let pct = 100 * cc.resolved / cc.total.max(1);
            let cline = format!(
                "  config: {}/{} settings resolved ({}%)",
                cc.resolved, cc.total, pct
            );
            let _ = writeln!(o, "{}", paint(&cline, "2", color));
            let ab = cc.abstain_total();
            if ab > 0 {
                let mut parts: Vec<String> = Vec::new();
                if cc.abstain_no_spec > 0 {
                    parts.push(format!("{} no spec", cc.abstain_no_spec));
                }
                if cc.abstain_outside_repo > 0 {
                    parts.push(format!("{} set outside repo", cc.abstain_outside_repo));
                }
                if cc.abstain_other > 0 {
                    parts.push(format!("{} other", cc.abstain_other));
                }
                let aline = format!("  config abstain \u{2014} {}", parts.join(" \u{00b7} "));
                let _ = writeln!(o, "{}", paint(&aline, "2", color));
            }
        }
        if cc.unparseable_files > 0 {
            let uline = format!(
                "  {} config file{} unparseable",
                cc.unparseable_files,
                if cc.unparseable_files == 1 { "" } else { "s" }
            );
            let _ = writeln!(o, "{}", paint(&uline, "2", color));
        }
        // Identity-only telemetry: format id + count, never content. Split by
        // whether a retriever for the format exists, because one line saying
        // "unsupported" for both was actively misleading (po-av01j.136 defect
        // 2): it reported 109 Gatekeeper policies as unsupported Kubernetes in
        // a run where the Kubernetes lane resolved 288 settings.
        let render_list = |v: &[(String, usize, bool)]| -> String {
            v.iter()
                .map(|(f, n, _)| format!("{f} ({n})"))
                .collect::<Vec<_>>()
                .join(" \u{00b7} ")
        };
        let unsupported: Vec<_> = cc
            .sightings
            .iter()
            .filter(|(_, _, has)| !has)
            .cloned()
            .collect();
        let declined: Vec<_> = cc
            .sightings
            .iter()
            .filter(|(_, _, has)| *has)
            .cloned()
            .collect();
        if !unsupported.is_empty() {
            // The authoring queue: nothing here reads these formats at all.
            let sline = format!(
                "  unsupported config formats sighted: {}",
                render_list(&unsupported)
            );
            let _ = writeln!(o, "{}", paint(&sline, "2", color));
        }
        if !declined.is_empty() {
            // Supported formats whose retriever declined these particular
            // files — normally a resource carrying nothing any spec asks
            // about. NOT a coverage gap, and it must not read as one.
            let sline = format!(
                "  supported formats, nothing to retrieve: {}",
                render_list(&declined)
            );
            let _ = writeln!(o, "{}", paint(&sline, "2", color));
        }
    }
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

/// Provisional ranking for an unjudged finding: blast radius (how many sites
/// the class hits) is the one severity signal available without a class judge.
/// It is EXPOSURE, not criticality -- reported as such so the reader is never
/// told a severity we didn't actually judge.
fn exposure_tier(site_count: usize) -> &'static str {
    if site_count >= 100 {
        "high"
    } else if site_count >= 10 {
        "medium"
    } else {
        "low"
    }
}

fn write_finding_line(o: &mut String, f: &Finding, color: bool) {
    let _ = writeln!(o, "  {} \u{2014} {}", f.site, f.description);
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
    // A judged finding shows its severity; an unjudged one ranks by exposure
    // (blast radius) and says plainly the severity is unrated -- honest about
    // what the scanner knows vs. what a human review still owes it.
    let meta = if f.severity.is_empty() {
        let plural = if f.site_count == 1 { "" } else { "s" };
        format!(
            "exposure: {} \u{00b7} {} site{plural} \u{00b7} severity unrated{ev}",
            exposure_tier(f.site_count),
            f.site_count
        )
    } else {
        let mut m = format!("severity: {}{ev}", f.severity);
        if f.site_count > 1 {
            let _ = write!(m, "  \u{00b7} {} sites", f.site_count);
        }
        m
    };
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
