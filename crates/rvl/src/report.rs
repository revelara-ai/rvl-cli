//! SECURITY CONTRACT — customer code never leaves the machine.
//!
//! rvl is going OPEN SOURCE, so this must be true and auditable BY
//! CONSTRUCTION, not by convention. When rvl tells the Revelara spec factory
//! about API surfaces it could not decide (no spec exists yet), the payload
//! carries ONLY the public API SHAPE, the language it was written in, and a
//! count:
//!
//!   * `client_type` — the public API type identity (e.g. `db.Pool`),
//!   * `method`      — the public API method identity (e.g. `Query`),
//!   * `lang`        — the LANGUAGE NAME those sites were written in
//!     ("go", "python", "csharp", …), or empty,
//!   * `site_count`  — how many call sites had that shape.
//!
//! and NOTHING else. No source snippets. No enclosing function bodies. No file
//! paths (a path leaks repo structure). No line numbers. Nothing that identifies
//! the repository beyond the public API identity, its language, and a count.
//!
//! WHY `lang` DOES NOT WEAKEN THIS CONTRACT. A language name is not source. It
//! is not a path, not a line number, not a symbol the customer wrote, and it is
//! not repo-identifying: it ranges over a closed set of public ecosystem names
//! that every scanner build already announces by shipping a helper per language,
//! and knowing that a `db.Pool.Query` surface is Go tells a reader nothing about
//! the repository it came from that `db.Pool.Query` did not already tell them.
//! It is a property of the LANGUAGE the public API belongs to, at the same
//! altitude as `client_type` itself. It is here because the factory's authoring
//! prompt otherwise has to assume one language for the whole corpus, and a
//! confidently wrong language is a worse answer than no language at all.
//!
//! `lang` is ALSO the one field on this payload whose value comes from an
//! external packet stream rather than from rvl's own analysis, so it is
//! normalized before it can ride: [`normalize_lang`] admits only a short
//! identifier and reduces everything else to empty. A snippet cannot survive
//! that check, which is what keeps "structurally incapable of carrying source"
//! literally true of this field too, and not merely true of how we happen to
//! populate it.
//!
//! THIS IS NOT A PRECEDENT FOR SOURCE-BEARING FIELDS. `snippet`, `kind`,
//! `constructions`, `client_construction`, file paths and line numbers stay OFF
//! this payload permanently. The Revelara-side `specfactory.Surface` does have
//! those fields and this report will never fill them; that asymmetry is
//! deliberate and correct — those fields are fed by corpora we own, never by a
//! customer scan. The test for a new field is not "is it small?" but "is it
//! structurally incapable of carrying source?", and the answer for anything
//! free-form quoted out of the customer's file is no.
//!
//! [`ReportSurface`] is the ENTIRE per-surface payload. The audit tests below
//! serialize a report built from sites whose every source-bearing field (and the
//! language field) is a sentinel, and assert the sentinels never appear — adding
//! a source-bearing field here breaks those tests (and the open-source privacy
//! contract) on purpose.

use rvl_core::authoring::{self, KeysOn, Routing};
use rvl_core::Site;
use rvl_propagate::Finding;

/// One reported API surface. The WHOLE per-surface payload: public API identity,
/// the language it was observed in, and a count. See the module SECURITY
/// CONTRACT — this type must stay structurally incapable of carrying source,
/// paths, or line numbers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ReportSurface {
    pub client_type: String,
    pub method: String,
    /// The one language every site behind this surface was written in, as the
    /// scanner spells it. Empty means NO language is being claimed — either no
    /// site carried one, or the shape was observed in more than one language
    /// (see [`build_report`]). Always serialized, so the payload's key set is
    /// fixed and an auditor can assert it unconditionally.
    #[serde(default)]
    pub lang: String,
    pub site_count: usize,
}

/// The longest string that can be a language identifier. The real ones are
/// short ("typescript" is 10, "objective-c" is 11); anything longer is not a
/// language name. Mirrors `langMaxLen` on the Revelara side.
const LANG_MAX_LEN: usize = 24;

/// Reduce a scanner-supplied language to the short identifier that may ride on
/// the wire, or to empty.
///
/// This is a SHAPE check, not an allowlist: it admits every language rvl
/// emits today and any it adds later, while refusing prose, whitespace,
/// newlines, punctuation and quotes. That refusal is the point. `lang` arrives
/// on a `--retrieved` packet stream, which is external input; without this,
/// a stream whose `lang` held a source snippet would put that snippet on the
/// only payload that ever leaves the machine. Deliberately identical to
/// `normalizeLang` in the Revelara `specfactory` package, so both ends agree on
/// what a language name is and neither has to trust the other to have checked.
fn normalize_lang(s: &str) -> String {
    let v = s.trim().to_ascii_lowercase();
    if v.is_empty() || v.len() > LANG_MAX_LEN {
        return String::new();
    }
    if !v
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "_-+#.".contains(c))
    {
        return String::new();
    }
    v
}

/// What one (client_type, method) group has accumulated so far: how many sites
/// had that shape, and the single language they agree on — if they agree.
#[derive(Default)]
struct GroupAcc {
    site_count: usize,
    /// The one language seen so far. Never holds empty for "seen": an empty
    /// language is never recorded, so empty here means "nothing seen yet".
    lang: String,
    /// Set once two DIFFERENT languages have been seen. A mixed group states
    /// no language at all rather than picking a winner.
    mixed: bool,
    /// Set once any site says the called API is declared in the scanned
    /// repository. The mark belongs to the surface, so one site is enough.
    in_repo: bool,
}

impl GroupAcc {
    /// Fold one site's language into the group.
    ///
    /// A site with no language is an ABSENCE OF EVIDENCE, not a third opinion:
    /// it never makes a group mixed. Two different languages do, and then the
    /// group reports none. This is exactly the rule `specfactory.BuildQuestions`
    /// applies on the Revelara side, applied here because rvl is what does
    /// the aggregating: a group arrives there as ONE surface, so if this end
    /// picked an arbitrary winner the other end would faithfully state a
    /// language that is wrong for some of the sites behind it. Folding with the
    /// same rule makes the two ends agree and makes the re-fold there a no-op.
    fn observe(&mut self, lang: &str) {
        let l = normalize_lang(lang);
        if l.is_empty() {
            return;
        }
        if self.lang.is_empty() {
            self.lang = l;
        } else if self.lang != l {
            self.mixed = true;
        }
    }

    /// The language to put on the wire: the agreed one, or empty when the group
    /// is mixed or nothing carried a language. Both land on the other end as
    /// "state no language", which is the safe answer for both.
    fn reported_lang(self) -> String {
        if self.mixed {
            String::new()
        } else {
            self.lang
        }
    }
}

/// The full shape-only report: a scanner version string (not repo data) and the
/// unknown API surfaces. This is exactly what would ever be transmitted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Report {
    /// Sites whose client type never resolved, so no spec could ever be keyed
    /// on them (po-av01j.146). Kept as a COUNT rather than dropped silently:
    /// it is the signal that retrieval is failing to resolve receivers, and a
    /// silent drop would hide it. Carries no identity, so the privacy contract
    /// is unchanged.
    #[serde(default)]
    pub unresolved_sites: u32,
    /// Surfaces the scanned repository declares itself, and the sites behind
    /// them. See [`build_report`]. Counts only: the names stay on the machine.
    #[serde(default)]
    pub repo_internal_surfaces: u32,
    #[serde(default)]
    pub repo_internal_sites: u32,
    pub scanner_version: String,
    pub surfaces: Vec<ReportSurface>,
}

/// A finding is an UNKNOWN surface when propagation could not decide it because
/// no spec covers its API. This mirrors how the scan/coverage code counts
/// unknowns (`reason.starts_with("no spec")`); the two must stay in lockstep so
/// "what the scan calls unknown" and "what the report would send" are identical.
fn is_unknown(reason: &str) -> bool {
    reason.starts_with("no spec")
}

/// Is this client type UNMINTABLE -- an identity a spec could never be keyed on
/// (po-av01j.146)?
///
/// Measured across five repositories, 15 surfaces and 270 sites carried an
/// EMPTY client_type or the literal "invalid type": ".post", "invalid
/// type.Get". These are retrieval artifacts rather than API surfaces. They
/// cannot be minted -- there is nothing to key a spec on -- they inflate the
/// queue, and a factory that consumed them would author a spec against an
/// identity no scan can ever match.
///
/// Excluded from the payload and COUNTED instead, because a silent drop would
/// be the same mistake this epic keeps finding: the number is the signal that
/// retrieval is failing to resolve receivers.
fn is_unmintable(client_type: &str) -> bool {
    let t = client_type.trim();
    t.is_empty() || t.starts_with("invalid type") || t.starts_with('<')
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// Every unknown finding, grouped by (client_type, method). `findings` and
/// `sites` are index-aligned (`propagate_all` maps sites 1:1), so each unknown
/// finding names its site by position. A group whose client type did not
/// resolve is kept, under the text the retriever gave: the payload counts it
/// and the queue routes it.
///
/// ONLY the public API identity, its language and the repo-internal mark are
/// read from a site here, so nothing else can leak into either view.
/// BTreeMap keeps assembly deterministic before the final sort.
fn unknown_groups(
    sites: &[Site],
    findings: &[Finding],
) -> std::collections::BTreeMap<(String, String), GroupAcc> {
    let mut groups: std::collections::BTreeMap<(String, String), GroupAcc> =
        std::collections::BTreeMap::new();
    for (f, s) in findings.iter().zip(sites.iter()) {
        if !is_unknown(&f.reason) {
            continue;
        }
        let key = (s.client_type.clone(), s.method.clone());
        let acc = groups.entry(key).or_default();
        acc.site_count += 1;
        acc.in_repo |= s.provenance.api_in_repo;
        acc.observe(&s.lang);
    }
    groups
}

/// Build the shape-only report. For each unknown surface we take ONLY
/// `client_type`, `method` and the normalized `lang` from the site — never the
/// snippet, enclosing body, file path, or line — dedup by (client_type,
/// method), and sum the per-shape site counts.
///
/// Language is a property of the SITES, and the group is what gets reported, so
/// it is folded: a group whose sites all agree reports that language, a group
/// that spans two reports none. Grouping stays keyed on (client_type, method)
/// only — adding the language to the key would split one API into two surfaces
/// whose specs then collide downstream, where spec identity is (api_type,
/// method) end to end.
///
/// REPO-INTERNAL SURFACES DO NOT SHIP (po-av01j.146). A surface whose called
/// API the scanned repository declares itself (`provenance.api_in_repo`) is
/// useful to exactly one repository, so a spec for it is worthless in a shared
/// corpus; measured across five repositories these were 122 of 245 surfaces.
/// Its name also identifies the repository, which this payload promises not to
/// do. Such a surface is excluded and counted, in surfaces and in sites. A
/// retriever that does not set the mark changes nothing: its surfaces ship as
/// they did before.
///
/// Sorted deterministically: highest `site_count` first, ties broken by
/// `client_type` then `method`, so the payload (and its audit) is reproducible.
pub fn build_report(sites: &[Site], findings: &[Finding], scanner_version: &str) -> Report {
    let mut unresolved_sites: u32 = 0;
    let mut groups = unknown_groups(sites, findings);
    groups.retain(|(client_type, _), acc| {
        let unmintable = is_unmintable(client_type);
        if unmintable {
            unresolved_sites = unresolved_sites.saturating_add(count(acc.site_count));
        }
        !unmintable
    });

    let (internal, shared): (Vec<_>, Vec<_>) = groups.into_iter().partition(|(_, acc)| acc.in_repo);
    let repo_internal_surfaces = count(internal.len());
    let repo_internal_sites = count(internal.iter().map(|(_, acc)| acc.site_count).sum());

    let mut surfaces: Vec<ReportSurface> = shared
        .into_iter()
        .map(|((client_type, method), acc)| ReportSurface {
            client_type,
            method,
            site_count: acc.site_count,
            lang: acc.reported_lang(),
        })
        .collect();

    surfaces.sort_by(|a, b| {
        b.site_count
            .cmp(&a.site_count)
            .then_with(|| a.client_type.cmp(&b.client_type))
            .then_with(|| a.method.cmp(&b.method))
    });

    Report {
        scanner_version: scanner_version.to_string(),
        surfaces,
        unresolved_sites,
        repo_internal_surfaces,
        repo_internal_sites,
    }
}

/// One finding of the spec-authoring queue: an unknown API identity, how many
/// sites have it, and where it goes.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct QueueEntry {
    /// As the retriever gave it. Empty or `invalid type` when the receiver
    /// did not resolve.
    pub client_type: String,
    pub method: String,
    pub lang: String,
    pub site_count: usize,
    pub routing: Routing,
}

/// The spec-authoring queue of one scan: EVERY unknown finding, with its
/// computed quadrant and lane.
///
/// THIS IS NOT THE REPORT PAYLOAD and is never sent. It names the surfaces the
/// scanned repository declares itself, which [`Report`] only counts, because a
/// person who routes findings must see which ones were routed away from a
/// spec. `local_only` is always true and is serialized, so a file of this
/// shape says what it is. It carries no source, path or line number.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct AuthoringQueue {
    pub local_only: bool,
    pub entries: Vec<QueueEntry>,
}

/// Build the spec-authoring queue from the findings [`build_report`] reads.
///
/// The two gates are the two exclusions of the payload, read as answers:
///
///   * DETERMINISTIC: the client type resolved, so there is an identity a
///     rule can be keyed on ([`is_unmintable`] says it did not);
///   * TRANSFERABLE: no site marks the called API as declared in the scanned
///     repository (`provenance.api_in_repo`). A retriever that does not set
///     the mark is read as "not in the repository", as it is for the payload.
///
/// So the entries routed to the API spec lane are exactly the surfaces of the
/// payload, and each excluded count of the payload is here as named rows.
///
/// Sorted by quadrant, spec lane first, then as the payload is.
pub fn build_queue(sites: &[Site], findings: &[Finding]) -> AuthoringQueue {
    let mut entries: Vec<QueueEntry> = unknown_groups(sites, findings)
        .into_iter()
        .map(|((client_type, method), acc)| QueueEntry {
            routing: authoring::route(KeysOn::ApiCall, !is_unmintable(&client_type), !acc.in_repo),
            client_type,
            method,
            site_count: acc.site_count,
            lang: acc.reported_lang(),
        })
        .collect();
    entries.sort_by(|a, b| {
        a.routing
            .quadrant
            .cmp(&b.routing.quadrant)
            .then_with(|| b.site_count.cmp(&a.site_count))
            .then_with(|| a.client_type.cmp(&b.client_type))
            .then_with(|| a.method.cmp(&b.method))
    });
    AuthoringQueue {
        local_only: true,
        entries,
    }
}

/// One surface in a combined view of several reports: the same shape-only
/// identity, with the number of reports it appears in.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CombinedSurface {
    pub client_type: String,
    pub method: String,
    /// Folded across the reports by the rule one report uses across its sites:
    /// the one language they agree on, or empty.
    #[serde(default)]
    pub lang: String,
    /// How many of the combined reports carry this surface.
    pub repo_count: usize,
    /// The sites behind it, summed over those reports.
    pub site_count: usize,
}

/// Several [`Report`]s as one ranked list. Made from report payloads only, so
/// it can carry nothing a report could not.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct CombinedReport {
    /// How many reports were combined.
    pub reports: usize,
    pub unresolved_sites: u32,
    pub repo_internal_surfaces: u32,
    pub repo_internal_sites: u32,
    pub surfaces: Vec<CombinedSurface>,
}

/// Combine one report per repository and rank the surfaces by RECURRENCE: how
/// many repositories have the surface, then how many sites.
///
/// One report can only rank by site count, and site count inside one
/// repository is what a single heavy user maximizes. A surface that many
/// repositories share is the one a shared spec pays for, and only a combined
/// view can know that.
///
/// The inputs are files and are not trusted to be what [`build_report`] would
/// write today: an unmintable identity is moved to the count again, and the
/// language is normalized again.
pub fn combine_reports(reports: &[Report]) -> CombinedReport {
    #[derive(Default)]
    struct Acc {
        group: GroupAcc,
        repo_count: usize,
    }
    let mut groups: std::collections::BTreeMap<(String, String), Acc> =
        std::collections::BTreeMap::new();
    let mut combined = CombinedReport {
        reports: reports.len(),
        unresolved_sites: 0,
        repo_internal_surfaces: 0,
        repo_internal_sites: 0,
        surfaces: Vec::new(),
    };
    for r in reports {
        combined.unresolved_sites = combined.unresolved_sites.saturating_add(r.unresolved_sites);
        combined.repo_internal_surfaces = combined
            .repo_internal_surfaces
            .saturating_add(r.repo_internal_surfaces);
        combined.repo_internal_sites = combined
            .repo_internal_sites
            .saturating_add(r.repo_internal_sites);
        let mut seen = std::collections::BTreeSet::new();
        for s in &r.surfaces {
            if is_unmintable(&s.client_type) {
                combined.unresolved_sites = combined
                    .unresolved_sites
                    .saturating_add(count(s.site_count));
                continue;
            }
            let key = (s.client_type.clone(), s.method.clone());
            let acc = groups.entry(key.clone()).or_default();
            acc.group.site_count = acc.group.site_count.saturating_add(s.site_count);
            acc.group.observe(&s.lang);
            if seen.insert(key) {
                acc.repo_count += 1;
            }
        }
    }

    combined.surfaces = groups
        .into_iter()
        .map(|((client_type, method), acc)| CombinedSurface {
            client_type,
            method,
            repo_count: acc.repo_count,
            site_count: acc.group.site_count,
            lang: acc.group.reported_lang(),
        })
        .collect();
    combined.surfaces.sort_by(|a, b| {
        b.repo_count
            .cmp(&a.repo_count)
            .then_with(|| b.site_count.cmp(&a.site_count))
            .then_with(|| a.client_type.cmp(&b.client_type))
            .then_with(|| a.method.cmp(&b.method))
    });
    combined
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinctive sentinels planted in the source-bearing fields of a site. If
    // ANY of these appears in the serialized report, customer code leaked.
    const SENTINEL_SNIPPET: &str = "SECRET_BUSINESS_LOGIC_abc123";
    const SENTINEL_BODY: &str = "ENCLOSING_BODY_SECRET_xyz789";
    const SENTINEL_PATH: &str = "internal/secret/customer_module.go";
    const SENTINEL_LINE: u32 = 424242;

    fn unknown_site(client: &str, method: &str) -> Site {
        Site {
            file_path: SENTINEL_PATH.into(),
            line_number: SENTINEL_LINE,
            client_type: client.into(),
            method: method.into(),
            snippet: SENTINEL_SNIPPET.into(),
            enclosing_function_body: SENTINEL_BODY.into(),
            ..Default::default()
        }
    }

    /// A site whose LANGUAGE field is itself hostile: the packet stream is
    /// external input, so `lang` is the one reported field an attacker (or an
    /// accident) could aim source at.
    fn site_with_lang(client: &str, method: &str, lang: &str) -> Site {
        let mut s = unknown_site(client, method);
        s.lang = lang.into();
        s
    }

    fn finding(reason: &str) -> Finding {
        Finding {
            site_id: "sid".into(),
            verdict: rvl_core::Verdict::Abstain,
            reason: reason.into(),
        }
    }

    #[test]
    fn report_json_never_carries_source_paths_or_lines() {
        // Two unknown sites whose source-bearing fields are all sentinels. The
        // second also aims a source sentinel at `lang`, the one reported field
        // whose value comes from the (external) packet stream.
        let sites = vec![
            unknown_site("db.Pool", "Query"),
            site_with_lang("db.Pool", "Query", SENTINEL_SNIPPET),
        ];
        let findings = vec![finding("no spec for db.Pool.Query"), finding("no spec")];
        let report = build_report(&sites, &findings, "9.9.9");
        let json = serde_json::to_string(&report).unwrap();

        // The shape DID make it through.
        assert!(json.contains("db.Pool"));
        assert!(json.contains("Query"));

        // NONE of the source/path/line sentinels rode along.
        assert!(
            !json.contains(SENTINEL_SNIPPET),
            "snippet leaked into the report payload"
        );
        assert!(
            !json.contains(SENTINEL_BODY),
            "enclosing function body leaked into the report payload"
        );
        assert!(
            !json.contains(SENTINEL_PATH),
            "file path leaked into the report payload"
        );
        assert!(
            !json.contains(&SENTINEL_LINE.to_string()),
            "line number leaked into the report payload"
        );
    }

    /// AUDIT: judgment provenance is display text from the signed cache and
    /// never reaches the shape-only payload. A sentinel planted in
    /// `source_note` (and the refs) rides the same scan's triage, proving it
    /// was in reach, and is absent from the report and the queue.
    #[test]
    fn judgment_provenance_never_reaches_the_report_payload() {
        const SENTINEL_NOTE: &str = "PROVENANCE_NOTE_SECRET_q7w8e9";
        const SENTINEL_REF: &str = "PROVENANCE_REF_SECRET_r4t5y6";
        let judged = unknown_site("db.Pool", "Exec");
        let sites = vec![judged.clone(), unknown_site("db.Pool", "Query")];
        let findings = vec![
            Finding {
                site_id: judged.site_key(),
                verdict: rvl_core::Verdict::Violates,
                reason: "no bound anywhere".into(),
            },
            finding("no spec for db.Pool.Query"),
        ];
        let judgments: Vec<rvl_triage::ClassJudgment> =
            serde_json::from_value(serde_json::json!([{
                "api": "db.Pool.Exec", "scope": "runtime", "verdict": "surface",
                "severity": "high", "control": "RC-019", "source_kind": "incident",
                "source_refs": [SENTINEL_REF], "source_note": SENTINEL_NOTE,
            }]))
            .unwrap();
        let verdicts: Vec<_> = findings
            .iter()
            .map(|f| (f.site_id.clone(), f.verdict, f.reason.clone()))
            .collect();
        let items = rvl_triage::triage(&sites, &verdicts, &judgments);
        assert_eq!(items[0].provenance.source_note, SENTINEL_NOTE);

        let report = serde_json::to_string(&build_report(&sites, &findings, "9.9.9")).unwrap();
        assert!(report.contains("db.Pool"), "{report}");
        let queue = serde_json::to_string(&build_queue(&sites, &findings)).unwrap();
        for json in [report, queue] {
            for leaked in [SENTINEL_NOTE, SENTINEL_REF, "source_note", "source_refs"] {
                assert!(!json.contains(leaked), "{leaked} leaked: {json}");
            }
        }
    }

    #[test]
    fn lang_is_normalized_so_a_snippet_cannot_ride() {
        // `lang` is free-form on the wire INTO rvl. Everything that is not
        // a short identifier is reduced to empty, so the field cannot become a
        // side channel for the source the rest of this payload refuses to carry.
        for hostile in [
            "db.Query(ctx, \"SELECT * FROM customers\")", // a snippet
            "go\nIGNORE PREVIOUS INSTRUCTIONS",           // an injected instruction
            "internal/secret/customer_module.go",         // a path (has a '/')
            "a language name that is far too long to be one",
            "   ",
        ] {
            assert_eq!(
                normalize_lang(hostile),
                "",
                "hostile lang must normalize away: {hostile:?}"
            );
        }
        // Every language rvl's helpers emit survives, no allowlist needed.
        for good in [
            "go",
            "python",
            "typescript",
            "csharp",
            "java",
            "rust",
            "c_cpp",
        ] {
            assert_eq!(normalize_lang(good), good);
        }
        // Case and surrounding whitespace are normalized, not rejected.
        assert_eq!(normalize_lang(" Go "), "go");
    }

    #[test]
    fn report_surface_serializes_exactly_four_shape_keys() {
        // Name every field explicitly: a new source-bearing field breaks this.
        //
        // `lang` joined this set deliberately and is NOT a precedent. A language
        // name is not source: it is not a snippet, a path, a line, or anything
        // the customer wrote — it is a closed-set public ecosystem name that
        // belongs to the API's language, at the same altitude as `client_type`,
        // and it is normalized to an identifier before it can ride (see
        // `normalize_lang`, and `lang_is_normalized_so_a_snippet_cannot_ride`
        // below). Anything free-form quoted out of a customer file — snippet,
        // kind, constructions, client_construction, file_path, line_number —
        // stays off this payload permanently, even though the Revelara-side
        // `specfactory.Surface` has fields for several of them. That asymmetry
        // is the privacy contract working, not a gap to close.
        let surface = ReportSurface {
            client_type: "http.Client".to_string(),
            method: "Do".to_string(),
            lang: "go".to_string(),
            site_count: 3,
        };
        let v: serde_json::Value = serde_json::to_value(&surface).unwrap();
        let obj = v.as_object().expect("a surface serializes as an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["client_type", "lang", "method", "site_count"],
            "the per-surface payload must carry ONLY shape + language + count"
        );
    }

    #[test]
    fn the_key_set_is_fixed_even_when_no_language_is_claimed() {
        // The payload's shape does not vary with its content: an auditor can
        // assert one key set for every surface a scan could ever produce.
        let sites = vec![unknown_site("db.Pool", "Query")]; // no lang
        let findings = vec![finding("no spec")];
        let report = build_report(&sites, &findings, "1.0.0");
        let v = serde_json::to_value(&report.surfaces[0]).unwrap();
        let obj = v.as_object().unwrap();
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, vec!["client_type", "lang", "method", "site_count"]);
        assert_eq!(v["lang"], "", "no language claimed is the empty string");
    }

    #[test]
    fn surface_carries_the_language_its_sites_were_observed_in() {
        let sites = vec![site_with_lang("db.Pool", "Query", "python")];
        let findings = vec![finding("no spec")];
        let report = build_report(&sites, &findings, "1.0.0");
        let v = serde_json::to_value(&report.surfaces[0]).unwrap();
        assert_eq!(v["lang"], "python");
    }

    #[test]
    fn a_group_spanning_two_languages_states_neither() {
        // An unresolved receiver emits a bare `HttpClient` in both C# and Java.
        // Reporting either would be a confidently wrong language, which is the
        // exact failure the language threading exists to remove; report none.
        let sites = vec![
            site_with_lang("HttpClient", "Send", "csharp"),
            site_with_lang("HttpClient", "Send", "java"),
        ];
        let findings = vec![finding("no spec"), finding("no spec")];
        let report = build_report(&sites, &findings, "1.0.0");
        assert_eq!(report.surfaces.len(), 1, "one shape, still one surface");
        let v = serde_json::to_value(&report.surfaces[0]).unwrap();
        assert_eq!(v["lang"], "", "a mixed group must state no language");
        assert_eq!(v["site_count"], 2, "both sites still count");
    }

    #[test]
    fn a_site_without_a_language_is_not_a_third_opinion() {
        // Absence of evidence must not turn an agreeing group into a mixed one:
        // a pre-`lang` packet stream would otherwise silence every surface.
        let sites = vec![
            site_with_lang("db.Pool", "Query", "go"),
            unknown_site("db.Pool", "Query"),
        ];
        let findings = vec![finding("no spec"), finding("no spec")];
        let report = build_report(&sites, &findings, "1.0.0");
        assert_eq!(report.surfaces[0].lang, "go");
        assert_eq!(report.surfaces[0].site_count, 2);
    }

    #[test]
    fn language_is_not_part_of_the_grouping_key() {
        // Two languages, one shape => still ONE surface. Splitting by language
        // would mint two questions whose drafts collide downstream, where spec
        // identity is (api_type, method).
        let sites = vec![
            site_with_lang("HttpClient", "Send", "csharp"),
            site_with_lang("HttpClient", "Send", "java"),
            site_with_lang("db.Pool", "Query", "go"),
        ];
        let findings = vec![finding("no spec"), finding("no spec"), finding("no spec")];
        let report = build_report(&sites, &findings, "1.0.0");
        assert_eq!(report.surfaces.len(), 2, "two shapes, not three languages");
    }

    #[test]
    fn unknown_surfaces_are_deduped_and_summed() {
        // Three unknowns: two share a shape (summed), one is distinct.
        let sites = vec![
            site_with_lang("db.Pool", "Query", "go"),
            site_with_lang("db.Pool", "Query", "go"),
            site_with_lang("http.Client", "Do", "go"),
        ];
        let findings = vec![finding("no spec"), finding("no spec"), finding("no spec")];
        let report = build_report(&sites, &findings, "1.0.0");

        assert_eq!(report.surfaces.len(), 2, "two distinct shapes");
        // Sorted by site_count desc, so the summed shape leads.
        assert_eq!(
            report.surfaces[0],
            ReportSurface {
                client_type: "db.Pool".into(),
                method: "Query".into(),
                lang: "go".into(),
                site_count: 2,
            }
        );
        assert_eq!(
            report.surfaces[1],
            ReportSurface {
                client_type: "http.Client".into(),
                method: "Do".into(),
                lang: "go".into(),
                site_count: 1,
            }
        );
    }

    #[test]
    fn decided_surfaces_are_never_reported() {
        // A satisfies/violates finding is a DECISION, not an unknown; it must
        // not appear. Only "no spec" (undecided) surfaces are reported.
        let sites = vec![
            unknown_site("db.Pool", "Query"),
            unknown_site("http.Client", "Do"),
        ];
        let findings = vec![
            finding("satisfies: bounded by context deadline"),
            finding("violates: no deadline on the call"),
        ];
        let report = build_report(&sites, &findings, "1.0.0");
        assert!(
            report.surfaces.is_empty(),
            "decided surfaces are not reported; we only report what we couldn't decide"
        );
    }

    #[test]
    fn empty_or_all_decided_scan_yields_no_surfaces() {
        assert!(build_report(&[], &[], "1.0.0").surfaces.is_empty());
    }
    // po-av01j.146. Measured across five repositories: 15 surfaces and 270
    // sites carried an empty client_type or the literal "invalid type". They
    // cannot be minted -- there is nothing to key a spec on -- and a factory
    // that consumed them would author against an identity no scan can match.
    #[test]
    fn unmintable_identities_are_excluded_from_the_payload() {
        for bad in ["", "   ", "invalid type", "<unknown>"] {
            assert!(is_unmintable(bad), "{bad:?} must not reach the factory");
        }
        for good in ["net/http.Client", "pg.Pool", "tonic::client::grpc::Grpc<T>"] {
            assert!(!is_unmintable(good), "{good:?} is a real surface");
        }
    }

    // Counted, never silently dropped: the number IS the signal that retrieval
    // is failing to resolve receivers, and hiding it would be the same mistake
    // this epic keeps finding.
    #[test]
    fn excluded_sites_are_counted_rather_than_vanishing() {
        let sites = vec![
            unknown_site("", "post"),
            unknown_site("invalid type", "Get"),
            unknown_site("net/http.Client", "Do"),
        ];
        let findings: Vec<Finding> = sites
            .iter()
            .map(|_| finding("no spec for pkg.T.M"))
            .collect();
        let r = build_report(&sites, &findings, "test");
        assert_eq!(r.surfaces.len(), 1, "only the real surface ships");
        assert_eq!(r.surfaces[0].client_type, "net/http.Client");
        assert_eq!(r.unresolved_sites, 2, "the rest are counted, not hidden");
    }

    fn in_repo_site(client: &str, method: &str) -> Site {
        let mut s = site_with_lang(client, method, "go");
        s.provenance.api_in_repo = true;
        s
    }

    fn no_spec(n: usize) -> Vec<Finding> {
        (0..n).map(|_| finding("no spec")).collect()
    }

    // A surface the scanned repository declares itself is useful to that one
    // repository only, and its name identifies the repository. It does not
    // ship; it is counted.
    #[test]
    fn repo_internal_surfaces_are_excluded_and_counted() {
        let sites = vec![
            in_repo_site("example.com/shop/internal/storage.SQLXDB", "Lookup"),
            in_repo_site("example.com/shop/internal/storage.SQLXDB", "Lookup"),
            in_repo_site("example.com/shop/internal/ledger.Writer", "Post"),
            site_with_lang("net/http.Client", "Do", "go"),
        ];
        let r = build_report(&sites, &no_spec(4), "test");
        assert_eq!(r.surfaces.len(), 1, "only the dependency surface ships");
        assert_eq!(r.surfaces[0].client_type, "net/http.Client");
        assert_eq!(r.repo_internal_surfaces, 2);
        assert_eq!(r.repo_internal_sites, 3);
        let json = serde_json::to_string(&r).unwrap();
        assert!(
            !json.contains("example.com/shop"),
            "a repo-internal type name is repo-identifying and must not ship: {json}"
        );
    }

    // The mark belongs to the surface. A stream where only some sites of one
    // shape carry it still describes one repo-internal surface, and no part
    // of it ships.
    #[test]
    fn one_marked_site_makes_the_whole_surface_repo_internal() {
        let sites = vec![
            in_repo_site("example.com/shop/ledger.Writer", "Post"),
            site_with_lang("example.com/shop/ledger.Writer", "Post", "go"),
        ];
        let r = build_report(&sites, &no_spec(2), "test");
        assert!(r.surfaces.is_empty());
        assert_eq!(r.repo_internal_surfaces, 1);
        assert_eq!(r.repo_internal_sites, 2);
    }

    #[test]
    fn the_report_serializes_exactly_its_counts_version_and_surfaces() {
        let v = serde_json::to_value(build_report(&[], &[], "1.0.0")).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "repo_internal_sites",
                "repo_internal_surfaces",
                "scanner_version",
                "surfaces",
                "unresolved_sites"
            ]
        );
    }

    fn report_of(surfaces: &[(&str, &str, &str, usize)]) -> Report {
        Report {
            unresolved_sites: 0,
            repo_internal_surfaces: 0,
            repo_internal_sites: 0,
            scanner_version: "test".into(),
            surfaces: surfaces
                .iter()
                .map(|(client_type, method, lang, site_count)| ReportSurface {
                    client_type: (*client_type).into(),
                    method: (*method).into(),
                    lang: (*lang).into(),
                    site_count: *site_count,
                })
                .collect(),
        }
    }

    // Site count inside one repository is what a single heavy user maximizes.
    // A surface two repositories share outranks one that a single repository
    // calls 500 times.
    #[test]
    fn combined_surfaces_rank_by_repository_count_before_site_count() {
        let a = report_of(&[
            ("vendor/big.Client", "Call", "go", 500),
            ("net/http.Client", "Do", "go", 2),
        ]);
        let b = report_of(&[("net/http.Client", "Do", "go", 1)]);
        let c = combine_reports(&[a, b]);
        assert_eq!(c.reports, 2);
        assert_eq!(
            c.surfaces,
            vec![
                CombinedSurface {
                    client_type: "net/http.Client".into(),
                    method: "Do".into(),
                    lang: "go".into(),
                    repo_count: 2,
                    site_count: 3,
                },
                CombinedSurface {
                    client_type: "vendor/big.Client".into(),
                    method: "Call".into(),
                    lang: "go".into(),
                    repo_count: 1,
                    site_count: 500,
                },
            ]
        );
    }

    #[test]
    fn combined_ties_break_on_site_count_then_name() {
        let a = report_of(&[
            ("b.T", "M", "go", 1),
            ("a.T", "M", "go", 1),
            ("c.T", "M", "go", 9),
        ]);
        let names: Vec<String> = combine_reports(&[a])
            .surfaces
            .into_iter()
            .map(|s| s.client_type)
            .collect();
        assert_eq!(names, vec!["c.T", "a.T", "b.T"]);
    }

    #[test]
    fn combining_sums_the_excluded_counts_of_every_input() {
        let mut a = report_of(&[]);
        a.unresolved_sites = 3;
        a.repo_internal_surfaces = 2;
        a.repo_internal_sites = 7;
        let mut b = report_of(&[]);
        b.unresolved_sites = 1;
        b.repo_internal_surfaces = 5;
        b.repo_internal_sites = 6;
        let c = combine_reports(&[a, b]);
        assert_eq!(c.unresolved_sites, 4);
        assert_eq!(c.repo_internal_surfaces, 7);
        assert_eq!(c.repo_internal_sites, 13);
    }

    // The inputs are files, so they are checked again: a payload written by a
    // build that still shipped unresolved identities must not put them back
    // in the queue, and its language must not carry anything but a name.
    #[test]
    fn combining_checks_its_inputs_again() {
        let a = report_of(&[
            ("invalid type", "Get", "go", 4),
            ("", "post", "typescript", 2),
            ("HttpClient", "Send", "csharp", 1),
            ("db.Pool", "Query", SENTINEL_SNIPPET, 1),
        ]);
        let b = report_of(&[("HttpClient", "Send", "java", 1)]);
        let c = combine_reports(&[a, b]);
        assert_eq!(c.unresolved_sites, 6);
        assert_eq!(c.surfaces.len(), 2);
        assert_eq!(c.surfaces[0].client_type, "HttpClient");
        assert_eq!(c.surfaces[0].repo_count, 2);
        assert_eq!(c.surfaces[0].lang, "", "two languages, neither is claimed");
        assert_eq!(c.surfaces[1].lang, "", "a snippet is not a language");
    }

    // One payload that lists a shape twice is still one repository.
    #[test]
    fn a_shape_listed_twice_in_one_payload_is_one_repository() {
        let a = report_of(&[("db.Pool", "Query", "go", 1), ("db.Pool", "Query", "go", 2)]);
        let c = combine_reports(&[a]);
        assert_eq!(c.surfaces[0].repo_count, 1);
        assert_eq!(c.surfaces[0].site_count, 3);
    }

    fn queue_row<'a>(q: &'a AuthoringQueue, client_type: &str) -> &'a QueueEntry {
        q.entries
            .iter()
            .find(|e| e.client_type == client_type)
            .unwrap_or_else(|| panic!("no {client_type:?} in {q:?}"))
    }

    // One finding per quadrant. The repo-internal one is the case the routing
    // exists for: a queue constructor one repository declares and calls from
    // many places resolves cleanly, so a rule could decide every site, and no
    // other repository will ever have a site for the spec to judge.
    #[test]
    fn the_queue_routes_one_finding_in_each_quadrant() {
        use rvl_core::authoring::{Lane, Quadrant};
        let mut unresolved_in_repo = unknown_site("invalid type", "push");
        unresolved_in_repo.provenance.api_in_repo = true;
        let sites = vec![
            site_with_lang("net/http.Client", "Do", "go"),
            in_repo_site("example.com/broker/server", "newIPQueue"),
            in_repo_site("example.com/broker/server", "newIPQueue"),
            site_with_lang("", "post", "typescript"),
            unresolved_in_repo,
            // Decided, so it is not in the queue at all.
            unknown_site("db.Pool", "Query"),
        ];
        let mut findings = no_spec(5);
        findings.push(finding("satisfies: bounded by context deadline"));
        let q = build_queue(&sites, &findings);
        assert_eq!(q.entries.len(), 4, "{q:?}");

        let shared = queue_row(&q, "net/http.Client");
        assert_eq!(shared.routing.quadrant, Quadrant::DeterministicTransferable);
        assert_eq!(shared.routing.lane, Lane::ApiSpec);

        let internal = queue_row(&q, "example.com/broker/server");
        assert_eq!(internal.method, "newIPQueue");
        assert_eq!(internal.site_count, 2);
        assert!(internal.routing.deterministic, "the identity resolved");
        assert!(!internal.routing.transferable, "one repository has it");
        assert_eq!(
            internal.routing.quadrant,
            Quadrant::DeterministicNotTransferable
        );
        assert_eq!(internal.routing.lane, Lane::Agent);

        let unresolved = queue_row(&q, "");
        assert_eq!(
            unresolved.routing.quadrant,
            Quadrant::TransferableNotDeterministic
        );
        assert_eq!(unresolved.routing.lane, Lane::Agent);

        let neither = queue_row(&q, "invalid type");
        assert_eq!(neither.routing.quadrant, Quadrant::Neither);
        assert_eq!(neither.routing.lane, Lane::Agent);
    }

    // The queue and the payload read the same findings with the same two
    // tests, so the rows routed to the API spec lane are exactly the surfaces
    // the payload carries.
    #[test]
    fn the_api_spec_lane_of_the_queue_is_the_report_payload() {
        use rvl_core::authoring::Lane;
        let sites = vec![
            site_with_lang("net/http.Client", "Do", "go"),
            site_with_lang("db.Pool", "Query", "go"),
            site_with_lang("db.Pool", "Query", "go"),
            in_repo_site("example.com/shop/ledger.Writer", "Post"),
            unknown_site("", "post"),
        ];
        let findings = no_spec(5);
        let report = build_report(&sites, &findings, "test");
        let lane: Vec<ReportSurface> = build_queue(&sites, &findings)
            .entries
            .into_iter()
            .filter(|e| e.routing.lane == Lane::ApiSpec)
            .map(|e| ReportSurface {
                client_type: e.client_type,
                method: e.method,
                lang: e.lang,
                site_count: e.site_count,
            })
            .collect();
        assert_eq!(lane, report.surfaces);
    }

    // Mintable work leads, and inside a quadrant the order is the payload's.
    #[test]
    fn the_queue_lists_the_spec_lane_first_then_by_site_count() {
        let sites = vec![
            in_repo_site("example.com/shop/ledger.Writer", "Post"),
            in_repo_site("example.com/shop/ledger.Writer", "Post"),
            in_repo_site("example.com/shop/ledger.Writer", "Post"),
            site_with_lang("b.T", "M", "go"),
            site_with_lang("a.T", "M", "go"),
            site_with_lang("a.T", "M", "go"),
        ];
        let names: Vec<String> = build_queue(&sites, &no_spec(6))
            .entries
            .into_iter()
            .map(|e| e.client_type)
            .collect();
        assert_eq!(names, vec!["a.T", "b.T", "example.com/shop/ledger.Writer"]);
    }

    // The queue names what the payload refuses to, so it says on its face
    // that it is not the payload. It still carries no source, path or line.
    #[test]
    fn the_queue_is_marked_local_and_carries_no_source() {
        let sites = vec![
            unknown_site("db.Pool", "Query"),
            site_with_lang("db.Pool", "Query", SENTINEL_SNIPPET),
        ];
        let q = build_queue(&sites, &no_spec(2));
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["local_only"], true);
        let json = v.to_string();
        for leaked in [SENTINEL_SNIPPET, SENTINEL_BODY, SENTINEL_PATH] {
            assert!(!json.contains(leaked), "{leaked} is in the queue: {json}");
        }
        assert!(!json.contains(&SENTINEL_LINE.to_string()), "{json}");
        let mut keys: Vec<&str> = v["entries"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["client_type", "lang", "method", "routing", "site_count"]
        );
    }
}
