//! SECURITY CONTRACT — customer code never leaves the machine.
//!
//! rvlscan is going OPEN SOURCE, so this must be true and auditable BY
//! CONSTRUCTION, not by convention. When rvlscan tells the Revelara spec factory
//! about API surfaces it could not decide (no spec exists yet), the payload
//! carries ONLY the public API SHAPE and a count:
//!
//!   * `client_type` — the public API type identity (e.g. `db.Pool`),
//!   * `method`      — the public API method identity (e.g. `Query`),
//!   * `site_count`  — how many call sites had that shape.
//!
//! and NOTHING else. No source snippets. No enclosing function bodies. No file
//! paths (a path leaks repo structure). No line numbers. Nothing that identifies
//! the repository beyond the public API identity and a count.
//!
//! [`ReportSurface`] is the ENTIRE per-surface payload. It is deliberately
//! STRUCTURALLY INCAPABLE of carrying source: there is no field a snippet, body,
//! path, or line could ride in. Do NOT add one. The audit tests below serialize
//! a report built from source-bearing sites and assert the sentinels never
//! appear — adding a source-bearing field here breaks those tests (and the
//! open-source privacy contract) on purpose.

use rvl_core::Site;
use rvl_propagate::Finding;

/// One reported API surface. The WHOLE per-surface payload: public API identity
/// plus a count. See the module SECURITY CONTRACT — this type must stay
/// structurally incapable of carrying source, paths, or line numbers.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ReportSurface {
    pub client_type: String,
    pub method: String,
    pub site_count: usize,
}

/// The full shape-only report: a scanner version string (not repo data) and the
/// unknown API surfaces. This is exactly what would ever be transmitted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct Report {
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

/// Build the shape-only report. `findings` and `sites` are index-aligned
/// (`propagate_all` maps sites 1:1), so each unknown finding names its site by
/// position. For each unknown surface we take ONLY `client_type` and `method`
/// from the site — never the snippet, enclosing body, file path, or line — dedup
/// by (client_type, method), and sum the per-shape site counts.
///
/// Sorted deterministically: highest `site_count` first, ties broken by
/// `client_type` then `method`, so the payload (and its audit) is reproducible.
pub fn build_report(sites: &[Site], findings: &[Finding], scanner_version: &str) -> Report {
    // Accumulate counts per (client_type, method). BTreeMap keeps assembly
    // deterministic before the final sort.
    let mut counts: std::collections::BTreeMap<(String, String), usize> =
        std::collections::BTreeMap::new();
    for (f, s) in findings.iter().zip(sites.iter()) {
        if !is_unknown(&f.reason) {
            continue;
        }
        // ONLY the public API identity crosses over. Nothing else on the site
        // is read here, so nothing else can leak.
        let key = (s.client_type.clone(), s.method.clone());
        *counts.entry(key).or_insert(0) += 1;
    }

    let mut surfaces: Vec<ReportSurface> = counts
        .into_iter()
        .map(|((client_type, method), site_count)| ReportSurface {
            client_type,
            method,
            site_count,
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
    }
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

    fn finding(reason: &str) -> Finding {
        Finding {
            site_id: "sid".into(),
            verdict: rvl_core::Verdict::Abstain,
            reason: reason.into(),
        }
    }

    #[test]
    fn report_json_never_carries_source_paths_or_lines() {
        // Two unknown sites whose source-bearing fields are all sentinels.
        let sites = vec![
            unknown_site("db.Pool", "Query"),
            unknown_site("db.Pool", "Query"),
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

    #[test]
    fn report_surface_serializes_exactly_three_shape_keys() {
        // Name every field explicitly: a new source-bearing field breaks this.
        let surface = ReportSurface {
            client_type: "http.Client".to_string(),
            method: "Do".to_string(),
            site_count: 3,
        };
        let v: serde_json::Value = serde_json::to_value(&surface).unwrap();
        let obj = v.as_object().expect("a surface serializes as an object");
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec!["client_type", "method", "site_count"],
            "the per-surface payload must carry ONLY shape + count"
        );
    }

    #[test]
    fn unknown_surfaces_are_deduped_and_summed() {
        // Three unknowns: two share a shape (summed), one is distinct.
        let sites = vec![
            unknown_site("db.Pool", "Query"),
            unknown_site("db.Pool", "Query"),
            unknown_site("http.Client", "Do"),
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
                site_count: 2,
            }
        );
        assert_eq!(
            report.surfaces[1],
            ReportSurface {
                client_type: "http.Client".into(),
                method: "Do".into(),
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
}
