//! `rvl migrate` (po-7p45k.21): the user-side companion to the server's
//! catalog v2 migration. Read-only by default: it inspects the repo's
//! `.revelara.yaml` and the org's service catalog and reports, per
//! finding, the concrete YAML edit that fixes it. `--apply` performs only
//! the one additive, comment-only edit (appending undeclared component
//! candidates, commented out); everything else is always a suggestion.
//!
//! Finding classes:
//!   legacy-compound   the server still has a `<project>/<component>`
//!                     identity for this project
//!   contested         a service touching this repo is quarantined and
//!                     waits for a human call on the Services page
//!   undeclared        a component detected locally is not declared
//!   slug-violation    a declared name does not survive slugify unchanged
//!
//! Exit codes: 0 = no findings, 1 = findings reported, 2 = usage/config
//! error. Server checks degrade gracefully: with no credentials the local
//! classes still run and the skipped server classes are named.

use std::path::Path;
use std::process::ExitCode;

use crate::init::{detect_components, Component};
use rvl_data::project_config::load_project_config_from;

pub struct MigrateArgs {
    pub apply: bool,
}

/// One catalog row, as much of the list response as migrate needs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct CatalogRow {
    pub service_name: String,
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub contested: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingClass {
    LegacyCompound,
    Contested,
    Undeclared,
    SlugViolation,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub class: FindingClass,
    pub subject: String,
    pub detail: String,
    /// The concrete `.revelara.yaml` edit (or action) that resolves it.
    pub edit: String,
}

/// Mirror of the server's catalog slugify (internal/catalog/slug.go):
/// lowercase, trim, whitespace/underscore/hyphen runs to single hyphens,
/// everything outside [a-z0-9-] dropped, trimmed to 63 chars, "" when
/// fewer than 2 chars survive. No '/' special-casing, no affix stripping.
pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().to_lowercase().chars() {
        if c.is_whitespace() || c == '_' || c == '-' {
            out.push('-');
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        }
        // anything else (punctuation, '/', non-ascii) is dropped
    }
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let mut s = out.trim_matches('-').to_string();
    if s.len() > 63 {
        s = s[..63].trim_matches('-').to_string();
    }
    if s.len() < 2 {
        return String::new();
    }
    s
}

/// Pure classification: everything the report says, derived from the
/// declared config, the locally detected components, and the org catalog.
/// Separated from I/O so the report is unit-testable against a fixture
/// catalog (the mocked server).
pub fn classify(
    project: &str,
    declared: &[(String, String)], // (name, path)
    detected: &[Component],
    catalog: &[CatalogRow],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let declared_names: Vec<&str> = declared.iter().map(|(n, _)| n.as_str()).collect();

    // 1. Legacy compound identities for this project still on the server.
    let compound_prefix = format!("{project}/");
    for row in catalog {
        if let Some(tail) = row.service_name.strip_prefix(&compound_prefix) {
            let suggested = slugify(tail);
            findings.push(Finding {
                class: FindingClass::LegacyCompound,
                subject: row.service_name.clone(),
                detail: format!(
                    "the server still has the pre-v2 compound identity {:?} for this project",
                    row.service_name
                ),
                edit: format!(
                    "declare the component so future scans attribute to it directly:\n\
                     components:\n    - name: {suggested}\n      path: <path of {tail} in this repo>\n\
                     (the server-side migration converts the compound to a service + alias; historical risks follow)"
                ),
            });
        }
    }

    // 2. Contested (quarantined) services touching this repo: the project
    // itself or any declared component name.
    for row in catalog {
        if row.contested != Some(true) {
            continue;
        }
        let name = row.service_name.as_str();
        let slug = row.slug.as_deref().unwrap_or("");
        let touches = name == project
            || slug == slugify(project)
            || declared_names
                .iter()
                .any(|d| *d == name || slugify(d) == slug);
        if touches {
            findings.push(Finding {
                class: FindingClass::Contested,
                subject: row.service_name.clone(),
                detail: format!(
                    "service {:?} is contested: another repo claimed the same name and the claim is quarantined",
                    row.service_name
                ),
                edit: "resolve on the Services page (confirm the code move, or rename), or pick a more specific name in .revelara.yaml if this was a naming collision".to_string(),
            });
        }
    }

    // 3. Locally detected components that are not declared.
    for c in detected {
        let dup = declared
            .iter()
            .any(|(n, p)| n == &c.name || p.trim_end_matches('/') == c.path.trim_end_matches('/'));
        if !dup {
            findings.push(Finding {
                class: FindingClass::Undeclared,
                subject: c.name.clone(),
                detail: format!(
                    "component candidate detected at {:?} but not declared",
                    c.path
                ),
                edit: format!(
                    "if this is a service of its own, declare it (org-unique name):\n\
                     components:\n    - name: {}\n      path: {}",
                    slugify(&c.name),
                    c.path
                ),
            });
        }
    }

    // 4. Slug-format violations: names that will not survive slugify
    // unchanged (the server accepts them but canonicalizes; declaring the
    // slug form keeps what you see in the file identical to the catalog).
    let mut check_slug = |kind: &str, name: &str| {
        let slug = slugify(name);
        if slug.is_empty() {
            findings.push(Finding {
                class: FindingClass::SlugViolation,
                subject: name.to_string(),
                detail: format!("{kind} name {name:?} slugifies to nothing and the server will reject it"),
                edit: format!("rename the {kind} to a descriptive [a-z0-9-] name"),
            });
        } else if slug != name {
            findings.push(Finding {
                class: FindingClass::SlugViolation,
                subject: name.to_string(),
                detail: format!(
                    "{kind} name {name:?} is canonicalized to {slug:?} by the server"
                ),
                edit: format!("use the canonical form in .revelara.yaml: {slug}"),
            });
        }
    };
    check_slug("project", project);
    for (n, _) in declared {
        check_slug("component", n);
    }

    findings
}

fn class_label(c: &FindingClass) -> &'static str {
    match c {
        FindingClass::LegacyCompound => "legacy-compound",
        FindingClass::Contested => "contested",
        FindingClass::Undeclared => "undeclared",
        FindingClass::SlugViolation => "slug-violation",
    }
}

/// Fetch every catalog page. `Err` = server unavailable; the report
/// degrades to local-only checks and prints the reason.
fn fetch_catalog() -> Result<Vec<CatalogRow>, String> {
    let (_cfg, client) = rvl_data::client::load_and_resolve().map_err(|f| f.msg)?;
    #[derive(serde::Deserialize)]
    struct Page {
        #[serde(default)]
        services: Vec<CatalogRow>,
        #[serde(default)]
        next_cursor: Option<String>,
    }
    let mut rows = Vec::new();
    let mut cursor = String::new();
    loop {
        let url = if cursor.is_empty() {
            format!("{}/api/v1/catalog/services?limit=200", client.api_url)
        } else {
            format!(
                "{}/api/v1/catalog/services?limit=200&cursor={}",
                client.api_url, cursor
            )
        };
        let body = client.request("GET", &url, None)?;
        let page: Page =
            serde_json::from_slice(&body).map_err(|e| format!("bad catalog response: {e}"))?;
        rows.extend(page.services);
        match page.next_cursor {
            Some(c) if !c.is_empty() => cursor = c,
            _ => break,
        }
    }
    Ok(rows)
}

/// The comment-only candidates block `--apply` appends for undeclared
/// components: same shape init writes, so uncommenting declares.
fn candidates_block(undeclared: &[&Finding]) -> String {
    let mut out = String::from(
        "\n# rvl migrate: detected component candidates. Uncommenting declares\n\
         # them as org-unique services in the catalog. See /help/services.\n\
         # components:\n",
    );
    for f in undeclared {
        let path = f
            .detail
            .split('"')
            .nth(1)
            .unwrap_or("")
            .to_string();
        out.push_str(&format!(
            "#     - name: {}\n#       path: {}\n",
            slugify(&f.subject),
            path
        ));
    }
    out
}

pub fn run(args: MigrateArgs) -> ExitCode {
    let root = Path::new(".");
    let Some(cfg) = load_project_config_from(root) else {
        eprintln!("Error: no .revelara.yaml found (run `rvl init` first).");
        return ExitCode::from(2);
    };
    let declared: Vec<(String, String)> = cfg
        .components
        .iter()
        .map(|c| (c.name.clone(), c.path.clone()))
        .collect();
    let detected = detect_components(root);

    let catalog = fetch_catalog();
    let findings = classify(
        &cfg.project,
        &declared,
        &detected,
        catalog.as_deref().unwrap_or(&[]),
    );

    println!("rvl migrate report for project {:?}", cfg.project);
    if let Err(reason) = &catalog {
        println!(
            "  (server checks skipped - legacy-compound and contested not evaluated: {reason})"
        );
    }
    println!();

    if findings.is_empty() {
        println!("No findings. This repo is aligned with catalog v2.");
        return ExitCode::SUCCESS;
    }

    for f in &findings {
        println!("[{}] {}", class_label(&f.class), f.subject);
        println!("  {}", f.detail);
        for line in f.edit.lines() {
            println!("  fix: {line}");
        }
        println!();
    }

    let undeclared: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.class == FindingClass::Undeclared)
        .collect();
    if args.apply {
        if undeclared.is_empty() {
            println!("--apply: nothing to apply (only report-only findings).");
        } else {
            let block = candidates_block(&undeclared);
            match std::fs::OpenOptions::new()
                .append(true)
                .open(".revelara.yaml")
                .and_then(|mut fh| std::io::Write::write_all(&mut fh, block.as_bytes()))
            {
                Ok(()) => println!(
                    "--apply: appended {} commented candidate(s) to .revelara.yaml (uncomment to declare).",
                    undeclared.len()
                ),
                Err(e) => {
                    eprintln!("--apply failed: {e}");
                    return ExitCode::from(2);
                }
            }
        }
    } else if !undeclared.is_empty() {
        println!(
            "Run `rvl migrate --apply` to append the {} candidate declaration(s) above, commented out.",
            undeclared.len()
        );
    }

    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, slug: Option<&str>, contested: bool) -> CatalogRow {
        CatalogRow {
            service_name: name.into(),
            slug: slug.map(Into::into),
            contested: Some(contested),
        }
    }

    #[test]
    fn migrate_report() {
        // Fixture repo + mocked server: every finding class appears once,
        // each with its suggested YAML edit.
        let declared = vec![("Checkout API".to_string(), "services/checkout/".to_string())];
        let detected = vec![
            Component {
                name: "search".into(),
                path: "services/search/".into(),
            },
            Component {
                name: "checkout-api".into(),
                path: "services/checkout/".into(), // same path as declared: not a finding
            },
        ];
        let catalog = vec![
            row("shop/payments", None, false), // legacy compound
            row("checkout-api", Some("checkout-api"), true), // contested
            row("unrelated-svc", Some("unrelated-svc"), true), // contested but foreign
        ];
        let findings = classify("shop", &declared, &detected, &catalog);

        let classes: Vec<_> = findings.iter().map(|f| class_label(&f.class)).collect();
        assert!(classes.contains(&"legacy-compound"), "{classes:?}");
        assert!(classes.contains(&"contested"), "{classes:?}");
        assert!(classes.contains(&"undeclared"), "{classes:?}");
        assert!(classes.contains(&"slug-violation"), "{classes:?}");

        // The foreign contested service is NOT reported.
        assert!(
            !findings
                .iter()
                .any(|f| f.subject == "unrelated-svc"),
            "foreign contested service leaked into the report"
        );
        // Every finding carries a concrete edit.
        assert!(findings.iter().all(|f| !f.edit.is_empty()));
        // The compound's edit suggests the slugified tail.
        let compound = findings
            .iter()
            .find(|f| f.class == FindingClass::LegacyCompound)
            .unwrap();
        assert!(compound.edit.contains("name: payments"), "{}", compound.edit);
        // The slug violation names the canonical form.
        let slugv = findings
            .iter()
            .find(|f| f.class == FindingClass::SlugViolation)
            .unwrap();
        assert!(slugv.edit.contains("checkout-api"), "{}", slugv.edit);
    }

    #[test]
    fn migrate_report_clean_repo_zero_findings() {
        let declared = vec![("checkout-api".to_string(), "services/checkout/".to_string())];
        let detected = vec![Component {
            name: "checkout-api".into(),
            path: "services/checkout/".into(),
        }];
        let catalog = vec![row("checkout-api", Some("checkout-api"), false)];
        let findings = classify("shop", &declared, &detected, &catalog);
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn slugify_mirrors_server() {
        assert_eq!(slugify("Checkout API"), "checkout-api");
        assert_eq!(slugify("  a_b  c "), "a-b-c");
        assert_eq!(slugify("shop/payments"), "shoppayments"); // '/' dropped, no special-casing
        assert_eq!(slugify("x"), ""); // under 2 chars fails closed
        assert_eq!(slugify("already-canonical"), "already-canonical");
    }
}
