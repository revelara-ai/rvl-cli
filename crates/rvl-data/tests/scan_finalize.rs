//! `rvl scan finalize`: lens files and the engine document become the
//! `03-findings-*.json` submission parts. The fixtures and expected values
//! are the ones the scan skill's own tests held for the script this command
//! replaces.

use rvl_data::scan_finalize::{self, FinalizeArgs};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// A scan temp dir laid out as the scan skill prescribes: `<dir>` is what gets
/// submitted, and the lens files, engine document, patch and register sit
/// BESIDE it under the same name.
struct Fixture {
    _root: tempfile::TempDir,
    scan_dir: PathBuf,
}

fn write_json(path: &Path, v: &Value) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_vec(v).unwrap()).unwrap();
}

fn read_json(path: &Path) -> Value {
    let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&data).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[derive(Default)]
struct Opts<'a> {
    engine: bool,
    patch: bool,
    register: bool,
    mode: Option<&'a str>,
    crit: f64,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let scan_dir = root.path().join("scan-parts-abc");
        std::fs::create_dir_all(&scan_dir).unwrap();
        Fixture {
            _root: root,
            scan_dir,
        }
    }

    fn sibling(&self, suffix: &str) -> PathBuf {
        let mut s = self.scan_dir.clone().into_os_string();
        s.push(suffix);
        PathBuf::from(s)
    }

    fn components(&self, comps: Value) {
        write_json(
            &self.scan_dir.join("01-stack.json"),
            &json!({"repo_url": "git@github.com:acme/shop.git", "components": comps}),
        );
    }

    fn lens(&self, agent: &str, findings: Value) {
        write_json(
            &self.sibling(".lens").join(format!("{agent}.json")),
            &json!({"findings": findings}),
        );
    }

    fn try_finalize(&self, o: Opts) -> anyhow::Result<String> {
        let args = FinalizeArgs {
            scan_dir: self.scan_dir.clone(),
            engine: o.engine.then(|| self.sibling(".engine.json")),
            patch: o.patch.then(|| self.sibling(".patch.json")),
            register: o.register.then(|| self.sibling(".register.json")),
            mode: o.mode.unwrap_or("quick").to_string(),
            crit: o.crit,
        };
        let mut out = Vec::new();
        scan_finalize::run(&args, &mut out)?;
        Ok(String::from_utf8(out).unwrap())
    }

    fn finalize(&self, o: Opts) -> String {
        self.try_finalize(o)
            .unwrap_or_else(|e| panic!("finalize failed: {e:#}"))
    }

    fn doc(&self, agent: &str) -> Value {
        read_json(&self.scan_dir.join(format!("03-findings-{agent}.json")))
    }

    fn findings(&self, agent: &str) -> Vec<Value> {
        self.doc(agent)["findings"].as_array().unwrap().clone()
    }

    fn json_names(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.scan_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

fn finding(title: &str, location: &str) -> Value {
    let mut f = json!({"title": title, "severity": "medium", "risk_category": "availability", "description": title, "control_code": "RC-019"});
    if !location.is_empty() {
        f["location"] = json!(location);
    }
    f
}

#[test]
fn finalize_maps_lens_and_engine_rows_to_the_submission_schema() {
    let fx = Fixture::new();
    write_json(
        &fx.scan_dir.join("01-stack.json"),
        &json!({"components": [
            {"name": "backend", "path": "./internal"},
            {"name": "frontend", "path": "./frontend"},
        ]}),
    );
    write_json(
        &fx.sibling(".lens").join("golang-pro.json"),
        &json!({
            "findings": [
                {
                    "risk_category": "Data Integrity",
                    "severity": "critical",
                    "title": "Unbounded write",
                    "description": "Writes without a transaction.",
                    "remediation": "Wrap in a transaction.",
                    "location": {"file": "internal/api/h.go", "line": 10},
                    "evidence": "bare string evidence",
                    "control_code": "RC-019",
                    "causal_factors": "missing control path: no tx",
                    "uca_type": "not_provided",
                    "loss_scenario": "partial writes",
                },
                {
                    "risk_category": "performance",
                    "severity": "low",
                    "title": "Slow render",
                    "description": "Re-renders on every tick.",
                    "location": "frontend/src/x.ts:5",
                    "control_code": "RC-035",
                },
            ],
            "summary": {"total_findings": 2},
        }),
    );
    write_json(
        &fx.sibling(".lens").join("general-reviewer.json"),
        &json!({
            "findings": [{
                "risk_category": "availability", "severity": "medium", "title": "No graceful shutdown",
                "description": "SIGTERM kills in-flight work.",
                // A lens has no retrieval mechanism, so grounding it writes is
                // invented. Finalize must not carry it to the register.
                "corroboration": [{"type": "past_incident", "incident_id": "inc-invented", "relevance_score": 0.95}],
                "graph_evidence": {"impact_chains": ["invented -> chain"]},
            }],
            "adjudications": ["must never be submitted"],
        }),
    );
    write_json(
        &fx.sibling(".engine.json"),
        &json!({
            "schema": "rvl-scan/v1",
            "exit": 3,
            "covered_classes": ["http.Client"],
            "undecided": [],
            "coverage": {"resolved": 1, "total": 2, "abstain": 1},
            "findings": [
                {"id": "E1", "class": "http.Client", "site": "internal/x.go:3", "control": "RC-019", "fix": "set timeout", "description": "No client timeout", "severity": "blocking", "site_count": 2},
                {"id": "E2", "class": "retry", "site": "repo", "control": "RC-021", "fix": "add backoff", "description": "Retry without backoff", "severity": "advisory", "base_severity": "medium", "gate_exempt": true},
                {"id": "E3", "class": "x", "site": "internal/y.go:1", "control": "RC-019", "fix": "f", "description": "waived", "severity": "blocking", "suppressed": true},
            ],
        }),
    );
    write_json(
        &fx.sibling(".patch.json"),
        &json!({
            "findings": {
                "golang-pro#1": {
                    "control_codes": ["RC-019", "RC-020"],
                    "corroboration": [{"type": "past_incident", "incident_id": "inc-1", "relevance_score": 0.9}],
                    "corroboration_strength": 1.0,
                },
            },
            "drop": ["golang-pro#2"],
            "control_categories": {"RC-019": "fault_tolerance"},
            "catalog_meta": {"tier": "standard"},
        }),
    );

    let out = fx.finalize(Opts {
        engine: true,
        patch: true,
        mode: Some("quick"),
        crit: 0.6,
        ..Default::default()
    });
    let want = "\
Written: 03-findings-general-reviewer.json (1 findings)
Written: 03-findings-golang-pro.json (1 findings)
Written: 03-findings-engine.json (2 findings)
LENS_DIGEST (2 findings, score desc; ref PRIO score category site [controls] title):
  golang-pro#1 CRIT 100 data_integrity internal/api/h.go:10 [RC-019,RC-020] Unbounded write
  general-reviewer#1 MEDI 56 availability PROJECT [] No graceful shutdown
";
    assert_eq!(out, want);

    let golang = fx.doc("golang-pro");
    let rows = golang["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "patch drop not applied");
    let g = &rows[0];
    for (k, v) in [
        ("component", "backend"),
        ("provenance", "agent:golang-pro"),
        ("category", "data_integrity"),
        ("likelihood", "high"),
        ("impact", "high"),
        ("priority", "critical"),
        ("title", "Unbounded write"),
        ("uca_type", "not_provided"),
        ("loss_scenario", "partial writes"),
    ] {
        assert_eq!(g[k], json!(v), "golang-pro#1 {k}");
    }
    assert_eq!(g["risk_score"], json!(100), "capped at 100");
    assert_eq!(g["control_codes"], json!(["RC-019", "RC-020"]));
    assert_eq!(
        g["narrative"],
        json!("Writes without a transaction. Remediation: Wrap in a transaction.")
    );
    assert_eq!(
        g["evidence"],
        json!([
            {"type": "code", "path": "internal/api/h.go", "line_number": 10, "description": "Unbounded write"},
            {"type": "code", "description": "bare string evidence"},
        ])
    );
    assert_eq!(
        g["substantiation"],
        json!([{"type": "code_location", "location": "internal/api/h.go", "line": 10}])
    );
    assert_eq!(
        g["causal_factors"],
        json!(["missing control path: no tx"]),
        "a string is coerced to an array"
    );
    assert_eq!(
        g["corroboration"],
        json!([{"type": "past_incident", "incident_id": "inc-1", "relevance_score": 0.9}])
    );
    assert!(
        golang.get("summary").is_none(),
        "the lens summary block must not reach the submission"
    );
    assert_eq!(golang["business_criticality"], json!(0.6));
    assert_eq!(golang["scan_mode"], json!("quick"));
    assert_eq!(golang["catalog_meta"], json!({"tier": "standard"}));

    let general = fx.doc("general-reviewer");
    assert!(
        general.get("adjudications").is_none(),
        "adjudications are report-only and must never be submitted"
    );
    let gr = &general["findings"][0];
    assert_eq!(general["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        gr["component"],
        json!("backend"),
        "a pathless finding falls back to the first component"
    );
    assert_eq!(gr["provenance"], json!("agent:general-reviewer"));
    // Grounding comes from the patch alone. This finding has no patch entry,
    // so what the lens wrote must be gone.
    assert_eq!(gr["corroboration"], json!([]));
    assert_eq!(gr["graph_evidence"], Value::Null);
    assert_eq!(gr["substantiation"], json!([]));
    assert_eq!(gr["evidence"], json!([]));
    // medium x medium = 49; x1.0 corroboration x1.0 substantiation x1.15
    // criticality = 56.35.
    assert_eq!(gr["risk_score"], json!(56));
    assert_eq!(gr["priority"], json!("medium"));

    let engine = fx.findings("engine");
    assert_eq!(engine.len(), 2, "suppressed engine rows are excluded");
    assert_eq!(
        engine[0],
        json!({
            "provenance": "engine", "title": "No client timeout",
            "narrative": "No client timeout. Engine class http.Client at internal/x.go:3 (2 sites). Fix: set timeout",
            "category": "fault_tolerance", "control_codes": ["RC-019"],
            "likelihood": "high", "impact": "high", "risk_score": 75, "priority": "high",
            "substantiation": [{"type": "engine_site", "location": "internal/x.go", "line": 3}],
            "evidence": [{"type": "code", "description": "engine-resolved site", "path": "internal/x.go", "line_number": 3}],
            "component": "backend",
        })
    );
    assert_eq!(
        engine[1],
        json!({
            "provenance": "engine", "title": "Retry without backoff",
            "narrative": "Retry without backoff. Engine class retry at repo (1 sites). Fix: add backoff (gate-exempt)",
            "category": "availability", "control_codes": ["RC-021"],
            "likelihood": "medium", "impact": "medium", "risk_score": 45, "priority": "medium",
            "substantiation": [],
            "evidence": [{"type": "code", "description": "engine-resolved site"}],
            "component": "backend",
        })
    );

    // The CLI submits every *.json in the submit dir.
    for n in fx.json_names() {
        assert!(
            n == "01-stack.json" || n.starts_with("03-findings-"),
            "unexpected file {n} in the submit dir"
        );
    }

    // Rerun without the patch: output is rebuilt from the raw lens files, so
    // the dropped finding returns and the retired RC-035 code is stripped.
    fx.finalize(Opts {
        mode: Some("deep"),
        ..Default::default()
    });
    let golang = fx.doc("golang-pro");
    let rows = golang["findings"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "finalize rebuilds from the raw lens files");
    assert_eq!(rows[1]["control_codes"], json!([]), "retired RC-035");
    assert_eq!(rows[1]["component"], json!("frontend"));
    assert_eq!(golang["business_criticality"], json!(0.0));
    assert_eq!(golang["scan_mode"], json!("deep"));
    assert!(golang.get("catalog_meta").is_none());
    assert!(
        !fx.scan_dir.join("03-findings-engine.json").exists(),
        "a run without an engine document must not leave a stale engine findings file"
    );
}

/// Runs finalize over one lens file holding a finding per path, and returns
/// the component each finding landed on. A finding with no component field
/// maps to "".
fn components_by_title(fx: &Fixture, paths: &[&str]) -> BTreeMap<String, String> {
    fx.lens(
        "golang-pro",
        Value::Array(paths.iter().map(|p| finding(p, p)).collect()),
    );
    fx.finalize(Opts::default());
    fx.findings("golang-pro")
        .iter()
        .map(|row| {
            (
                row["title"].as_str().unwrap().to_string(),
                row.get("component")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect()
}

#[test]
fn component_is_the_longest_matching_prefix() {
    // Name, the components of the stack file, and finding path to component.
    type Case = (&'static str, Value, Vec<(&'static str, &'static str)>);
    let cases: Vec<Case> = vec![
        (
            // The shorter prefix is declared first, so a first-match
            // implementation fails the nested cases.
            "nested prefixes with a root component",
            json!([
                {"name": "backend", "path": "./internal"},
                {"name": "api", "path": "internal/api/"},
                {"name": "frontend", "path": "frontend"},
                {"name": "repo", "path": "."},
            ]),
            vec![
                ("internal/api/handlers.go:10", "api"),
                ("./internal/api/handlers.go:11", "api"),
                ("internal/api", "api"),
                // A prefix ends at a path separator.
                ("internal/apix/handlers.go:12", "backend"),
                ("internal/db/pool.go:13", "backend"),
                ("frontend/src/app.ts:14", "frontend"),
                ("frontendx/src/app.ts:15", "repo"),
                // Root matches what no other prefix does.
                ("scripts/deploy.sh:16", "repo"),
                // A repo-wide finding with no location.
                ("", "repo"),
            ],
        ),
        (
            "no root component falls back to the first component",
            json!([
                {"name": "backend", "path": "cmd/server/"},
                {"name": "worker", "path": "cmd/worker/"},
            ]),
            vec![
                ("cmd/worker/main.go:1", "worker"),
                ("cmd/server/main.go:2", "backend"),
                ("cmd/eval/main.go:3", "backend"),
                ("", "backend"),
            ],
        ),
        (
            "a component without a path never matches by prefix",
            json!([{"name": "backend", "path": "internal"}, {"name": "pathless"}]),
            vec![("internal/x.go:1", "backend"), ("docs/x.md:2", "backend")],
        ),
        (
            "no components declared, no component field",
            Value::Null,
            vec![("internal/x.go:1", "")],
        ),
    ];
    for (name, comps, want) in cases {
        let fx = Fixture::new();
        fx.components(comps);
        let paths: Vec<&str> = want.iter().map(|(p, _)| *p).collect();
        let got = components_by_title(&fx, &paths);
        for (p, c) in want {
            assert_eq!(got[p], c, "{name}: finding at {p:?}");
        }
    }
}

/// The documented `--scan-dir` contract applied to `paths` in order: array
/// fields concatenate, scalar and object fields are last writer wins.
fn merge_scan_dir(paths: &[PathBuf]) -> serde_json::Map<String, Value> {
    let mut merged = serde_json::Map::new();
    for p in paths {
        let Value::Object(doc) = read_json(p) else {
            panic!("{} is not an object", p.display());
        };
        for (k, v) in doc {
            match (merged.get_mut(&k), v) {
                (Some(Value::Array(prev)), Value::Array(arr)) => prev.extend(arr),
                (_, v) => {
                    merged.insert(k, v);
                }
            }
        }
    }
    merged
}

#[test]
fn per_lens_files_merge_to_one_union() {
    let fx = Fixture::new();
    fx.components(json!([{"name": "backend", "path": "internal"}]));
    let shared = finding("HTTP client has no timeout", "internal/client.go:20");
    fx.lens(
        "golang-pro",
        json!([
            shared,
            finding("Unbounded goroutine fan-out", "internal/fanout.go:8")
        ]),
    );
    fx.lens("resilience-pro", json!([shared]));
    fx.lens(
        "general-reviewer",
        json!([
            shared,
            finding("io.ReadAll without a limit", "internal/read.go:3")
        ]),
    );
    write_json(
        &fx.sibling(".engine.json"),
        &json!({
            "schema": "rvl-scan/v1",
            "findings": [
                {"id": "E1", "class": "http.Client", "site": "internal/client.go:20", "control": "RC-019", "fix": "set timeout", "description": "No client timeout", "severity": "blocking"},
            ],
        }),
    );
    write_json(
        &fx.sibling(".patch.json"),
        &json!({"catalog_meta": {"tier": "standard"}}),
    );
    fx.finalize(Opts {
        engine: true,
        patch: true,
        mode: Some("deep"),
        crit: 0.6,
        ..Default::default()
    });

    let names = fx.json_names();
    assert_eq!(
        names,
        [
            "01-stack.json",
            "03-findings-engine.json",
            "03-findings-general-reviewer.json",
            "03-findings-golang-pro.json",
            "03-findings-resilience-pro.json"
        ],
        "one findings file per lens plus the engine"
    );
    let files: Vec<PathBuf> = names.iter().map(|n| fx.scan_dir.join(n)).collect();
    let forward = merge_scan_dir(&files);
    let reversed: Vec<PathBuf> = files.iter().rev().cloned().collect();
    let backward = merge_scan_dir(&reversed);

    // Last writer wins is only safe when every writer agrees.
    for (k, v) in &forward {
        if !v.is_array() {
            assert_eq!(
                Some(v),
                backward.get(k),
                "scalar field {k:?} depends on file order"
            );
        }
    }
    assert_eq!(forward["scan_mode"], json!("deep"));
    assert_eq!(forward["business_criticality"], json!(0.6));
    assert_eq!(forward["repo_url"], json!("git@github.com:acme/shop.git"));
    assert_eq!(
        forward["components"].as_array().unwrap().len(),
        1,
        "the findings files must not add or clobber components"
    );

    // The union keeps every row: no local cross-lens dedup.
    let rows = forward["findings"].as_array().unwrap();
    let mut by_provenance: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows {
        *by_provenance
            .entry(
                row["provenance"]
                    .as_str()
                    .expect("every row has a provenance"),
            )
            .or_default() += 1;
    }
    assert_eq!(
        by_provenance,
        BTreeMap::from([
            ("agent:general-reviewer", 2),
            ("agent:golang-pro", 2),
            ("agent:resilience-pro", 1),
            ("engine", 1)
        ])
    );
    let shared_rows = rows
        .iter()
        .filter(|r| r["title"] == shared["title"])
        .count();
    assert_eq!(
        shared_rows, 3,
        "a defect three lenses reported stays three rows"
    );
    assert_eq!(backward["findings"].as_array().unwrap().len(), rows.len());
}

#[test]
fn extends_takes_the_register_identity() {
    let fx = Fixture::new();
    fx.lens(
        "golang-pro",
        json!([
            finding(
                "No preStop drain: SIGTERM shutdown starts before endpoints are removed",
                "cmd/server/main.go:179"
            ),
            finding("Unbounded goroutine fan-out", "internal/fanout.go:8"),
        ]),
    );
    fx.lens(
        "resilience-pro",
        json!([
            finding(
                "No preStop hook: backend endpoints race SIGTERM during rollouts",
                "k8s/base/backend-deployment.yml:92"
            ),
            finding(
                "Rate limiter trusts X-Forwarded-For",
                "internal/middleware/rate_limit.go:99"
            ),
        ]),
    );
    write_json(
        &fx.sibling(".register.json"),
        &json!({"risks": [
            {"risk_code": "R-038", "title": "No preStop hook or connection-drain delay on any deployment", "control_codes": ["RC-018"]},
            {"risk_code": "R-090", "title": "Per-IP rate limiter trusts the leftmost X-Forwarded-For value", "control_codes": []},
        ]}),
    );
    write_json(
        &fx.sibling(".patch.json"),
        &json!({"findings": {
            "golang-pro#1": {"control_codes": ["RC-018", "RC-014"], "extends": "R-038"},
            "resilience-pro#1": {"control_codes": ["RC-018", "RC-014"], "extends": "R-038"},
            "resilience-pro#2": {"control_codes": ["RC-069"], "extends": "R-090"},
            "golang-pro#2": {"extends": "R-999"},
        }}),
    );
    let out = fx.finalize(Opts {
        patch: true,
        register: true,
        ..Default::default()
    });
    let want = "\
UNKNOWN golang-pro#2 extends R-999: kept as new
Written: 03-findings-golang-pro.json (2 findings)
DUP resilience-pro#1 extends R-038, kept by golang-pro#1: dropped
Written: 03-findings-resilience-pro.json (1 findings)
LENS_DIGEST (3 findings, score desc; ref PRIO score category site [controls] title):
  golang-pro#1 MEDI 49 availability cmd/server/main.go:179 [RC-018] No preStop drain: SIGTERM shutdown starts before endpoints are removed extends R-038
  golang-pro#2 MEDI 49 availability internal/fanout.go:8 [RC-019] Unbounded goroutine fan-out
  resilience-pro#2 MEDI 49 availability internal/middleware/rate_limit.go:99 [RC-069] Rate limiter trusts X-Forwarded-For extends R-090
";
    assert_eq!(out, want);

    let golang = fx.findings("golang-pro");
    assert_eq!(golang.len(), 2);
    // An extending finding carries the register risk's title and control
    // codes, and the lens's own wording stays in the narrative.
    assert_eq!(
        golang[0]["title"],
        json!("No preStop hook or connection-drain delay on any deployment")
    );
    assert_eq!(golang[0]["control_codes"], json!(["RC-018"]));
    assert!(golang[0]["narrative"]
        .as_str()
        .unwrap()
        .contains("No preStop drain"));
    // A risk code the register does not hold changes nothing.
    assert_eq!(golang[1]["title"], json!("Unbounded goroutine fan-out"));

    // Two findings on one risk in one submission: the server applies the
    // first and rejects the second as a conflict. Finalize keeps one.
    let resilience = fx.findings("resilience-pro");
    assert_eq!(resilience.len(), 1);
    // A register risk with no control codes: the title is taken, and the
    // grounded codes stay.
    assert_eq!(
        resilience[0]["title"],
        json!("Per-IP rate limiter trusts the leftmost X-Forwarded-For value")
    );
    assert_eq!(resilience[0]["control_codes"], json!(["RC-069"]));
}

#[test]
fn an_engine_row_with_no_control_sends_no_code() {
    let fx = Fixture::new();
    write_json(
        &fx.sibling(".engine.json"),
        &json!({
            "schema": "rvl-scan/v1",
            "findings": [
                {"id": "vsm6", "class": "subprocess.run", "site": "scripts/x.py:78", "control": "", "fix": "", "description": "subprocess.run has no timeout", "severity": "advisory"},
                {"id": "E1", "class": "http.Client", "site": "internal/x.go:3", "control": "RC-019", "fix": "set timeout", "description": "No client timeout", "severity": "blocking"},
            ],
        }),
    );
    let out = fx.finalize(Opts {
        engine: true,
        ..Default::default()
    });
    assert_eq!(
        out,
        "Written: 03-findings-engine.json (2 findings)\n\
         LENS_DIGEST (0 findings, score desc; ref PRIO score category site [controls] title):\n"
    );
    let rows = fx.findings("engine");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["control_codes"], json!([]));
    assert_eq!(rows[0]["risk_score"], json!(25));
    assert_eq!(rows[0]["priority"], json!("low"));
    assert!(rows[0].get("component").is_none());
    assert_eq!(rows[1]["control_codes"], json!(["RC-019"]));
}

#[test]
fn a_refused_engine_document_leaves_the_submit_dir_as_it_was() {
    let fx = Fixture::new();
    fx.lens("golang-pro", json!([finding("A", "a.go:1")]));
    fx.finalize(Opts::default());
    let before = std::fs::read(fx.scan_dir.join("03-findings-golang-pro.json")).unwrap();

    fx.lens("golang-pro", json!([finding("B", "b.go:2")]));
    write_json(
        &fx.sibling(".engine.json"),
        &json!({"schema": "rvl-scan/v2"}),
    );
    let err = fx
        .try_finalize(Opts {
            engine: true,
            ..Default::default()
        })
        .unwrap_err();
    assert!(format!("{err:#}").contains("rvl-scan/v2"), "{err:#}");
    assert_eq!(
        std::fs::read(fx.scan_dir.join("03-findings-golang-pro.json")).unwrap(),
        before,
        "a run that fails on its inputs must not delete or rewrite a findings file"
    );
    assert_eq!(fx.json_names(), ["03-findings-golang-pro.json"]);
}

#[test]
fn an_unparseable_lens_file_is_named_and_the_others_are_written() {
    let fx = Fixture::new();
    fx.lens("golang-pro", json!([finding("A", "a.go:1")]));
    std::fs::write(fx.sibling(".lens").join("broken.json"), "{not json").unwrap();
    // A file that is not a lens output at all.
    std::fs::write(fx.sibling(".lens").join("notes.txt"), "x").unwrap();
    let out = fx.finalize(Opts::default());
    assert!(
        out.lines().next().unwrap().starts_with(&format!(
            "INVALID {}: ",
            fx.sibling(".lens").join("broken.json").display()
        )),
        "{out}"
    );
    assert_eq!(fx.json_names(), ["03-findings-golang-pro.json"]);
}

#[test]
fn score_keeps_the_reference_rounding_and_default_corroboration_strength() {
    let fx = Fixture::new();
    let mut high = finding("H", "a.go:1");
    high["severity"] = json!("high");
    let mut low_high = finding("LH", "b.go:2");
    low_high["likelihood"] = json!("low");
    low_high["impact"] = json!("high");
    let mut low_low = finding("LL", "d.go:4");
    low_low["likelihood"] = json!("low");
    low_low["impact"] = json!("low");
    fx.lens(
        "golang-pro",
        json!([high, low_high, finding("M", "c.go:3"), low_low]),
    );
    write_json(
        &fx.sibling(".patch.json"),
        &json!({"findings": {
            // count 2, top relevance 0.8: min(1, 2/5 x 0.3 + 0.8 x 0.4) = 0.44.
            "golang-pro#1": {"corroboration": [{"relevance_score": 0.5}, {"relevance_score": 0.8}], "substantiation_strength": 1.0},
            "golang-pro#3": {"corroboration_strength": 0.0},
        }}),
    );
    let scores = |crit: f64| -> Vec<(i64, String)> {
        fx.finalize(Opts {
            patch: true,
            crit,
            ..Default::default()
        });
        fx.findings("golang-pro")
            .iter()
            .map(|r| {
                (
                    r["risk_score"].as_i64().unwrap(),
                    r["priority"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    };
    let p = |n: i64, s: &str| (n, s.to_string());
    // high x medium = 70; x1.132 x1.2 x1.5 = 142.6, capped. 40 x 1.5 = 60.
    // 49 x 1.5 = 73.5 and 16 x 1.5 = 24.
    assert_eq!(
        scores(2.0),
        [
            p(100, "critical"),
            p(60, "high"),
            p(74, "high"),
            p(24, "low")
        ]
    );
    // Criticality 0.125 is a factor of 1.03125: 70 x 1.132 x 1.2 = 95.088,
    // then 98.06. 41.25. 50.53. 16.5 is a tie, and a tie rounds to the even
    // number: 16, not 17.
    assert_eq!(
        scores(0.125),
        [
            p(98, "critical"),
            p(41, "medium"),
            p(51, "medium"),
            p(16, "low")
        ]
    );
}
