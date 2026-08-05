//! Golden packet tests for the cindex helper, run over the checked-in
//! fixtures. Engine-dependent tests SKIP (with a log line) when no libclang
//! can be loaded — the workspace must build and test on machines without a
//! C toolchain; provisioning the engine is an environment concern.

use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cindex"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("testdata")
        .join(name)
}

/// True when the runtime engine loads; otherwise logs a SKIP line.
fn engine_available(test: &str) -> bool {
    let out = bin().arg("--engine-check").output().expect("run cindex");
    if out.status.success() {
        return true;
    }
    eprintln!(
        "SKIP {test}: no libclang available: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    false
}

/// Run `cindex --retrieve` over a fixture and split the JSONL stream into
/// site records and repo-scoped (kind-tagged) records.
fn retrieve(
    dir: &std::path::Path,
    files: &[&str],
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let mut cmd = bin();
    cmd.arg("--retrieve")
        .arg("--root")
        .arg(dir)
        .arg("--name")
        .arg("fixture");
    if !files.is_empty() {
        cmd.arg("--files").arg(files.join(","));
    }
    let out = cmd.output().expect("run cindex");
    assert!(
        out.status.success(),
        "cindex failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8 stdout");
    let mut sites = Vec::new();
    let mut records = Vec::new();
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSONL line ({e}): {line}"));
        if v.get("kind").is_some() {
            records.push(v);
        } else {
            sites.push(v);
        }
    }
    (sites, records)
}

fn sites_with_method<'a>(
    sites: &'a [serde_json::Value],
    method: &str,
) -> Vec<&'a serde_json::Value> {
    sites
        .iter()
        .filter(|s| s["func"].as_str() == Some(method))
        .collect()
}

fn stats(records: &[serde_json::Value]) -> &serde_json::Value {
    records
        .iter()
        .find(|r| r["kind"].as_str() == Some("retrieval_stats"))
        .expect("a retrieval_stats record must ride the stream")
}

#[test]
fn packet_schema_flag_negotiates_v2() {
    // No engine needed: version negotiation must work everywhere.
    let out = bin().arg("--packet-schema").output().expect("run cindex");
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "2");
}

#[test]
fn c_fixture_emits_the_planted_g1_sites_with_const_args_and_macro_flag() {
    if !engine_available("c_fixture_emits_the_planted_g1_sites_with_const_args_and_macro_flag") {
        return;
    }
    let (sites, records) = retrieve(&fixture("fixture-c"), &[]);

    // Contract basics on every site record.
    for s in &sites {
        assert_eq!(s["packet_schema"].as_u64(), Some(2), "schema stamp: {s}");
        assert_eq!(s["lang"].as_str(), Some("c_cpp"), "lang stamp: {s}");
        assert!(
            s["site_key"].as_str().is_some_and(|k| !k.is_empty()),
            "site_key present: {s}"
        );
        assert!(
            s["file_path"].as_str().is_some_and(|p| !p.contains('\\')),
            "file_path forward-slashed: {s}"
        );
    }
    // site_key unique across the stream.
    let mut keys: Vec<&str> = sites
        .iter()
        .filter_map(|s| s["site_key"].as_str())
        .collect();
    let total = keys.len();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), total, "site_key must be unique");

    // The CURLOPT_TIMEOUT discrimination: the setopt site carries the enum
    // constant NAME as a named_constant const_arg, plus the literal 30.
    let setopts = sites_with_method(&sites, "curl_easy_setopt");
    assert_eq!(setopts.len(), 2, "both planted setopt sites: {sites:?}");
    let timeout_site = setopts
        .iter()
        .find(|s| {
            s["const_args"]
                .as_array()
                .is_some_and(|a| a.iter().any(|c| c["value"] == "CURLOPT_TIMEOUT"))
        })
        .expect("a setopt site carrying CURLOPT_TIMEOUT in const_args");
    let cargs = timeout_site["const_args"].as_array().unwrap();
    let opt = cargs
        .iter()
        .find(|c| c["value"] == "CURLOPT_TIMEOUT")
        .unwrap();
    assert_eq!(opt["how"], "named_constant");
    assert_eq!(opt["index"], 1);
    let lit = cargs
        .iter()
        .find(|c| c["how"] == "literal" && c["value"] == "30")
        .expect("the literal 30 rides const_args");
    assert_eq!(lit["index"], 2);
    assert_eq!(timeout_site["client_type"], "libcurl.CURL");
    assert_eq!(timeout_site["symbol"], "fetch_users");
    assert!(
        timeout_site["snippet"]
            .as_str()
            .is_some_and(|s| s.contains("curl_easy_setopt")),
        "snippet carries the call source: {timeout_site}"
    );
    assert_eq!(
        timeout_site["provenance"]["client_type_resolved"], true,
        "compile-db sites are high tier"
    );

    // The URL setopt discriminates the other way.
    assert!(
        setopts.iter().any(|s| {
            s["const_args"]
                .as_array()
                .is_some_and(|a| a.iter().any(|c| c["value"] == "CURLOPT_URL"))
        }),
        "the CURLOPT_URL setopt site carries its enum constant"
    );

    // macro_expansion is mechanical: the direct perform is false, the
    // CHECKED_PERFORM-wrapped one is true.
    let performs = sites_with_method(&sites, "curl_easy_perform");
    assert_eq!(performs.len(), 2, "both perform sites: {sites:?}");
    let flags: Vec<bool> = performs
        .iter()
        .map(|s| s["macro_expansion"].as_bool().unwrap_or_default())
        .collect();
    assert!(
        flags.iter().filter(|f| **f).count() == 1,
        "exactly one perform site sits in a macro expansion: {performs:?}"
    );
    let wrapped = performs
        .iter()
        .find(|s| s["macro_expansion"] == true)
        .unwrap();
    assert_eq!(wrapped["symbol"], "wrapped");

    // The other planted client families.
    assert_eq!(
        sites_with_method(&sites, "PQexec")[0]["client_type"],
        "libpq.PGconn"
    );
    assert!(!sites_with_method(&sites, "PQconnectdb").is_empty());
    assert_eq!(
        sites_with_method(&sites, "redisCommand")[0]["client_type"],
        "hiredis.redisContext"
    );
    assert!(!sites_with_method(&sites, "redisConnect").is_empty());
    assert_eq!(
        sites_with_method(&sites, "connect")[0]["client_type"],
        "posix.socket"
    );
    assert_eq!(
        sites_with_method(&sites, "recv")[0]["client_type"],
        "posix.socket"
    );
    // Noise stays out: PQclear/curl_easy_cleanup/curl_easy_init are not I/O
    // call sites.
    assert!(sites_with_method(&sites, "PQclear").is_empty());
    assert!(sites_with_method(&sites, "curl_easy_cleanup").is_empty());
    assert!(sites_with_method(&sites, "curl_easy_init").is_empty());

    // The stats record: one TU, parsed, compile-db mode.
    let st = stats(&records);
    assert_eq!(st["mode"], "compile_db");
    assert_eq!(st["tus_total"], 1);
    assert_eq!(st["tus_parsed"], 1);
    assert_eq!(st["tus_failed"], 0);
}

#[test]
fn cpp_fixture_tiers_virtual_dispatch_and_abstains_on_templates() {
    if !engine_available("cpp_fixture_tiers_virtual_dispatch_and_abstains_on_templates") {
        return;
    }
    let (sites, _records) = retrieve(&fixture("fixture-cpp"), &[]);

    // Virtual dispatch: emitted at the STATIC interface identity, mid tier =
    // callee_candidates counts the in-TU definitions (base + 2 overriders).
    let fetches = sites_with_method(&sites, "fetch");
    assert_eq!(fetches.len(), 1, "one virtual dispatch site: {sites:?}");
    let fetch = fetches[0];
    assert_eq!(fetch["client_type"], "app::Backend");
    assert_eq!(fetch["provenance"]["client_type_resolved"], true);
    assert_eq!(
        fetch["provenance"]["callee_candidates"], 3,
        "mid tier: virtual dispatch reports its definition ambiguity: {fetch}"
    );

    // gRPC-style stub identity.
    let hello = sites_with_method(&sites, "SayHello");
    assert_eq!(hello.len(), 1, "the stub call is emitted: {sites:?}");
    assert_eq!(hello[0]["client_type"], "helloworld::Greeter::Stub");

    // The uninstantiated template's dependent callee is an abstention, not a
    // guess: no site from generic_talk.
    assert!(
        sites_with_method(&sites, "query").is_empty(),
        "dependent template callee must not be emitted: {sites:?}"
    );
    assert!(
        !sites.iter().any(|s| s["symbol"] == "generic_talk"),
        "nothing emitted from the uninstantiated template body"
    );
}

#[test]
fn no_db_fallback_is_the_extern_c_allowlist_at_low_tier() {
    if !engine_available("no_db_fallback_is_the_extern_c_allowlist_at_low_tier") {
        return;
    }
    let (sites, records) = retrieve(&fixture("fixture-nodb"), &[]);

    let performs = sites_with_method(&sites, "curl_easy_perform");
    assert_eq!(
        performs.len(),
        1,
        "the allowlisted call is emitted: {sites:?}"
    );
    assert_eq!(performs[0]["client_type"], "libcurl.CURL");
    assert_eq!(
        performs[0]["provenance"]["client_type_resolved"], false,
        "no-db sites are LOW tier: {}",
        performs[0]
    );
    // Off-allowlist calls abstain.
    assert!(
        sites_with_method(&sites, "helper_step").is_empty(),
        "non-allowlisted calls must not be emitted: {sites:?}"
    );
    // C++ without a compile db is a documented abstention class.
    assert!(
        !sites
            .iter()
            .any(|s| s["file_path"].as_str().is_some_and(|p| p.ends_with(".cpp"))),
        "no packets from C++ files without a compile db: {sites:?}"
    );
    let st = stats(&records);
    assert_eq!(st["mode"], "allowlist");
    assert_eq!(st["cpp_files_skipped_no_db"], 1);
}

#[test]
fn files_filter_restricts_emission_to_the_named_files() {
    if !engine_available("files_filter_restricts_emission_to_the_named_files") {
        return;
    }
    let (sites, _) = retrieve(&fixture("fixture-c"), &["src/main.c"]);
    assert!(!sites.is_empty(), "the named TU emits");
    let (none, _) = retrieve(&fixture("fixture-c"), &["src/other.c"]);
    assert!(
        none.is_empty(),
        "a filter naming no real TU emits nothing: {none:?}"
    );
}

#[test]
fn unparseable_tus_are_counted_never_guessed() {
    if !engine_available("unparseable_tus_are_counted_never_guessed") {
        return;
    }
    // A compile db naming a missing file: the TU fails, the failure is
    // COUNTED, and the run still exits 0 (degrade coverage, don't abort).
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compile_commands.json"),
        r#"[{"directory":".","command":"cc -c src/gone.c","file":"src/gone.c"}]"#,
    )
    .unwrap();
    let (sites, records) = retrieve(dir.path(), &[]);
    assert!(sites.is_empty());
    let st = stats(&records);
    assert_eq!(st["tus_total"], 1);
    assert_eq!(st["tus_failed"], 1);
}
