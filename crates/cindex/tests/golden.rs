//! Golden packet tests for the cindex helper, run over the checked-in
//! fixtures. Engine-dependent tests SKIP (with a log line) when no libclang
//! can be loaded — the workspace must build and test on machines without a
//! C toolchain; provisioning the engine is an environment concern.

use std::path::PathBuf;
use std::process::Command;

/// The crate directory, read at run time. `cargo test` sets CARGO_MANIFEST_DIR
/// for every test process; a binary reused from a shared CARGO_TARGET_DIR still
/// carries the compile-time path of whichever checkout built it, which may be gone.
fn manifest_dir() -> std::path::PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .unwrap_or_else(|| env!("CARGO_MANIFEST_DIR").into())
        .into()
}

/// Locate the `cindex` executable.
///
/// It is NOT a bin of this package — it is a bin of `rvl`
/// (`crates/rvl/src/bin/cindex.rs`), so release packaging can pack it beside
/// `rvl`; see the note at the top of `src/lib.rs`. That means
/// `CARGO_BIN_EXE_cindex` does not exist here, so the binary is found the only
/// way a non-owning package can: walk up from this test executable
/// (`target/<profile>/deps/golden-<hash>`) to the profile directory, where
/// cargo puts every workspace bin.
fn bin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("test executable path");
    let profile_dir = exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("target/<profile> directory");
    profile_dir.join(if cfg!(windows) {
        "cindex.exe"
    } else {
        "cindex"
    })
}

fn bin() -> Command {
    let path = bin_path();
    assert!(
        path.is_file(),
        "cindex is not built at {} — it is a bin of the `rvl` package, so build it with \
         `cargo build -p rvl --bin cindex` (a plain `cargo build --workspace` also does it)",
        path.display()
    );
    Command::new(path)
}

fn fixture(name: &str) -> PathBuf {
    manifest_dir().join("testdata").join(name)
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

    // The stats record: both TUs (main.c, workers.c) parsed, compile-db mode.
    let st = stats(&records);
    assert_eq!(st["mode"], "compile_db");
    assert_eq!(st["tus_total"], 2);
    assert_eq!(st["tus_parsed"], 2);
    assert_eq!(st["tus_failed"], 0);
    // Every header resolves, so this is a genuinely clean parse, and the
    // stats must say so in the terms the missing-header case uses.
    assert_eq!(st["tus_incomplete"], 0, "clean parse: {st}");
    assert_eq!(st["includes_missing"], 0, "clean parse: {st}");
    assert_eq!(st["decls_unresolved"], 0, "clean parse: {st}");
    assert!(
        st.get("calls_unresolved").is_none(),
        "the old name read as a completeness claim and is gone: {st}"
    );
}

#[test]
fn cpp_fixture_tiers_virtual_dispatch_and_abstains_on_templates() {
    if !engine_available("cpp_fixture_tiers_virtual_dispatch_and_abstains_on_templates") {
        return;
    }
    let (sites, records) = retrieve(&fixture("fixture-cpp"), &[]);

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
    // The dependent callee is counted where it belongs: a call clang formed
    // whose callee did not resolve. It is not a parse error, so the TU stays
    // complete.
    let st = stats(&records);
    assert!(
        st["calls_callee_unresolved"]
            .as_u64()
            .is_some_and(|n| n >= 1),
        "the dependent call is counted: {st}"
    );
    assert_eq!(
        st["tus_incomplete"], 0,
        "templates are not a parse error: {st}"
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
    // The G3 registration rides the same allowlist, at the same low tier.
    let threads = sites_with_method(&sites, "pthread_create");
    assert_eq!(threads.len(), 1, "the allowlisted registration: {sites:?}");
    assert_eq!(threads[0]["site_kind"], "background_job");
    assert_eq!(threads[0]["provenance"]["client_type_resolved"], false);
}

/// G3 (po-av01j.51): `pthread_create` is a background-job REGISTRATION. The
/// retriever reports where the thread starts and nothing about the loop it
/// runs; the lifecycle calls around it are not sites, and the classic G1
/// sites in the same repo carry no `site_kind` key.
#[test]
fn c_fixture_emits_pthread_create_as_a_background_job_site() {
    if !engine_available("c_fixture_emits_pthread_create_as_a_background_job_site") {
        return;
    }
    let (sites, _records) = retrieve(&fixture("fixture-c"), &[]);

    let jobs: Vec<&serde_json::Value> = sites
        .iter()
        .filter(|s| s["site_kind"] == "background_job")
        .collect();
    assert_eq!(jobs.len(), 1, "one planted registration: {sites:?}");
    let job = jobs[0];
    assert_eq!(job["func"], "pthread_create");
    assert_eq!(job["client_type"], "posix.pthread");
    assert_eq!(job["file_path"], "src/workers.c");
    assert_eq!(job["symbol"], "start_workers");
    assert_eq!(job["provenance"]["client_type_resolved"], true);
    assert_eq!(
        job["site_key"],
        format!(
            "src/workers.c:{}:posix.pthread:pthread_create",
            job["line_number"]
        )
    );

    assert!(sites_with_method(&sites, "pthread_detach").is_empty());
    assert!(sites_with_method(&sites, "pthread_join").is_empty());
    // Every other site is a classic call site: the key is absent.
    for s in sites.iter().filter(|s| s["func"] != "pthread_create") {
        assert!(
            s.get("site_kind").is_none(),
            "classic sites carry no kind: {s}"
        );
    }
}

/// G3 (po-av01j.51): constructing a `std::thread` / `std::jthread` with a
/// callable is the registration. The default constructor starts nothing and
/// the move constructor transfers a thread that already runs, so neither is
/// emitted.
#[test]
fn cpp_fixture_emits_std_thread_construction_as_background_job_sites() {
    if !engine_available("cpp_fixture_emits_std_thread_construction_as_background_job_sites") {
        return;
    }
    let (sites, _records) = retrieve(&fixture("fixture-cpp"), &[]);

    let jobs: Vec<&serde_json::Value> = sites
        .iter()
        .filter(|s| s["site_kind"] == "background_job")
        .collect();
    let mut found: Vec<(&str, &str, &str)> = jobs
        .iter()
        .map(|s| {
            (
                s["symbol"].as_str().unwrap_or_default(),
                s["client_type"].as_str().unwrap_or_default(),
                s["func"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    found.sort();
    assert_eq!(
        found,
        vec![
            ("start_joining", "std::jthread", "jthread"),
            ("start_poller", "std::thread", "thread"),
            ("start_temporary", "std::thread", "thread"),
        ],
        "exactly the three callable-carrying constructions: {jobs:?}"
    );
    for job in &jobs {
        assert_eq!(job["file_path"], "src/workers.cpp");
        assert_eq!(job["provenance"]["client_type_resolved"], true);
        assert!(
            job["snippet"]
                .as_str()
                .is_some_and(|s| s.contains("poll_forever")),
            "the snippet carries the construction source: {job}"
        );
    }
    assert!(
        !sites.iter().any(|s| s["symbol"] == "not_registrations"),
        "default and move construction start no thread: {sites:?}"
    );
    // The G1 sites of service.cpp are untouched by the new lane.
    assert!(sites_with_method(&sites, "fetch")[0]
        .get("site_kind")
        .is_none());
}

#[test]
fn server_fixture_emits_civetweb_and_mongoose_registrations_as_server_entries() {
    if !engine_available(
        "server_fixture_emits_civetweb_and_mongoose_registrations_as_server_entries",
    ) {
        return;
    }
    let (sites, _records) = retrieve(&fixture("fixture-server"), &[]);
    // Nothing in this fixture is a G1 client call: every record is a G2 entry.
    for s in &sites {
        assert_eq!(s["site_kind"], "server_entry", "site_kind stamp: {s}");
        assert_eq!(s["provenance"]["client_type_resolved"], true, "{s}");
    }

    // civetweb: both registrations, the literal path in const_args, the
    // dynamic one emitted WITHOUT a path (the lane abstains on it).
    let civet = sites_with_method(&sites, "mg_set_request_handler");
    assert_eq!(civet.len(), 2, "both civetweb registrations: {sites:?}");
    let has_path = |s: &serde_json::Value, path: &str| {
        s["const_args"]
            .as_array()
            .is_some_and(|a| a.iter().any(|c| c["value"] == format!("{path:?}")))
    };
    let health = civet
        .iter()
        .find(|s| has_path(s, "/healthz"))
        .expect("the /healthz registration carries its literal path");
    assert_eq!(health["client_type"], "civetweb.mg_context");
    assert_eq!(health["symbol"], "serve");
    assert_eq!(health["file_path"], "src/civet.c");
    let dynamic = civet.iter().find(|s| !has_path(s, "/healthz")).unwrap();
    assert!(
        !dynamic["snippet"].as_str().unwrap().contains('"'),
        "the dynamic registration carries no literal path: {dynamic}"
    );

    // mongoose: the listener registration.
    let listens = sites_with_method(&sites, "mg_http_listen");
    assert_eq!(listens.len(), 1, "the listener registration: {sites:?}");
    assert_eq!(listens[0]["client_type"], "mongoose.mg_mgr");

    // mongoose: route matches inside the REGISTERED event handler.
    let uri_matches = sites_with_method(&sites, "mg_http_match_uri");
    assert_eq!(uri_matches.len(), 1, "{sites:?}");
    assert_eq!(uri_matches[0]["client_type"], "mongoose.mg_http_message");
    assert!(has_path(uri_matches[0], "/api/users"), "{}", uri_matches[0]);

    let matches = sites_with_method(&sites, "mg_match");
    assert_eq!(
        matches.len(),
        1,
        "only the uri match inside the registered handler is a route \
         (not the method match, not the match outside a handler): {matches:?}"
    );
    assert_eq!(matches[0]["symbol"], "ev_handler");
    assert_eq!(matches[0]["client_type"], "mongoose.mg_http_message");
    assert!(
        matches[0]["snippet"]
            .as_str()
            .is_some_and(|s| s.contains("\"/api/health\"")),
        "the route path rides the snippet: {}",
        matches[0]
    );
}

#[test]
fn g1_packets_carry_no_site_kind_key() {
    if !engine_available("g1_packets_carry_no_site_kind_key") {
        return;
    }
    // Absent means the classic G1 call site; the key must not appear at all,
    // so pre-existing G1 streams stay byte-identical.
    let (sites, _) = retrieve(&fixture("fixture-c"), &[]);
    assert!(!sites.is_empty());
    // (The fixture's one G3 thread start is not a G1 site and is stamped.)
    for s in sites.iter().filter(|s| s["func"] != "pthread_create") {
        assert!(
            s.get("site_kind").is_none(),
            "G1 site grew a site_kind: {s}"
        );
    }
}

#[test]
fn no_db_server_entry_is_emitted_at_low_tier() {
    if !engine_available("no_db_server_entry_is_emitted_at_low_tier") {
        return;
    }
    let (sites, _) = retrieve(&fixture("fixture-nodb"), &[]);
    let regs = sites_with_method(&sites, "mg_set_request_handler");
    assert_eq!(regs.len(), 1, "{sites:?}");
    assert_eq!(regs[0]["site_kind"], "server_entry");
    assert_eq!(regs[0]["client_type"], "civetweb.mg_context");
    assert_eq!(regs[0]["provenance"]["client_type_resolved"], false);
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

/// Write a one-file no-db C repo and retrieve it.
fn retrieve_c_source(src: &str) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(dir.path().join("src/fetch.c"), src).unwrap();
    retrieve(dir.path(), &[])
}

/// po-av01j.138: the SAME curl_easy_perform call, differing only in whether
/// its declarations resolve. With the header missing, clang's recovery drops
/// the whole statement (`CURL *h` parses as a multiplication of two undeclared
/// identifiers), so no call expression exists to count. The site is lost, and
/// before this fix the stats record was byte-identical to the clean case:
/// `tus_parsed:1, tus_failed:0, calls_unresolved:0`. The loss must now be
/// visible, and distinguishable from a genuinely clean parse.
#[test]
fn a_missing_header_is_reported_as_an_incomplete_parse_not_a_clean_zero() {
    if !engine_available("a_missing_header_is_reported_as_an_incomplete_parse_not_a_clean_zero") {
        return;
    }
    let body = "int fetch(void) {\n  CURL *h = curl_easy_init();\n  CURLcode rc = curl_easy_perform(h);\n  curl_easy_cleanup(h);\n  return (int)rc;\n}\n";

    // The missing header: 0 sites, and the stats say why.
    let (sites, records) = retrieve_c_source(&format!("#include <curl/curl.h>\n{body}"));
    assert!(sites.is_empty(), "the site is lost to recovery: {sites:?}");
    let missing = stats(&records);
    assert_eq!(missing["tus_parsed"], 1, "{missing}");
    assert_eq!(missing["tus_incomplete"], 1, "not a clean parse: {missing}");
    assert_eq!(missing["includes_missing"], 1, "{missing}");
    assert!(
        missing["decls_unresolved"].as_u64().is_some_and(|n| n >= 1),
        "undeclared identifiers are counted: {missing}"
    );
    assert_eq!(
        missing["tus_incomplete_paths"],
        serde_json::json!(["src/fetch.c"]),
        "{missing}"
    );

    // The declarations written inline: 1 site, a clean parse.
    let decls = "typedef void CURL;\ntypedef int CURLcode;\nextern CURL *curl_easy_init(void);\nextern CURLcode curl_easy_perform(CURL *);\nextern void curl_easy_cleanup(CURL *);\n";
    let (sites, records) = retrieve_c_source(&format!("{decls}{body}"));
    assert_eq!(sites_with_method(&sites, "curl_easy_perform").len(), 1);
    let clean = stats(&records);
    assert_eq!(clean["tus_incomplete"], 0, "{clean}");
    assert_eq!(clean["includes_missing"], 0, "{clean}");
    assert_eq!(clean["decls_unresolved"], 0, "{clean}");

    // The whole point: the two records must differ.
    assert_ne!(
        missing, clean,
        "a truncated parse must not report the same stats as a clean one"
    );
}

/// A TU that loses a site to recovery still keeps the sites that DID resolve:
/// they are real evidence. Dropping them would turn a partial answer into a
/// bigger false negative. The TU is reported incomplete either way.
#[test]
fn an_incomplete_tu_keeps_its_resolved_sites() {
    if !engine_available("an_incomplete_tu_keeps_its_resolved_sites") {
        return;
    }
    let (sites, records) = retrieve_c_source(
        "#include <curl/curl.h>\nint fetch(void *h) {\n  curl_easy_perform(h);\n  return undeclared_thing;\n}\n",
    );
    assert_eq!(sites_with_method(&sites, "curl_easy_perform").len(), 1);
    let st = stats(&records);
    assert_eq!(st["tus_incomplete"], 1, "{st}");
}

/// The built `cindex` installed in `<tmp>/bin`, with a vendored bundle beside
/// it whose "library" is not a library. Needs no libclang on the machine.
///
/// The executable is a hard link, not a copy: a copy is open for writing while
/// it is made, and a child forked by another test thread in that window holds
/// the write descriptor until its own exec, so running the copy fails with
/// "Text file busy" (po-jz4qz). A symlink would not do, because `cindex`
/// finds its bundle beside its resolved path. The temp directory is under the
/// profile directory so that the link never crosses a filesystem.
fn install_with_broken_bundle() -> (tempfile::TempDir, PathBuf) {
    let built = bin_path();
    let tmp = tempfile::tempdir_in(built.parent().expect("target/<profile> directory")).unwrap();
    let bin_dir = tmp.path().join("bin");
    let bundle = bin_dir.join("libclang");
    std::fs::create_dir_all(bundle.join("include")).unwrap();
    let lib = if cfg!(target_os = "macos") {
        "libclang.dylib"
    } else {
        "libclang.so"
    };
    std::fs::write(bundle.join(lib), b"not a shared object").unwrap();
    let exe = bin_dir.join(built.file_name().expect("cindex file name"));
    std::fs::hard_link(&built, &exe).unwrap();
    (tmp, exe)
}

/// The vendored bundle beside the executable is what loads (po-av01j.49),
/// ahead of any system libclang: with a bundle whose library is garbage the
/// probe must FAIL and name the bundle, even on a machine where the system
/// search would have succeeded. Falling through to the system clang would
/// make release scans depend on the machine again.
#[test]
fn engine_check_loads_the_vendored_bundle_before_the_system_libclang() {
    let (_tmp, exe) = install_with_broken_bundle();
    let out = Command::new(&exe)
        .arg("--engine-check")
        .env_remove("LIBCLANG_PATH")
        .output()
        .expect("run the installed cindex");
    assert!(
        !out.status.success(),
        "a broken vendored bundle must not be bypassed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let err = String::from_utf8_lossy(&out.stderr);
    let bundle = exe
        .canonicalize()
        .unwrap()
        .parent()
        .unwrap()
        .join("libclang");
    assert!(
        err.contains(&bundle.display().to_string()),
        "the error must name the bundle it tried: {err}"
    );
}

/// LIBCLANG_PATH stays the operator's override, bundle or not.
#[test]
fn libclang_path_overrides_the_vendored_bundle() {
    let (_tmp, exe) = install_with_broken_bundle();
    let out = Command::new(&exe)
        .arg("--engine-check")
        .env("LIBCLANG_PATH", "/nonexistent/po-av01j.49")
        .output()
        .expect("run the installed cindex");
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !err.contains("vendored"),
        "LIBCLANG_PATH was set, so the bundle must not be consulted: {err}"
    );
}

/// The installed executable must run at once while other threads fork
/// (po-jz4qz). A forked child holds every descriptor of its parent until its
/// own exec; if the install opens the executable for writing, the kernel
/// refuses to run it during that window ("Text file busy").
#[test]
fn bundle_install_is_executable_at_once_while_other_threads_fork() {
    const INSTALLERS: usize = 4;
    const ROUNDS_PER_INSTALLER: usize = 50;
    const FORKERS: usize = 8;

    let done = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|s| {
        for _ in 0..FORKERS {
            s.spawn(|| {
                while !done.load(std::sync::atomic::Ordering::Relaxed) {
                    bin().arg("--packet-schema").output().expect("run cindex");
                }
            });
        }
        let installers: Vec<_> = (0..INSTALLERS)
            .map(|_| {
                s.spawn(|| {
                    for round in 0..ROUNDS_PER_INSTALLER {
                        let (_tmp, exe) = install_with_broken_bundle();
                        if let Err(e) = Command::new(&exe).arg("--packet-schema").output() {
                            return Err(format!("round {round}: {e}"));
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        let results: Vec<_> = installers.into_iter().map(|h| h.join()).collect();
        done.store(true, std::sync::atomic::Ordering::Relaxed);
        for r in results {
            r.expect("installer thread")
                .unwrap_or_else(|e| panic!("the installed cindex did not run: {e}"));
        }
    });
}

/// The enclosing functions (`symbol`) of the sites for one method, sorted.
fn symbols_of(sites: &[serde_json::Value], method: &str) -> Vec<String> {
    let mut out: Vec<String> = sites_with_method(sites, method)
        .iter()
        .map(|s| s["symbol"].as_str().unwrap_or_default().to_string())
        .collect();
    out.sort();
    out
}

#[test]
fn read_and_write_are_emitted_only_on_an_fd_with_local_socket_evidence() {
    if !engine_available("read_and_write_are_emitted_only_on_an_fd_with_local_socket_evidence") {
        return;
    }
    let (sites, records) = retrieve(&fixture("fixture-fd"), &[]);

    // read: a socket()-initialized local, an accept()-assigned local, and a
    // parameter the same function hands to send(). Nothing else.
    assert_eq!(
        symbols_of(&sites, "read"),
        vec!["accepted_fd", "param_used_as_socket", "socket_init_fd"]
    );
    assert_eq!(symbols_of(&sites, "write"), vec!["socket_init_fd"]);
    for s in sites_with_method(&sites, "read")
        .into_iter()
        .chain(sites_with_method(&sites, "write"))
    {
        assert_eq!(s["client_type"], "posix.socket", "{s}");
        assert_eq!(s["provenance"]["client_type_resolved"], true, "{s}");
    }

    // The abstentions are counted, never guessed at: param_unknown,
    // reused_variable (socket then open), file_fd (write + read) and
    // member_fd.
    assert_eq!(stats(&records)["fd_calls_abstained"], 5);
}

#[test]
fn every_parsed_tu_reports_the_repo_headers_it_includes() {
    if !engine_available("every_parsed_tu_reports_the_repo_headers_it_includes") {
        return;
    }
    let (sites, records) = retrieve(&fixture("fixture-fd"), &[]);
    let mut graph: Vec<(String, Vec<String>)> = records
        .iter()
        .filter(|r| r["kind"].as_str() == Some("tu_includes"))
        .map(|r| {
            assert_eq!(r["packet_schema"].as_u64(), Some(2), "{r}");
            (
                r["file"].as_str().expect("file").to_string(),
                r["includes"]
                    .as_array()
                    .expect("includes")
                    .iter()
                    .map(|i| i.as_str().expect("path").to_string())
                    .collect(),
            )
        })
        .collect();
    graph.sort();
    // Transitive (posixio.h comes in through proto.h), repo-relative, sorted,
    // and without the TU itself.
    let headers = vec![
        "include/proto.h".to_string(),
        "vendor/posixio.h".to_string(),
    ];
    assert_eq!(
        graph,
        vec![
            ("src/files.c".to_string(), headers.clone()),
            ("src/net.c".to_string(), headers),
        ]
    );
    // The header's own site rides the stream once, at the header's path.
    let in_header: Vec<_> = sites
        .iter()
        .filter(|s| s["file_path"] == "include/proto.h")
        .collect();
    assert_eq!(in_header.len(), 1, "{in_header:?}");
    assert_eq!(in_header[0]["func"], "send");
}
