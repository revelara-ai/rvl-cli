//! `rvl scan --blend` end to end (po-av01j.205).
//!
//! One command: the deterministic scan, then ONLY the sites it could not
//! decide go to the user's agent, then one merged report. The agent is a
//! stub script behind `RVL_AGENT_CMD`, the documented seam for custom agents
//! and tests, so these runs make no model calls.
//!
//! Pinned here:
//!   * the agent sees the undecided site and nothing the engine decided;
//!   * an agent that fails, or is vetoed, fails OPEN (exit 0) and the footer
//!     says NOT A BLENDED RESULT, never "commit clean";
//!   * `--agent`, the v1 alias every inherited hook shim runs, still never
//!     invokes an agent, and `--blend` is refused on the hook path.

use std::path::{Path, PathBuf};
use std::process::Command;

fn bin(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_rvl"));
    for k in [
        "GITHUB_BASE_REF",
        "RVL_BASE_REF",
        "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
        "RVL_AGENT_CMD",
        "RVL_NO_AGENT",
    ] {
        c.env_remove(k);
    }
    // Isolate ~/.revelara (org policy, agent selection) from the host.
    c.env("HOME", home);
    c
}

struct Fixture {
    dir: tempfile::TempDir,
    packets: PathBuf,
    specs: PathBuf,
    /// The site key of the one call the engine cannot decide.
    undecided_key: String,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("svc");
    std::fs::create_dir_all(&src).unwrap();
    let db_go = src.join("db.go");
    let unknown_go = src.join("unknown.go");
    std::fs::write(&db_go, "package svc\n\nfunc q() { tx.Query(ctx, q) }\n").unwrap();
    std::fs::write(&unknown_go, "package svc\n\nfunc m() { u.Mystery() }\n").unwrap();
    let packets = dir.path().join("retrieved.jsonl");
    std::fs::write(&packets, format!(
        "{{\"snapshot_id\":\"fixture\",\"file_path\":{db:?},\"line_number\":10,\"func\":\"Query\",\"client_type\":\"github.com/jackc/pgx/v5.Tx\",\"snippet\":\"tx.Query(ctx, q)\",\"lang\":\"go\"}}\n{{\"snapshot_id\":\"fixture\",\"file_path\":{unk:?},\"line_number\":20,\"func\":\"Mystery\",\"client_type\":\"x.Unknown\",\"snippet\":\"u.Mystery()\",\"lang\":\"go\"}}\n",
        db = db_go.to_str().unwrap(),
        unk = unknown_go.to_str().unwrap(),
    )).unwrap();
    let specs = dir.path().join("specs.json");
    std::fs::write(&specs, r#"{"apis":[{"type":"github.com/jackc/pgx/v5.Tx","method":"Query","site_count":1,"blocking":"yes","bounded_by":["context"],"confidence":0.95,"rationale":"pgx query blocks"}],"configs":[]}"#).unwrap();
    let undecided_key = format!("{}:20:x.Unknown:Mystery", unknown_go.to_str().unwrap());
    Fixture {
        dir,
        packets,
        specs,
        undecided_key,
    }
}

/// A stub agent: records its prompt in `prompt.txt`, prints `reply`.
fn stub_agent(dir: &Path, reply: &str, exit: i32) -> String {
    let script = dir.join("agent.sh");
    let log = dir.join("prompt.txt");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nprintf '%s' \"$1\" > '{}'\ncat <<'JSON'\n{reply}\nJSON\nexit {exit}\n",
            log.display()
        ),
    )
    .unwrap();
    format!("sh {}", script.display())
}

fn scan(fx: &Fixture, extra: &[&str], env: &[(&str, &str)]) -> (std::process::Output, String) {
    let mut c = bin(fx.dir.path());
    c.args(["scan", "--retrieved"])
        .arg(&fx.packets)
        .arg("--specs-file")
        .arg(&fx.specs)
        .args(extra)
        .arg(fx.dir.path())
        .env("RVL_CACHE_DIR", fx.dir.path().join("cache"));
    for (k, v) in env {
        c.env(k, v);
    }
    let out = c.output().expect("run rvl");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out, all)
}

#[test]
fn blend_sends_only_the_undecided_site_and_merges_the_verdict() {
    let fx = fixture();
    let reply = format!(
        r#"[{{"site":"{}","verdict":"violates","reason":"Mystery dials with no deadline"}}]"#,
        fx.undecided_key
    );
    let cmd = stub_agent(fx.dir.path(), &reply, 0);
    let out_json = fx.dir.path().join("out.json");
    let (out, all) = scan(
        &fx,
        &["--blend", "--out", out_json.to_str().unwrap()],
        &[("RVL_AGENT_CMD", &cmd)],
    );
    assert!(out.status.success(), "advisory blend never blocks: {all}");
    let prompt = std::fs::read_to_string(fx.dir.path().join("prompt.txt"))
        .expect("the agent must be consulted for the undecided site");
    assert!(prompt.contains(&fx.undecided_key), "{prompt}");
    assert!(
        !prompt.contains("pgx"),
        "the engine decided the pgx call; the agent must not see it: {prompt}"
    );
    assert!(all.contains("BLEND"), "{all}");
    assert!(all.contains("Mystery dials with no deadline"), "{all}");
    assert!(all.contains("blend complete"), "{all}");
    assert!(!all.contains("NOT A BLENDED RESULT"), "{all}");

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
    assert_eq!(doc["blend"]["complete"], true, "{doc}");
    assert_eq!(doc["blend"]["warned"], 1, "{doc}");
    assert_eq!(doc["blend"]["sent"], 1, "{doc}");
    // Engine rows stay engine truth: the agent verdict never rewrites them.
    let undecided = doc["undecided"].as_array().unwrap();
    assert_eq!(undecided.len(), 1, "{doc}");
}

#[test]
fn a_failing_agent_fails_open_and_never_reads_clean() {
    let fx = fixture();
    let cmd = stub_agent(fx.dir.path(), "rate limited", 1);
    let out_json = fx.dir.path().join("out.json");
    let (out, all) = scan(
        &fx,
        &["--blend", "--out", out_json.to_str().unwrap()],
        &[("RVL_AGENT_CMD", &cmd)],
    );
    assert!(out.status.success(), "the agent half fails open: {all}");
    assert!(!all.contains("commit clean"), "{all}");
    assert!(all.contains("NOT A BLENDED RESULT"), "{all}");
    assert!(all.contains("agent invocation failed"), "{all}");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&out_json).unwrap()).unwrap();
    assert_eq!(doc["blend"]["complete"], false, "{doc}");
}

#[test]
fn a_vetoed_agent_is_not_consulted_and_says_so() {
    let fx = fixture();
    let cmd = stub_agent(fx.dir.path(), "[]", 0);
    let (out, all) = scan(
        &fx,
        &["--blend"],
        &[("RVL_AGENT_CMD", &cmd), ("RVL_NO_AGENT", "1")],
    );
    assert!(out.status.success(), "{all}");
    assert!(
        !fx.dir.path().join("prompt.txt").exists(),
        "RVL_NO_AGENT=1 must veto the agent even with --blend"
    );
    assert!(all.contains("NOT A BLENDED RESULT"), "{all}");
    assert!(all.contains("RVL_NO_AGENT"), "{all}");
}

#[test]
fn without_blend_no_agent_is_consulted_even_with_agent_alias() {
    // Every rvl-cli v1 hook shim runs `rvl scan --agent`. That spelling must
    // stay the deterministic scan forever (po-av01j.191).
    let fx = fixture();
    let cmd = stub_agent(fx.dir.path(), "[]", 0);
    let (out, all) = scan(&fx, &["--agent"], &[("RVL_AGENT_CMD", &cmd)]);
    assert!(out.status.success(), "{all}");
    assert!(
        !fx.dir.path().join("prompt.txt").exists(),
        "--agent must never invoke an agent"
    );
    assert!(!all.contains("BLEND"), "{all}");
}

#[test]
fn blend_is_refused_on_the_hook_path() {
    let fx = fixture();
    let mut c = bin(fx.dir.path());
    let out = c
        .args(["scan", "--blend", "--staged"])
        .arg(fx.dir.path())
        .env("RVL_CACHE_DIR", fx.dir.path().join("cache"))
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "{err}");
    assert!(
        err.contains("--blend") && err.contains("hook"),
        "the refusal must name why, not be a clap parse error: {err}"
    );
}
