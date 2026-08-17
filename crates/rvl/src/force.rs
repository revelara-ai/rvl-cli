//! The AUDITED emergency gate bypass, ported from rvl-cli
//! `internal/agentscan/force.go` + `internal/agentscan/audit.go` and the
//! `runForceNext` / `handleForceThrough` halves of `internal/commands/
//! scan_agent.go`.
//!
//! Two mechanisms, both audited:
//!
//!   * `RVL_FORCE=1` in the environment (CI / shell one-liner).
//!   * A one-shot marker file written by `rvl scan force-next`, consumed by
//!     the next gate run. It exists because GUI git clients cannot easily set
//!     an env var for the hook process.
//!
//! A force-through SKIPS the scan entirely: it is the emergency path for
//! shipping a lesser risk to fix a greater one, so it must not pay the scan's
//! wall clock. It is distinct from `git commit --no-verify`, which skips every
//! hook and leaves NO record: a force-through is written to the local audit
//! trail.
//!
//! Why this file exists at all (po-av01j.182): v2 had neither mechanism, and
//! because `force-next` parsed as a PATH, `rvl scan force-next` scanned a
//! directory of that name and printed "0 advisory - commit clean", exit 0. The
//! documented safety valve reported success without bypassing anything — the
//! worst available failure shape. The missing-target error below is the root
//! enabler and is fixed with it.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// The one-shot marker, stored in the repo's git dir so it is per-worktree and
/// never committed.
pub const FORCE_MARKER_NAME: &str = "rvl-force-next";

/// The JSONL audit log, stored alongside the marker in the git dir.
pub const AUDIT_FILE_NAME: &str = "rvl-audit.jsonl";

/// Audit event kind for a gate override.
pub const AUDIT_FORCE_THROUGH: &str = "force-through";

/// The usage exit code, matching rvl-cli's `cliutil.ExitUsage`.
const EXIT_USAGE: u8 = 2;

/// Which mechanism armed a force-through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mechanism {
    /// `RVL_FORCE=1`.
    Env,
    /// The one-shot marker file.
    Marker,
}

impl Mechanism {
    /// The wire/audit name, matching rvl-cli's `"env"` / `"marker"`.
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::Env => "env",
            Mechanism::Marker => "marker",
        }
    }
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8(out.stdout).ok()?.trim().to_string())
}

/// The absolute git dir for `root`, resolved via `git rev-parse --git-dir` so
/// linked worktrees (where `.git` is a file) land in the correct per-worktree
/// dir. `None` outside a work tree.
pub fn resolve_git_dir(root: &Path) -> Option<PathBuf> {
    let dir = git(root, &["rev-parse", "--git-dir"])?;
    if dir.is_empty() {
        return None;
    }
    let p = PathBuf::from(dir);
    Some(if p.is_absolute() { p } else { root.join(p) })
}

/// The git work-tree root for `dir`, or `None` when it is not inside a repo.
pub fn git_toplevel(dir: &Path) -> Option<PathBuf> {
    git(dir, &["rev-parse", "--show-toplevel"])
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
}

/// `git config user.name`, falling back to `$USER`, then `"unknown"`. Audit
/// record only.
fn current_user(root: &Path) -> String {
    if let Some(name) = git(root, &["config", "user.name"]).filter(|s| !s.is_empty()) {
        return name;
    }
    match std::env::var("USER") {
        Ok(u) if !u.is_empty() => u,
        _ => "unknown".to_string(),
    }
}

/// Whether the one-shot marker exists.
pub fn marker_present(root: &Path) -> bool {
    resolve_git_dir(root).is_some_and(|d| d.join(FORCE_MARKER_NAME).exists())
}

/// Whether a force-through is in effect, and by which mechanism. The env var
/// takes precedence as the REPORTED mechanism, but a present marker is still
/// consumed by [`handle_force_through`] either way, so it can never silently
/// apply to a later run.
pub fn force_state(root: &Path) -> Option<Mechanism> {
    if std::env::var("RVL_FORCE").as_deref() == Ok("1") {
        return Some(Mechanism::Env);
    }
    if marker_present(root) {
        return Some(Mechanism::Marker);
    }
    None
}

/// Create the one-shot marker in the git dir and return its path. Overwriting
/// an existing marker is fine (idempotent).
pub fn write_force_marker(root: &Path) -> Result<PathBuf, String> {
    let git_dir = resolve_git_dir(root).ok_or_else(|| "resolve git dir".to_string())?;
    let path = git_dir.join(FORCE_MARKER_NAME);
    let payload = format!(
        "{{\"created_at\":\"{}\",\"user\":{}}}\n",
        now_utc_rfc3339(),
        json_string(&current_user(root))
    );
    std::fs::write(&path, payload).map_err(|e| format!("write force marker: {e}"))?;
    Ok(path)
}

/// Remove the one-shot marker. A missing marker is NOT an error: exactly-once
/// consumption is idempotent, so calling this after an env-mechanism force
/// still clears any stale marker.
pub fn consume_force_marker(root: &Path) -> Result<(), String> {
    let Some(git_dir) = resolve_git_dir(root) else {
        return Ok(());
    };
    match std::fs::remove_file(git_dir.join(FORCE_MARKER_NAME)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("consume force marker: {e}")),
    }
}

/// Append one JSON line to the audit log, creating it if needed.
/// Best-effort durability: the caller treats a write failure as a warning,
/// NEVER as a gate decision — an unwritable audit file must not turn an
/// emergency bypass into a block.
pub fn append_audit_event(root: &Path, kind: &str, detail: &[(&str, &str)]) -> Result<(), String> {
    use std::io::Write as _;
    let git_dir = resolve_git_dir(root).ok_or_else(|| "resolve git dir".to_string())?;
    let mut line = format!(
        "{{\"time\":\"{}\",\"kind\":{}",
        now_utc_rfc3339(),
        json_string(kind)
    );
    if !detail.is_empty() {
        line.push_str(",\"detail\":{");
        for (i, (k, v)) in detail.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            line.push_str(&format!("{}:{}", json_string(k), json_string(v)));
        }
        line.push('}');
    }
    line.push_str("}\n");
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(git_dir.join(AUDIT_FILE_NAME))
        .map_err(|e| format!("open audit log: {e}"))?;
    f.write_all(line.as_bytes())
        .map_err(|e| format!("append audit event: {e}"))
}

/// Announce the bypass, record it, and consume the marker (unconditionally —
/// so a marker armed while `RVL_FORCE=1` was also set cannot apply to a later
/// run). Mirrors rvl-cli's `handleForceThrough`.
pub fn handle_force_through(root: &Path, mechanism: Mechanism) {
    eprintln!(
        "\x1b[31mAGENT SCAN FORCED THROUGH (mechanism: {}) - scan skipped, event audited\x1b[0m",
        mechanism.as_str()
    );
    if let Err(e) = append_audit_event(
        root,
        AUDIT_FORCE_THROUGH,
        &[("mechanism", mechanism.as_str())],
    ) {
        eprintln!("warning: could not write audit event: {e}");
    }
    if let Err(e) = consume_force_marker(root) {
        eprintln!("warning: could not consume force marker: {e}");
    }
}

/// `rvl scan force-next [--target <dir>]`: arm the one-shot marker. The next
/// scan in this repo skips the gate and records an audit event.
pub fn run_force_next(target: Option<&Path>) -> ExitCode {
    let target = match target {
        Some(t) => t.to_path_buf(),
        None => match std::env::current_dir() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: cannot get cwd: {e}");
                return ExitCode::from(EXIT_USAGE);
            }
        },
    };
    let Some(root) = git_toplevel(&target) else {
        eprintln!("Error: {} is not inside a git repository", target.display());
        return ExitCode::from(EXIT_USAGE);
    };
    let path = match write_force_marker(&root) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("Force-through armed: {}", path.display());
    println!(
        "The NEXT `{BIN} scan` run in this repo will SKIP the gate and record an audit event.",
        BIN = rvl_data::BIN
    );
    println!("Remove the marker to cancel: rm {}", path.display());
    ExitCode::SUCCESS
}

/// The hint printed under a blocked ladder. Both override paths are consumed
/// by the next scan in this repo; `--no-verify` is the UNAUDITED alternative
/// this exists to keep people away from.
pub fn force_through_hint() -> String {
    format!(
        "commit blocked; use RVL_FORCE=1 or '{BIN} scan force-next' to override",
        BIN = rvl_data::BIN
    )
}

/// Minimal JSON string escaping for the audit/marker records.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// UTC RFC3339, hand-rolled rather than pulling in `chrono`: this is an audit
/// string a human reads, and a gate must not gain a dependency for a log line.
/// (Same algorithm the eval ledger uses — Howard Hinnant's civil-from-days.)
fn now_utc_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir.path())
            .args(["init", "-q"])
            .status()
            .unwrap()
            .success();
        assert!(ok, "git init failed");
        dir
    }

    /// The marker round-trips through the git dir and is consumed exactly once.
    #[test]
    fn marker_is_written_then_consumed_once() {
        let dir = init_repo();
        let root = git_toplevel(dir.path()).expect("repo root");
        assert!(!marker_present(&root));

        let path = write_force_marker(&root).expect("write marker");
        assert!(path.ends_with(FORCE_MARKER_NAME));
        assert!(marker_present(&root));

        let payload = std::fs::read_to_string(&path).unwrap();
        assert!(payload.contains("\"created_at\""), "{payload}");
        assert!(payload.contains("\"user\""), "{payload}");

        consume_force_marker(&root).expect("consume");
        assert!(!marker_present(&root));
        // Idempotent: consuming a missing marker is not an error.
        consume_force_marker(&root).expect("second consume is a no-op");
    }

    /// The audit trail is append-only JSONL naming the mechanism.
    #[test]
    fn audit_events_append_as_jsonl() {
        let dir = init_repo();
        let root = git_toplevel(dir.path()).expect("repo root");
        append_audit_event(&root, AUDIT_FORCE_THROUGH, &[("mechanism", "marker")]).unwrap();
        append_audit_event(&root, AUDIT_FORCE_THROUGH, &[("mechanism", "env")]).unwrap();

        let log = std::fs::read_to_string(resolve_git_dir(&root).unwrap().join(AUDIT_FILE_NAME))
            .expect("audit log");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).expect("valid JSON line");
            assert_eq!(v["kind"], AUDIT_FORCE_THROUGH);
            assert!(v["time"].as_str().unwrap().ends_with('Z'));
        }
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(lines[0]).unwrap()["detail"]["mechanism"],
            "marker"
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(lines[1]).unwrap()["detail"]["mechanism"],
            "env"
        );
    }

    /// A marker arms the bypass; nothing armed reports nothing. (The env
    /// mechanism is covered end-to-end in the CLI tests, where the env var can
    /// be set for a child process without racing other tests in-process.)
    #[test]
    fn force_state_reports_the_marker() {
        let dir = init_repo();
        let root = git_toplevel(dir.path()).expect("repo root");
        assert_eq!(force_state(&root), None);
        write_force_marker(&root).unwrap();
        assert_eq!(force_state(&root), Some(Mechanism::Marker));
    }

    /// Outside a git work tree there is nowhere per-worktree to keep a marker,
    /// so no marker can be present and arming is refused rather than writing
    /// somewhere that would never be read.
    #[test]
    fn outside_a_repo_there_is_no_marker() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_git_dir(dir.path()).is_none());
        assert!(!marker_present(dir.path()));
        assert!(write_force_marker(dir.path()).is_err());
    }
}
