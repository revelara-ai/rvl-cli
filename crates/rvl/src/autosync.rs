//! The binary's half of keeping the spec cache current (po-av01j.171). The
//! policy and its reasons live in [`rvl_cache::auto`]; this module wires it
//! to the scan, `sync --background`, and `init`.
//!
//! * After a scan (never before or during it, so the scan's one cache load is
//!   untouched), a due check is handed to a detached `sync --background`
//!   process. The scan does not wait for it and never learns how it went.
//! * While a scan loads its cache it enforces a CI pin and prints the
//!   attribution line when the corpus changed since this repo's last scan.
//! * `init` syncs synchronously: it is a setup step, and a first scan with no
//!   cache cannot run at all.

use crate::Config;
use rvl_cache::auto;
use rvl_cache::{CacheStore, HttpFetcher, Keyset, OssHttpFetcher, SyncOutcome, TieredLoaded};
use rvl_core::BIN;
use std::path::Path;
use std::process::ExitCode;
use std::sync::OnceLock;

/// The content_version pin for this run, set once by `scan` before it loads.
static PIN: OnceLock<String> = OnceLock::new();

/// `--spec-version` wins over `RVL_SPEC_VERSION`; blank means no pin.
pub fn resolve_pin(flag: Option<String>) -> Option<String> {
    let blank_is_none = |p: String| Some(p.trim().to_string()).filter(|p| !p.is_empty());
    flag.and_then(blank_is_none).or_else(|| {
        std::env::var("RVL_SPEC_VERSION")
            .ok()
            .and_then(blank_is_none)
    })
}

pub fn set_pin(pin: Option<String>) {
    if let Some(p) = pin {
        let _ = PIN.set(p);
    }
}

fn pin() -> Option<&'static str> {
    PIN.get().map(String::as_str)
}

/// Run while a scan loads the signed cache, before anything is judged: a pin
/// mismatch refuses the scan, and a corpus that changed under this repo since
/// its last scan is named on stderr, beside the staleness note.
pub fn cache_header(
    tiers: &TieredLoaded,
    cache_root: &Path,
    repo_root: Option<&Path>,
) -> anyhow::Result<()> {
    let oss = tiers
        .oss
        .as_ref()
        .map(|l| l.envelope.content_version.as_str());
    let commercial = tiers
        .commercial
        .as_ref()
        .map(|l| l.envelope.content_version.as_str());
    if let Some(p) = pin() {
        let loaded: Vec<&str> = [commercial, oss].into_iter().flatten().collect();
        auto::check_pin(p, &loaded).map_err(anyhow::Error::msg)?;
    }
    if let (Some(root), Some(label)) = (repo_root, auto::tiers_label(oss, commercial)) {
        let key = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        if let Some(previous) = auto::note_applied(cache_root, &key.to_string_lossy(), &label) {
            eprintln!("{}", attribution(&previous, &label));
        }
    }
    Ok(())
}

/// The one wording for "the corpus moved, not your code".
fn attribution(previous: &str, current: &str) -> String {
    format!(
        "spec cache updated since this repo's last scan: {previous} -> {current}; \
         findings can change because the corpus changed, not your code"
    )
}

/// After a scan: start the background check when one is due. Everything here
/// is best-effort and silent, and nothing waits on the child.
pub fn after_scan(cfg: &Config, used_signed_cache: bool) {
    if !used_signed_cache {
        return;
    }
    let ci = std::env::var("CI").ok();
    if auto::suppressed(cfg.offline, pin(), ci.as_deref()).is_some() {
        return;
    }
    if !auto::claim(
        &cfg.cache_dir,
        auto::now_secs(),
        auto::AUTO_SYNC_INTERVAL_SECS,
    ) {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["sync", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Its own process group, so a Ctrl-C aimed at the hook that ran this scan
    // does not also reach a fetch the user never saw start.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    // Not waited on: this process exits right after the scan, and the child
    // is reparented. A spawn failure only means no check this interval.
    let _ = cmd.spawn();
}

/// Both tiers, in `sync`'s order. The commercial tier is `None` without an
/// API key. A tier that ends current restarts the auto-sync interval, so the
/// scan after an explicit or init sync does not fetch again.
pub fn sync_tiers(
    cfg: &Config,
    store: &CacheStore,
    keyset: &Keyset,
) -> anyhow::Result<(SyncOutcome, Option<SyncOutcome>)> {
    let oss_store = store.subdir_store(rvl_cache::OSS_DIR)?;
    let oss = rvl_cache::sync(
        &oss_store,
        &OssHttpFetcher {
            base_url: cfg.base_url.clone(),
        },
        keyset,
        cfg.offline,
    );
    let commercial = (!cfg.org_key.is_empty()).then(|| {
        rvl_cache::sync(
            store,
            &HttpFetcher {
                base_url: cfg.base_url.clone(),
                org_key: cfg.org_key.clone(),
            },
            keyset,
            cfg.offline,
        )
    });
    note_if_current(&cfg.cache_dir, [Some(&oss), commercial.as_ref()]);
    Ok((oss, commercial))
}

fn is_current(o: &SyncOutcome) -> bool {
    matches!(o, SyncOutcome::UpToDate | SyncOutcome::Installed { .. })
}

/// Restart the auto-sync interval when any of `outcomes` left a tier current.
pub fn note_if_current<'a>(
    cache_dir: &Path,
    outcomes: impl IntoIterator<Item = Option<&'a SyncOutcome>>,
) {
    if outcomes.into_iter().flatten().any(is_current) {
        auto::record_check(cache_dir, auto::now_secs());
    }
}

/// `sync --background`: the check a scan handed off. Silent and always exit
/// 0; the outcome is visible to the next scan as a new cache (with the
/// attribution line), or as nothing at all.
pub fn background(cfg: &Config, store: &CacheStore, keyset: &Keyset) -> ExitCode {
    let _ = sync_tiers(cfg, store, keyset);
    ExitCode::SUCCESS
}

/// `init`'s synchronous sync, as the text after "Spec cache: ". It never fails
/// init: every other step already happened, so a failed fetch is a warning
/// that names the fix.
pub fn init_sync(cfg: &Config) -> String {
    if cfg.offline {
        return "not synced (RVL_OFFLINE=1)".to_string();
    }
    let fix = format!("run '{BIN} sync' before the first scan");
    let synced = CacheStore::open(&cfg.cache_dir).and_then(|store| {
        let keyset = Keyset::from_hex(rvl_cache::PINNED_KEYSET_HEX)?;
        sync_tiers(cfg, &store, &keyset)
    });
    let (oss, commercial) = match synced {
        Ok(o) => o,
        Err(e) => return format!("not synced ({e}); {fix}"),
    };
    let mut parts = vec![describe("oss tier", &oss)];
    if let Some(c) = &commercial {
        parts.push(describe("commercial tier", c));
    }
    if !is_current(&oss) && !commercial.as_ref().is_some_and(is_current) {
        parts.push(fix);
    }
    parts.join("; ")
}

fn describe(tier: &str, o: &SyncOutcome) -> String {
    match o {
        SyncOutcome::Offline => format!("{tier} not synced (RVL_OFFLINE=1)"),
        SyncOutcome::UpToDate => format!("{tier} up to date"),
        SyncOutcome::Installed { content_version } => {
            format!("{tier} installed {content_version}")
        }
        SyncOutcome::SchemaTooNew { hint } => format!("{tier}: {hint}"),
        SyncOutcome::Rejected { reason } => format!("{tier} rejected ({reason})"),
        SyncOutcome::FetchFailed { reason } => format!("{tier} fetch failed ({reason})"),
        SyncOutcome::InstallFailed { reason } => format!("{tier} install failed ({reason})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attribution_names_both_corpora_and_clears_the_code() {
        let line = attribution("oss o1", "oss o2");
        assert!(line.contains("oss o1 -> oss o2"), "{line}");
        assert!(line.contains("not your code"), "{line}");
    }

    #[test]
    fn describe_every_outcome_names_its_tier() {
        for o in [
            SyncOutcome::Offline,
            SyncOutcome::UpToDate,
            SyncOutcome::Installed {
                content_version: "v".into(),
            },
            SyncOutcome::SchemaTooNew { hint: "h".into() },
            SyncOutcome::Rejected { reason: "r".into() },
            SyncOutcome::FetchFailed { reason: "f".into() },
            SyncOutcome::InstallFailed { reason: "i".into() },
        ] {
            assert!(describe("oss tier", &o).starts_with("oss tier"));
        }
    }

    #[test]
    fn a_blank_flag_is_as_if_not_given() {
        // Compared with the omitted flag, not with None: both fall back to
        // RVL_SPEC_VERSION, whatever the test environment holds.
        assert_eq!(resolve_pin(Some("  ".into())), resolve_pin(None));
        assert_eq!(
            resolve_pin(Some(" 2026-09-01.a ".into())).as_deref(),
            Some("2026-09-01.a")
        );
    }
}
