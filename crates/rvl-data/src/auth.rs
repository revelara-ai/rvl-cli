//! Slice (a): auth + status — `login`, `logout`, `status`, ported from
//! rvl-cli `internal/commands/auth.go`.
//!
//! `login` is interactive (no JSON contract); `status` is a human report
//! whose behavior contract is: show the configured endpoint/key/org, make
//! one live credential check, exit 1 with "Connection failed" when it
//! fails, then report CLI-update and installed-plugin drift.
//!
//! The update nag and the plugin section were briefly dropped in the port
//! and restored in po-av01j.185: the v1 -> v2 cutover's P4 step relies on
//! the nag to move stragglers, and it is the ONLY signal a v1 holdout
//! gets. The plugin section is rendered by the caller (`rvl`), which owns
//! the skills machinery this crate deliberately does not depend on.

use crate::client::{resolve_organization_id, validate_credentials, Client};
use crate::config::{self, DataConfig, DEFAULT_API_URL};
use crate::{CmdResult, Failure, BIN};
use std::io::Write as _;
use std::process::ExitCode;

/// `login`: prompt for API URL, key, and organization, validate against
/// the API, and save `~/.revelara/config.yaml`.
pub fn run_login() -> ExitCode {
    let mut cfg = config::load().ok().flatten().unwrap_or_default();

    let default_url = if cfg.api_url.is_empty() {
        DEFAULT_API_URL.to_string()
    } else {
        cfg.api_url.clone()
    };
    let api_url = prompt(&format!("Revelara API URL [{default_url}]: "));
    cfg.api_url = if api_url.is_empty() {
        default_url
    } else {
        api_url
    };

    if !cfg.api_key.is_empty() {
        if cfg.api_key.len() > 12 {
            let masked = format!(
                "{}...{}",
                &cfg.api_key[..8],
                &cfg.api_key[cfg.api_key.len() - 4..]
            );
            print!("API Key [{masked}] (Enter to keep): ");
        } else {
            print!("API Key [set] (Enter to keep): ");
        }
    } else {
        print!("API Key: ");
    }
    let _ = std::io::stdout().flush();
    let api_key = match read_secret() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("Error reading API key: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !api_key.is_empty() {
        cfg.api_key = api_key;
    } else if !cfg.api_key.is_empty() {
        println!("  Keeping existing API key.");
    }
    if cfg.api_key.is_empty() {
        eprintln!("Error: API key is required");
        return ExitCode::FAILURE;
    }

    let org_name = prompt(&format!("Organization name [{}]: ", cfg.org_name));
    if !org_name.is_empty() {
        cfg.org_name = org_name;
    }

    println!("\nValidating credentials...");
    let mut org_id = None;
    if !cfg.org_name.is_empty() {
        match resolve_organization_id(&cfg) {
            Ok(id) => {
                if let Some(id) = &id {
                    println!("Organization resolved: {} -> {}", cfg.org_name, id);
                }
                org_id = id;
            }
            Err(e) => {
                eprintln!("Error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let client = Client {
        api_url: cfg.api_url.clone(),
        api_key: cfg.api_key.clone(),
        org_id,
    };
    if let Err(e) = validate_credentials(&client) {
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = config::save(&cfg) {
        eprintln!("Error saving config: {e}");
        return ExitCode::FAILURE;
    }
    println!("Configuration saved to ~/.revelara/config.yaml");
    ExitCode::SUCCESS
}

/// `logout`: remove stored credentials.
pub fn run_logout() -> ExitCode {
    let Some(path) = config::config_path() else {
        eprintln!("Error: cannot determine home directory");
        return ExitCode::FAILURE;
    };
    match std::fs::remove_file(&path) {
        Ok(()) => {
            println!("Credentials removed.");
            ExitCode::SUCCESS
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("No credentials stored.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error removing config: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `status`: report the active configuration, check the connection, then
/// report CLI-update and installed-plugin drift.
///
/// `plugins` renders the "Plugins:" section and is called ONLY after the
/// credential check passes — it makes its own server call, and rvl-cli
/// does not reach the network for it on a connection failure either. It is
/// a callback because the skills machinery lives in `rvl-skills`, which
/// this crate does not (and should not) depend on.
pub fn run_status(version: &str, plugins: impl FnOnce() -> Option<String>) -> ExitCode {
    let (cfg, client) = match crate::client::load_and_resolve() {
        Ok(v) => v,
        Err(f) => {
            eprintln!("{}", f.msg);
            return ExitCode::from(f.code);
        }
    };
    match status_output(&cfg, &client, version) {
        Ok(out) => {
            print!("{out}");
            // rvl-cli puts the whole update block on stderr so a piped
            // `status` stays parseable; same here.
            if let Some(notice) = crate::update_check::update_notice(
                version,
                crate::update_check::fetch_latest_cli_version().as_deref(),
            ) {
                eprint!("{notice}");
            }
            if let Some(section) = plugins() {
                print!("{section}");
            }
            ExitCode::SUCCESS
        }
        Err(f) => {
            // The pre-check config lines still printed in rvl-cli before the
            // failing connection check; mirror that ordering.
            print!("{}", status_header(&cfg, version));
            println!("\nChecking connection...");
            eprintln!("{}", f.msg);
            ExitCode::from(f.code)
        }
    }
}

/// The config header `status` always prints, network-free.
pub fn status_header(cfg: &DataConfig, version: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "Revelara CLI v{version} ({BIN})");
    let _ = writeln!(out, "API URL: {}", cfg.api_url);
    if cfg.api_key.len() > 8 {
        let _ = writeln!(
            out,
            "API Key: {}...{}",
            &cfg.api_key[..4],
            &cfg.api_key[cfg.api_key.len() - 4..]
        );
    } else {
        let _ = writeln!(out, "API Key: (set)");
    }
    if !cfg.org_name.is_empty() {
        let _ = writeln!(out, "Organization: {}", cfg.org_name);
    }
    out
}

/// The full `status` output, or the connection failure.
pub fn status_output(cfg: &DataConfig, client: &Client, version: &str) -> CmdResult {
    use std::fmt::Write as _;
    let mut out = status_header(cfg, version);
    if let Err(e) = validate_credentials(client) {
        return Err(Failure::runtime(format!("Connection failed: {e}")));
    }
    let _ = writeln!(out, "\nChecking connection...");
    let _ = writeln!(out, "Status: Connected");
    Ok(out)
}

fn prompt(msg: &str) -> String {
    print!("{msg}");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    line.trim().to_string()
}

/// Read the API key without echoing it back (rvl-cli masks input). On a
/// TTY, terminal echo is disabled via termios; piped stdin falls back to a
/// plain read.
#[cfg(unix)]
fn read_secret() -> std::io::Result<String> {
    let fd = 0; // stdin
                // SAFETY: querying/toggling termios flags on stdin; the original state
                // is restored before returning.
    unsafe {
        if libc::isatty(fd) == 0 {
            return read_plain();
        }
        let mut term: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut term) != 0 {
            return read_plain();
        }
        let orig = term;
        term.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(fd, libc::TCSANOW, &term) != 0 {
            return read_plain();
        }
        let result = read_plain();
        libc::tcsetattr(fd, libc::TCSANOW, &orig);
        println!(); // the suppressed Enter
        result
    }
}

#[cfg(not(unix))]
fn read_secret() -> std::io::Result<String> {
    read_plain()
}

fn read_plain() -> std::io::Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_header_masks_the_key() {
        let cfg = DataConfig {
            api_url: "https://api.revelara.ai".into(),
            api_key: "pk_live_abcdef123456".into(),
            org_name: "acme".into(),
        };
        let out = status_header(&cfg, "0.1.0");
        assert!(out.contains("API URL: https://api.revelara.ai\n"));
        assert!(out.contains("API Key: pk_l...3456\n"), "{out}");
        assert!(out.contains("Organization: acme\n"));
        assert!(
            !out.contains("pk_live_abcdef123456"),
            "full key must never print"
        );
    }

    #[test]
    fn status_header_short_key_prints_set() {
        let cfg = DataConfig {
            api_url: "u".into(),
            api_key: "short".into(),
            org_name: String::new(),
        };
        let out = status_header(&cfg, "0.1.0");
        assert!(out.contains("API Key: (set)\n"));
        assert!(!out.contains("Organization:"));
    }
}
