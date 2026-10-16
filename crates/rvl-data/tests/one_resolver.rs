//! Every command gets its server, key and organization from
//! `rvl_data::config::resolve`, so `--context` reaches every command. This
//! test fails when a second reader of `~/.revelara/config.yaml` or of the
//! `RVL_*` connection variables appears anywhere in the workspace.

use std::path::{Path, PathBuf};

/// The one module allowed to read the file and the variables.
const RESOLVER: &str = "rvl-data/src/config.rs";

const ENV_NAMES: [&str; 4] = ["RVL_API_KEY", "RVL_API_URL", "RVL_ORG_NAME", "RVL_CONTEXT"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The reasons `text` reads the config file or a connection variable.
fn readers(text: &str) -> Vec<String> {
    let mut found: Vec<String> = ENV_NAMES
        .iter()
        .flat_map(|n| [format!("var(\"{n}\")"), format!("var_os(\"{n}\")")])
        .filter(|call| text.contains(call.as_str()))
        .collect();
    if text.contains("\".revelara\"") && text.contains("join(\"config.yaml\")") {
        found.push("joins .revelara/config.yaml".into());
    }
    if text.contains("\".revelara/config.yaml\"") {
        found.push("names .revelara/config.yaml as a path".into());
    }
    found
}

#[test]
fn the_detector_sees_each_kind_of_reader() {
    assert_eq!(readers("std::env::var(\"RVL_API_KEY\").ok()").len(), 1);
    assert_eq!(readers("std::env::var_os(\"RVL_CONTEXT\")").len(), 1);
    assert_eq!(
        readers("home.join(\".revelara\")\n    .join(\"config.yaml\")").len(),
        1
    );
    assert_eq!(readers("home.join(\".revelara/config.yaml\")").len(), 1);
    assert!(readers("set RVL_API_KEY, or add api_key to ~/.revelara/config.yaml").is_empty());
}

#[test]
fn only_the_resolver_reads_the_config_file_or_the_rvl_connection_variables() {
    let crates = Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .to_path_buf();
    let mut files = Vec::new();
    rust_files(&crates, &mut files);
    assert!(files.len() > 50, "walked too few files: {}", files.len());
    let mut offenders = Vec::new();
    let mut resolver_seen = false;
    for f in &files {
        let rel = f
            .strip_prefix(&crates)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        // Product code only: test fixtures write config files on purpose.
        if !rel.contains("/src/") || rel.contains("/target/") {
            continue;
        }
        let found = readers(&std::fs::read_to_string(f).unwrap());
        if rel == RESOLVER {
            resolver_seen = true;
            assert!(!found.is_empty(), "the resolver no longer reads the file");
            continue;
        }
        for why in found {
            offenders.push(format!("{rel}: {why}"));
        }
    }
    assert!(resolver_seen, "{RESOLVER} not found");
    assert!(
        offenders.is_empty(),
        "read the config through rvl_data::config::resolve instead:\n{}",
        offenders.join("\n")
    );
}
