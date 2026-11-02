//! Compile in the content version of the goindex this rvl is built beside.
//!
//! The scripted helpers are embedded, so rvl hashes their text to know which
//! build it ships. goindex is a Go build that rvl cannot carry, and on a source
//! build nothing is bundled beside the binary either, so a goindex found on
//! PATH had nothing to be compared with and an old one scanned silently. This
//! hashes helpers/goindex the way goindex's own `versionOf` does (version.go):
//! every file its `//go:embed *.go go.mod go.sum` carries, in name order, each
//! name and each body NUL-terminated.

use sha2::Digest as _;
use std::path::Path;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../helpers/goindex");
    println!("cargo:rerun-if-changed={}", dir.display());
    // A crate built outside this workspace has no goindex source; the scan
    // then has no version to compare against, as before.
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".go") || n == "go.mod" || n == "go.sum")
        .collect();
    names.sort();
    let mut h = sha2::Sha256::new();
    for name in &names {
        let body = std::fs::read(dir.join(name)).expect("reading a goindex source file");
        h.update(name.as_bytes());
        h.update([0]);
        h.update(&body);
        h.update([0]);
    }
    let mut hex = hex::encode(h.finalize());
    hex.truncate(12);
    println!("cargo:rustc-env=RVL_GOINDEX_CONTENT_VERSION={hex}");
}
