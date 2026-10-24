//! The release pin for the vendored ONNX Runtime, and the fetch tooling that
//! honors it.
//!
//! `crates/rvl-model/onnxruntime.pin` is the single source of truth: CI's
//! `ci/fetch-onnxruntime.sh` reads it, and these tests hold it to the release
//! target list in dist-workspace.toml, so adding a target without pinning a
//! runtime for it fails here instead of at tag time. The fetch script is
//! driven against local `file://` fixtures: it must refuse a checksum
//! mismatch and leave nothing behind.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::Digest as _;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Non-comment, non-blank lines, split on whitespace.
fn pin_rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.split_whitespace().map(str::to_string).collect())
        .collect()
}

/// `targets = [...]` from dist-workspace.toml: what a release builds.
fn dist_targets() -> BTreeSet<String> {
    let text = std::fs::read_to_string(repo_root().join("dist-workspace.toml")).unwrap();
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("targets = ["))
        .expect("dist-workspace.toml declares targets");
    line.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[test]
fn every_release_target_pins_exactly_one_checksummed_runtime() {
    let pin =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("onnxruntime.pin"))
            .unwrap();
    let rows = pin_rows(&pin);
    let version = rows
        .iter()
        .find(|r| r[0] == "version")
        .map(|r| r[1].clone())
        .expect("a `version` line");

    let mut seen = BTreeSet::new();
    let mut shas = BTreeSet::new();
    for r in rows.iter().filter(|r| r[0] == "lib") {
        assert_eq!(
            r.len(),
            6,
            "lib <triple> <url> <sha256> <lib-member> <license-member>: {r:?}"
        );
        let (triple, url, sha, member) = (&r[1], &r[2], &r[3], &r[4]);
        assert!(seen.insert(triple.clone()), "{triple} pinned twice");
        assert!(
            shas.insert(sha.clone()),
            "{triple} reuses another target's checksum"
        );
        assert!(
            url.starts_with("https://github.com/microsoft/onnxruntime/releases/download/"),
            "{triple}: {url}"
        );
        assert!(
            url.contains(&version),
            "{triple}: url is not version {version}: {url}"
        );
        assert!(is_sha256(sha), "{triple}: not a lowercase sha256: {sha}");
        let want = if triple.contains("apple-darwin") {
            "libonnxruntime.dylib"
        } else {
            "libonnxruntime.so"
        };
        assert_eq!(
            Path::new(member).file_name().unwrap(),
            want,
            "{triple}: the member must be the name rvl-model looks for (runtime::LIB_NAME)"
        );
    }
    assert_eq!(
        seen,
        dist_targets(),
        "onnxruntime.pin and dist-workspace.toml `targets` must name the same triples"
    );
}

#[test]
fn the_ort_crate_is_pinned_to_the_api_of_the_pinned_runtime() {
    let pin =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("onnxruntime.pin"))
            .unwrap();
    let version = pin_rows(&pin)
        .into_iter()
        .find(|r| r[0] == "version")
        .map(|r| r[1].clone())
        .unwrap();
    let minor = version.split('.').nth(1).unwrap();
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .unwrap();
    let ort = manifest
        .lines()
        .find(|l| l.starts_with("ort = "))
        .expect("an `ort` dependency");
    assert!(
        ort.contains(&format!("\"api-{minor}\"")),
        "ort must request the C API of ONNX Runtime {version} (api-{minor}): {ort}"
    );
    assert!(
        ort.contains("\"load-dynamic\"") && ort.contains("default-features = false"),
        "ort must load the vendored library, never download or link one: {ort}"
    );
}

// ---------------------------------------------------------------------------
// ci/fetch-onnxruntime.sh against local fixtures
// ---------------------------------------------------------------------------

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A fake release archive laid out like Microsoft's, plus its sha256.
struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    sha: String,
}

const TOP: &str = "onnxruntime-linux-x64-9.9.9";

fn fixture(test: &str) -> Option<Fixture> {
    for tool in ["tar", "gzip", "curl"] {
        if !have(tool) {
            rvl_testgate::skip(test, format_args!("`{tool}` not on PATH"));
            return None;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let top = dir.join("src").join(TOP);
    std::fs::create_dir_all(top.join("lib")).unwrap();
    std::fs::create_dir_all(top.join("include")).unwrap();
    std::fs::write(top.join("lib/libonnxruntime.so.9.9.9"), "ELF-ish").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            "libonnxruntime.so.9.9.9",
            top.join("lib/libonnxruntime.so.1"),
        )
        .unwrap();
        std::os::unix::fs::symlink("libonnxruntime.so.1", top.join("lib/libonnxruntime.so"))
            .unwrap();
    }
    std::fs::write(top.join("LICENSE"), "MIT License\n").unwrap();
    std::fs::write(top.join("ThirdPartyNotices.txt"), "notices\n").unwrap();
    std::fs::write(top.join("include/onnxruntime_c_api.h"), "/* api */\n").unwrap();
    let ok = Command::new("tar")
        .arg("-czf")
        .arg(dir.join("runtime.tgz"))
        .arg("-C")
        .arg(dir.join("src"))
        .arg(TOP)
        .status()
        .unwrap()
        .success();
    assert!(ok, "build the fake archive");
    let sha = hex::encode(sha2::Sha256::digest(
        std::fs::read(dir.join("runtime.tgz")).unwrap(),
    ));
    Some(Fixture {
        _tmp: tmp,
        dir,
        sha,
    })
}

impl Fixture {
    fn write_pin(&self, sha: &str) -> PathBuf {
        let pin = self.dir.join("test.pin");
        std::fs::write(
            &pin,
            format!(
                "version 9.9.9\n\
                 lib x86_64-unknown-linux-gnu file://{d}/runtime.tgz {sha} \
                 {TOP}/lib/libonnxruntime.so {TOP}/LICENSE\n",
                d = self.dir.display()
            ),
        )
        .unwrap();
        pin
    }

    fn fetch(&self, pin: &Path, triple: &str, out: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(repo_root().join("ci/fetch-onnxruntime.sh"))
            .arg(triple)
            .arg(out)
            .env("ONNXRUNTIME_PIN", pin)
            .output()
            .expect("run ci/fetch-onnxruntime.sh")
    }
}

#[cfg(unix)]
#[test]
fn fetch_lays_out_the_bundle_rvl_model_looks_for() {
    let Some(fx) = fixture("fetch_lays_out_the_bundle_rvl_model_looks_for") else {
        return;
    };
    let pin = fx.write_pin(&fx.sha);
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(
        res.status.success(),
        "fetch failed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let bundle = out.join("onnxruntime");
    let lib = bundle.join("libonnxruntime.so");
    assert!(
        !std::fs::symlink_metadata(&lib)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the archive's link is followed, so the bundle holds the library itself"
    );
    assert_eq!(std::fs::read_to_string(&lib).unwrap(), "ELF-ish");
    assert_eq!(
        std::fs::read_to_string(bundle.join("LICENSE")).unwrap(),
        "MIT License\n"
    );
    assert!(bundle.join("ThirdPartyNotices.txt").is_file());
    let mut names: Vec<_> = std::fs::read_dir(&bundle)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["LICENSE", "ThirdPartyNotices.txt", "libonnxruntime.so"]
    );
    // Re-running replaces the bundle rather than failing or merging.
    let again = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(lib.is_file());
}

#[test]
fn fetch_fails_closed_on_a_checksum_mismatch() {
    let Some(fx) = fixture("fetch_fails_closed_on_a_checksum_mismatch") else {
        return;
    };
    let pin = fx.write_pin(&"0".repeat(64));
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(!res.status.success(), "a tampered runtime must not ship");
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(err.contains("checksum"), "{err}");
    assert!(
        !out.join("onnxruntime").exists(),
        "nothing half-fetched is left to pack"
    );
}

#[test]
fn fetch_refuses_an_unpinned_target() {
    let Some(fx) = fixture("fetch_refuses_an_unpinned_target") else {
        return;
    };
    let pin = fx.write_pin(&fx.sha);
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-apple-darwin", &out);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("x86_64-apple-darwin"));
    assert!(!out.join("onnxruntime").exists());
}

#[test]
fn fetch_fails_closed_when_the_library_is_not_in_the_archive() {
    let Some(fx) = fixture("fetch_fails_closed_when_the_library_is_not_in_the_archive") else {
        return;
    };
    let pin = fx.dir.join("bad.pin");
    std::fs::write(
        &pin,
        format!(
            "version 9.9.9\n\
             lib x86_64-unknown-linux-gnu file://{d}/runtime.tgz {sha} \
             {TOP}/lib64/libonnxruntime.so {TOP}/LICENSE\n",
            d = fx.dir.display(),
            sha = fx.sha
        ),
    )
    .unwrap();
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(!res.status.success());
    assert!(!out.join("onnxruntime").exists());
}
