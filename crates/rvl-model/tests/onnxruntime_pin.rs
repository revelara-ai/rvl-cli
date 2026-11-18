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
    let mut members = BTreeSet::new();
    for r in rows.iter().filter(|r| r[0] == "lib") {
        assert_eq!(
            r.len(),
            6,
            "lib <triple> <url> <sha256> <lib-member> <license-member>: {r:?}"
        );
        let (triple, url, sha, member) = (&r[1], &r[2], &r[3], &r[4]);
        assert!(seen.insert(triple.clone()), "{triple} pinned twice");
        assert!(
            members.insert(member.clone()),
            "{triple} takes another target's library from the package"
        );
        assert!(
            url.starts_with("https://api.nuget.org/v3-flatcontainer/microsoft.ml.onnxruntime/")
                && url.ends_with(".nupkg"),
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

/// A fake package laid out like Microsoft's NuGet package, plus its sha256.
struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    sha: String,
}

const LIB: &str = "runtimes/linux-x64/native/libonnxruntime.so";

/// CRC-32 (IEEE), which every zip entry carries.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

/// A zip of `files`, stored uncompressed: enough for `unzip`, and no zip tool
/// or crate is needed to build it.
fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
    let u16le = |v: usize| u16::try_from(v).unwrap().to_le_bytes();
    let u32le = |v: usize| u32::try_from(v).unwrap().to_le_bytes();
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in files {
        let offset = out.len();
        let crc = crc32(data).to_le_bytes();
        // version 2.0, no flags, stored, 1980-01-01 00:00
        let common = [&20u16.to_le_bytes()[..], &[0, 0, 0, 0, 0, 0, 0x21, 0], &crc].concat();
        let sizes = [u32le(data.len()), u32le(data.len())].concat();
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&common);
        out.extend_from_slice(&sizes);
        out.extend_from_slice(&u16le(name.len()));
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        // made by Unix, so the external attributes below are a mode
        central.extend_from_slice(&0x0314u16.to_le_bytes());
        central.extend_from_slice(&common);
        central.extend_from_slice(&sizes);
        central.extend_from_slice(&u16le(name.len()));
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&(0o100_644u32 << 16).to_le_bytes());
        central.extend_from_slice(&u32le(offset));
        central.extend_from_slice(name.as_bytes());
    }
    let (cd_offset, cd_size) = (out.len(), central.len());
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&u16le(files.len()));
    out.extend_from_slice(&u16le(files.len()));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_offset));
    out.extend_from_slice(&[0, 0]);
    out
}

fn fixture(test: &str) -> Option<Fixture> {
    for tool in ["unzip", "curl"] {
        if !have(tool) {
            rvl_testgate::skip(test, format_args!("`{tool}` not on PATH"));
            return None;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let package = zip(&[
        ("LICENSE", b"MIT License\n"),
        ("ThirdPartyNotices.txt", b"notices\n"),
        ("Microsoft.ML.OnnxRuntime.nuspec", b"<package/>\n"),
        ("build/native/include/onnxruntime_c_api.h", b"/* api */\n"),
        (LIB, b"ELF-ish"),
        ("runtimes/linux-arm64/native/libonnxruntime.so", b"ELF-arm"),
    ]);
    std::fs::write(dir.join("runtime.nupkg"), &package).unwrap();
    let sha = hex::encode(sha2::Sha256::digest(&package));
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
                 lib x86_64-unknown-linux-gnu file://{d}/runtime.nupkg {sha} \
                 {LIB} LICENSE\n",
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
        "the bundle holds the library itself"
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
             lib x86_64-unknown-linux-gnu file://{d}/runtime.nupkg {sha} \
             runtimes/linux-x64/lib/libonnxruntime.so LICENSE\n",
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
