//! The release pin for the vendored libclang (po-av01j.49), and the fetch
//! tooling that honors it.
//!
//! `crates/cindex/libclang.pin` is the single source of truth: release CI's
//! `ci/fetch-libclang.sh` reads it, and these tests hold it to the release
//! target list in dist-workspace.toml, so adding a target without pinning an
//! engine for it fails here instead of at tag time. The fetch script is
//! driven against local `file://` fixtures: it must refuse a checksum
//! mismatch and leave nothing behind.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn pin_text() -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("libclang.pin"))
        .expect("read crates/cindex/libclang.pin")
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
fn every_release_target_pins_exactly_one_checksummed_libclang() {
    let rows = pin_rows(&pin_text());
    let version = rows
        .iter()
        .find(|r| r[0] == "version")
        .map(|r| r[1].clone())
        .expect("a `version` line");

    let libs: Vec<&Vec<String>> = rows.iter().filter(|r| r[0] == "lib").collect();
    let mut seen = BTreeSet::new();
    let mut shas = BTreeSet::new();
    for r in &libs {
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
        assert!(url.starts_with("https://"), "{triple}: {url}");
        assert!(
            url.contains(&version),
            "{triple}: url is not version {version}: {url}"
        );
        assert!(is_sha256(sha), "{triple}: not a lowercase sha256: {sha}");
        let want = if triple.contains("apple-darwin") {
            "libclang.dylib"
        } else {
            "libclang.so"
        };
        assert_eq!(
            Path::new(member).file_name().unwrap(),
            want,
            "{triple}: the member must be the name cindex looks for (engine::LIB_NAME)"
        );
    }
    assert_eq!(
        seen,
        dist_targets(),
        "libclang.pin and dist-workspace.toml `targets` must name the same triples"
    );

    let headers: Vec<&Vec<String>> = rows.iter().filter(|r| r[0] == "headers").collect();
    assert_eq!(headers.len(), 1, "exactly one `headers` line");
    let h = headers[0];
    assert_eq!(h.len(), 4, "headers <url> <sha256> <dir-in-tarball>: {h:?}");
    assert!(
        h[1].starts_with("https://") && h[1].contains(&version),
        "{h:?}"
    );
    assert!(is_sha256(&h[2]), "{h:?}");
    // The builtin headers must come from the same clang as the library.
    assert!(h[3].contains(&version), "{h:?}");
}

// ---------------------------------------------------------------------------
// ci/fetch-libclang.sh against local fixtures
// ---------------------------------------------------------------------------

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn sha256_of(path: &Path) -> String {
    let out = Command::new("python3")
        .arg("-c")
        .arg("import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())")
        .arg(path)
        .output()
        .unwrap();
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

/// A fake wheel and a fake clang source tarball, plus a pin naming them.
/// Returns None (with a SKIP line) where the fixture tools are missing.
struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    wheel_sha: String,
    tarball_sha: String,
}

fn fixture(test: &str) -> Option<Fixture> {
    for tool in ["python3", "tar", "xz", "unzip", "curl"] {
        if !have(tool) {
            rvl_testgate::skip(test, format_args!("`{tool}` not on PATH"));
            return None;
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().to_path_buf();
    let ok = Command::new("python3")
        .arg("-c")
        .arg(
            "import zipfile,sys\n\
             z=zipfile.ZipFile(sys.argv[1],'w')\n\
             z.writestr('libclang-9.9.9.data/platlib/clang/native/libclang.so','ELF-ish')\n\
             z.writestr('libclang-9.9.9.dist-info/LICENSE.TXT','Apache-2.0 WITH LLVM-exception')\n\
             z.close()",
        )
        .arg(dir.join("fake.whl"))
        .status()
        .unwrap()
        .success();
    assert!(ok, "build the fake wheel");
    let src = dir.join("src/clang-9.9.9.src/lib/Headers");
    std::fs::create_dir_all(src.join("openmp_wrappers")).unwrap();
    std::fs::write(src.join("stddef.h"), "/* builtin */\n").unwrap();
    std::fs::write(src.join("openmp_wrappers/cmath"), "\n").unwrap();
    std::fs::write(src.join("CMakeLists.txt"), "# build only\n").unwrap();
    std::fs::write(dir.join("src/clang-9.9.9.src/README.txt"), "not a header\n").unwrap();
    let ok = Command::new("tar")
        .arg("-cJf")
        .arg(dir.join("clang.src.tar.xz"))
        .arg("-C")
        .arg(dir.join("src"))
        .arg("clang-9.9.9.src")
        .status()
        .unwrap()
        .success();
    assert!(ok, "build the fake source tarball");
    let wheel_sha = sha256_of(&dir.join("fake.whl"));
    let tarball_sha = sha256_of(&dir.join("clang.src.tar.xz"));
    Some(Fixture {
        _tmp: tmp,
        dir,
        wheel_sha,
        tarball_sha,
    })
}

impl Fixture {
    fn write_pin(&self, wheel_sha: &str, tarball_sha: &str) -> PathBuf {
        let pin = self.dir.join("test.pin");
        std::fs::write(
            &pin,
            format!(
                "version 9.9.9\n\
                 headers file://{d}/clang.src.tar.xz {tarball_sha} clang-9.9.9.src/lib/Headers\n\
                 lib x86_64-unknown-linux-gnu file://{d}/fake.whl {wheel_sha} \
                 libclang-9.9.9.data/platlib/clang/native/libclang.so \
                 libclang-9.9.9.dist-info/LICENSE.TXT\n",
                d = self.dir.display()
            ),
        )
        .unwrap();
        pin
    }

    fn fetch(&self, pin: &Path, triple: &str, out: &Path) -> std::process::Output {
        Command::new("bash")
            .arg(repo_root().join("ci/fetch-libclang.sh"))
            .arg(triple)
            .arg(out)
            .env("LIBCLANG_PIN", pin)
            .output()
            .expect("run ci/fetch-libclang.sh")
    }
}

#[test]
fn fetch_lays_out_the_bundle_cindex_looks_for() {
    let Some(fx) = fixture("fetch_lays_out_the_bundle_cindex_looks_for") else {
        return;
    };
    let pin = fx.write_pin(&fx.wheel_sha, &fx.tarball_sha);
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(
        res.status.success(),
        "fetch failed: {}",
        String::from_utf8_lossy(&res.stderr)
    );
    let bundle = out.join("libclang");
    assert_eq!(
        std::fs::read_to_string(bundle.join("libclang.so")).unwrap(),
        "ELF-ish"
    );
    assert!(bundle.join("include/stddef.h").is_file());
    assert!(bundle.join("include/openmp_wrappers/cmath").is_file());
    assert!(
        !bundle.join("include/CMakeLists.txt").exists(),
        "build files are not headers"
    );
    assert!(
        bundle.join("LICENSE.TXT").is_file(),
        "LLVM's license ships with it"
    );
    // Re-running replaces the bundle rather than failing or merging.
    let again = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(
        again.status.success(),
        "{}",
        String::from_utf8_lossy(&again.stderr)
    );
    assert!(bundle.join("libclang.so").is_file());
}

#[test]
fn fetch_fails_closed_on_a_library_checksum_mismatch() {
    let Some(fx) = fixture("fetch_fails_closed_on_a_library_checksum_mismatch") else {
        return;
    };
    let pin = fx.write_pin(&"0".repeat(64), &fx.tarball_sha);
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(!res.status.success(), "a tampered library must not ship");
    let err = String::from_utf8_lossy(&res.stderr);
    assert!(err.contains("checksum"), "{err}");
    assert!(
        !out.join("libclang").exists(),
        "nothing half-fetched is left to pack"
    );
}

#[test]
fn fetch_fails_closed_on_a_headers_checksum_mismatch() {
    let Some(fx) = fixture("fetch_fails_closed_on_a_headers_checksum_mismatch") else {
        return;
    };
    let pin = fx.write_pin(&fx.wheel_sha, &"f".repeat(64));
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "x86_64-unknown-linux-gnu", &out);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("checksum"));
    assert!(!out.join("libclang").exists());
}

#[test]
fn fetch_refuses_an_unpinned_target() {
    let Some(fx) = fixture("fetch_refuses_an_unpinned_target") else {
        return;
    };
    let pin = fx.write_pin(&fx.wheel_sha, &fx.tarball_sha);
    let out = fx.dir.join("dist-extras");
    let res = fx.fetch(&pin, "riscv64gc-unknown-linux-gnu", &out);
    assert!(!res.status.success());
    assert!(String::from_utf8_lossy(&res.stderr).contains("riscv64gc-unknown-linux-gnu"));
    assert!(!out.join("libclang").exists());
}
