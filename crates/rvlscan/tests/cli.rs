use std::process::Command;

#[test]
fn version_flag_reports_name_and_semver() {
    let out = Command::new(env!("CARGO_BIN_EXE_rvlscan"))
        .arg("--version")
        .output()
        .expect("failed to run rvlscan binary");

    assert!(out.status.success(), "--version exited non-zero");
    let stdout = String::from_utf8(out.stdout).expect("stdout not utf-8");
    assert_eq!(
        stdout.trim(),
        concat!("rvlscan ", env!("CARGO_PKG_VERSION")),
        "--version must print '<binary> <semver>'"
    );
}
