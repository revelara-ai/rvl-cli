//! G5 content-pattern retriever tests (po-av01j.6).
//!
//! Every planted token below is FAKE and assembled by string concatenation so
//! no token-shaped literal ever sits whole in this source file (keeps secret
//! scanners, including this one, from flagging the fixture source itself).

use rvl_content::{scan_bytes, scan_root, shannon_entropy, to_sites};

// --- fake token constructors (shape-valid, never real) ---

fn aws_key() -> String {
    ["AK", "IA", "Q3RS7T9U", "V2WX4YZA"].concat() // AKIA + 16 [0-9A-Z]
}

fn github_token() -> String {
    ["ghp", "_", "AbCd1234EfGh5678IjKl9012MnOp3456QrSt"].concat() // ghp_ + 36
}

fn gcp_key() -> String {
    ["AI", "za", "SyDx4Q9mPzW7vK2nR5tY8uB3cE6fH1jL0aG"].concat() // AIza + 35
}

fn slack_token() -> String {
    [
        "xox",
        "b-",
        "123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx",
    ]
    .concat()
}

fn stripe_key() -> String {
    ["sk", "_live_", "4eC39HqLyjWDarjtT1zdp7dc"].concat()
}

fn pem_header() -> String {
    ["-----BEGIN RSA ", "PRIVATE KEY-----"].concat()
}

fn aws_secret() -> String {
    // 40 base64-ish chars, decent entropy, not a real credential.
    ["dGhpc0lzTm90QVJlYWxLZXlC", "dXRJdEhhc0VudHJv"].concat()
}

fn generic_secret() -> String {
    ["hF9mQ2xLp7", "Rt4KvN8sYw"].concat() // 20 mixed chars
}

fn rule_ids(findings: &[rvl_content::ContentFinding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule_id.as_str()).collect()
}

// --- detection per rule family ---

#[test]
fn detects_each_token_family() {
    let content = format!(
        "aws = \"{}\"\n\
         gh = \"{}\"\n\
         gcp = \"{}\"\n\
         slack = \"{}\"\n\
         stripe = \"{}\"\n\
         {}\n\
         aws_secret_access_key = \"{}\"\n",
        aws_key(),
        github_token(),
        gcp_key(),
        slack_token(),
        stripe_key(),
        pem_header(),
        aws_secret(),
    );
    let found = scan_bytes("app/config.py", &content);
    let ids = rule_ids(&found);
    for want in [
        "aws_access_key_id",
        "github_token",
        "gcp_api_key",
        "slack_token",
        "stripe_secret_key",
        "private_key_pem",
        "aws_secret_access_key",
    ] {
        assert!(ids.contains(&want), "missing rule {want} in {ids:?}");
    }
    // Well-known token shapes are high severity; line numbers are 1-based.
    let aws = found
        .iter()
        .find(|f| f.rule_id == "aws_access_key_id")
        .unwrap();
    assert_eq!(aws.severity, "high");
    assert_eq!(aws.line, 1);
    assert_eq!(aws.file, "app/config.py");
    let pem = found
        .iter()
        .find(|f| f.rule_id == "private_key_pem")
        .unwrap();
    assert_eq!(pem.line, 6);
}

#[test]
fn generic_assignment_needs_entropy() {
    // High-entropy literal assigned to a secret-named variable: flagged, medium.
    let hot = format!("api_key = \"{}\"\n", generic_secret());
    let found = scan_bytes("cfg.go", &hot);
    assert_eq!(rule_ids(&found), vec!["generic_api_key"], "{found:?}");
    assert_eq!(found[0].severity, "medium");
    assert!(found[0].entropy >= 3.5, "entropy {}", found[0].entropy);

    // Low-entropy value with the same shape: not a finding.
    let cold = "api_key = \"aaaaaaaaaaaaaaaaaaaa\"\n";
    assert!(scan_bytes("cfg.go", cold).is_empty());

    // A non-secret-named variable never triggers the generic rule.
    let named = format!("greeting = \"{}\"\n", generic_secret());
    assert!(scan_bytes("cfg.go", &named).is_empty());
}

#[test]
fn shannon_entropy_known_values() {
    assert_eq!(shannon_entropy(""), 0.0);
    assert_eq!(shannon_entropy("aaaa"), 0.0);
    // Four distinct equiprobable symbols = 2 bits/char.
    assert!((shannon_entropy("abcd") - 2.0).abs() < 1e-9);
    assert!(shannon_entropy(&generic_secret()) > 3.5);
}

// --- redaction: the raw secret must never appear anywhere ---

#[test]
fn redaction_never_carries_the_secret() {
    let content = format!(
        "aws = \"{}\"\napi_key = \"{}\"\n",
        aws_key(),
        generic_secret()
    );
    let found = scan_bytes("a.py", &content);
    assert_eq!(found.len(), 2);

    let serialized = serde_json::to_string(&found).unwrap();
    assert!(
        !serialized.contains(&aws_key()) && !serialized.contains(&generic_secret()),
        "raw secret leaked into serialized findings"
    );

    let sites = to_sites(&found, "snap");
    let sites_json = serde_json::to_string(&sites).unwrap();
    assert!(
        !sites_json.contains(&aws_key()) && !sites_json.contains(&generic_secret()),
        "raw secret leaked into packet sites"
    );

    // Masked preview: at most first 4 chars + ellipsis.
    let aws = found
        .iter()
        .find(|f| f.rule_id == "aws_access_key_id")
        .unwrap();
    assert_eq!(aws.masked, "AKIA\u{2026}");
}

// --- packet schema shape ---

#[test]
fn sites_ride_the_packet_schema_control_shape() {
    let content = format!("gh = \"{}\"\n", github_token());
    let found = scan_bytes("internal/cfg.go", &content);
    let sites = to_sites(&found, "snap-1");
    assert_eq!(sites.len(), 1);
    let s = &sites[0];
    assert_eq!(s.client_type, "secret");
    assert_eq!(s.method, "github_token");
    assert_eq!(s.file_path, "internal/cfg.go");
    assert_eq!(s.line_number, 1);
    assert_eq!(s.lang, "content");
    assert_eq!(s.snapshot_id, "snap-1");
    assert_eq!(s.snippet, found[0].masked);
    assert!(s.enclosing_function_body.is_empty(), "no source may ride");
    // The class/waiver key downstream: `secret.<rule_id>`.
    assert_eq!(s.site_key(), "internal/cfg.go:1:secret:github_token");
}

// --- allowlist / false-positive hooks ---

#[test]
fn allowlist_suppresses_placeholders_and_inline_allow() {
    // AWS's own documented example key: contains EXAMPLE.
    let doc = "aws = \"AKIAIOSFODNN7EXAMPLE\"\n";
    assert!(
        scan_bytes("a.py", doc).is_empty(),
        "EXAMPLE key must not flag"
    );

    // Interpolation / template placeholders.
    let interp = "api_key = \"${API_KEY_FROM_ENV}\"\n";
    assert!(scan_bytes("a.py", interp).is_empty());

    // Inline allow pragmas: ours and gitleaks's (migration-friendly).
    let ours = format!("gh = \"{}\" # rvlscan:allow\n", github_token());
    assert!(scan_bytes("a.py", &ours).is_empty());
    let theirs = format!("gh = \"{}\" # gitleaks:allow\n", github_token());
    assert!(scan_bytes("a.py", &theirs).is_empty());
}

#[test]
fn specific_rule_shadows_generic_on_the_same_line() {
    // `token = "ghp_..."` matches both github_token and the generic
    // assignment rule; one secret must be ONE finding.
    let line = format!("token = \"{}\"\n", github_token());
    let found = scan_bytes("a.py", &line);
    assert_eq!(rule_ids(&found), vec!["github_token"]);
}

// --- walk behavior: binary / vendored / lockfile skip ---

#[test]
fn walk_skips_binary_vendored_lockfiles_and_huge_files() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let planted = format!("k = \"{}\"\n", aws_key());

    // A real hit in a normal file.
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/app.py"), &planted).unwrap();
    // Vendored dirs are skipped.
    std::fs::create_dir_all(root.join("node_modules/x")).unwrap();
    std::fs::write(root.join("node_modules/x/a.js"), &planted).unwrap();
    std::fs::create_dir_all(root.join("vendor")).unwrap();
    std::fs::write(root.join("vendor/v.go"), &planted).unwrap();
    // Lockfiles are skipped.
    std::fs::write(root.join("Cargo.lock"), &planted).unwrap();
    // Binary content (NUL byte) is skipped.
    let mut bin = planted.clone().into_bytes();
    bin.insert(0, 0u8);
    std::fs::write(root.join("blob.dat"), &bin).unwrap();
    // Minified assets are skipped.
    std::fs::write(root.join("app.min.js"), &planted).unwrap();
    // Files over the size cap are skipped.
    let mut huge = String::with_capacity(1_100_000);
    huge.push_str(&planted);
    while huge.len() <= 1_048_576 {
        huge.push_str("padding padding padding padding padding padding\n");
    }
    std::fs::write(root.join("huge.txt"), &huge).unwrap();

    let found = scan_root(root);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].file, "src/app.py");
}

#[test]
fn scan_root_is_deterministic_and_repo_relative() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("b")).unwrap();
    std::fs::write(root.join("b/two.py"), format!("k = \"{}\"\n", aws_key())).unwrap();
    std::fs::write(
        root.join("a_one.env"),
        format!("gh = \"{}\"\n", github_token()),
    )
    .unwrap();

    let found = scan_root(root);
    let files: Vec<&str> = found.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(
        files,
        vec!["a_one.env", "b/two.py"],
        "sorted, repo-relative"
    );
}

// --- weak / default credentials (po-av01j.133.9) ---

#[test]
fn weak_shipped_credentials_are_found_despite_low_entropy() {
    // Both lines are real mlflow source the lane previously missed. Neither
    // reached the entropy gate: they failed the PATTERN, because a leading \b
    // blocked snake_case identifiers, "passphrase" was not in the vocabulary,
    // and values had to be quoted and >=16 chars.
    for line in [
        "admin_password = password1234",
        "DEFAULT_KEK_PASSPHRASE = \"mlflow-default-kek-passphrase-for-development-only\"",
    ] {
        let f = scan_bytes("conf/app.ini", line);
        assert!(
            f.iter().any(|x| x.rule_id == "weak_default_credential"),
            "weak shipped credential must fire: {line}"
        );
    }
}

#[test]
fn code_references_and_key_names_are_not_credentials() {
    // `password = request.authorization.password` READS a value; the dotted
    // form passed the value character class on the first version of this rule.
    // `PASSWORD = "password"` names a config key rather than setting a secret.
    for line in [
        "password = request.authorization.password",
        "PASSWORD = \"password\"",
        "api_key = os.environ[\"API_KEY\"]",
        "password_hash = \"a3f9d2b8c1e47f60a9b2c3d4e5f60718\"",
    ] {
        let f = scan_bytes("app/config.py", line);
        assert!(
            !f.iter().any(|x| x.rule_id == "weak_default_credential"),
            "must not flag: {line}"
        );
    }
}
