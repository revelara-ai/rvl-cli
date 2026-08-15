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

// --- names are not credentials; expressions are not literals (po-av01j.172) --
//
// All six lines below are verbatim open-webui source that the lane reported as
// secret findings. Every one of them is a NAME or an EXPRESSION.

#[test]
fn identifier_shaped_values_are_not_high_entropy_secrets() {
    for (file, line) in [
        // A config key-name mapping table: the dict KEY contains `api_key`, so
        // the site reads as secret-named; the VALUE is an env var NAME that
        // scores 3.62 bits/char, over the generic rule's 3.5 gate.
        (
            "migrations/versions/3ff2c63645b8_reshape.py",
            "    'audio.stt.azure.api_key': 'AUDIO_STT_AZURE_API_KEY',",
        ),
        (
            "migrations/versions/3ff2c63645b8_reshape.py",
            "    'oauth.oidc.client_secret': 'oauth.client_secret',",
        ),
        // The same table read the other way: the VALUE is a dotted config path.
        ("routers/audio.py", "    'API_KEY': 'audio.tts.api_key',"),
        (
            "routers/audio.py",
            "    'OPENAI_API_KEY': 'audio.tts.openai.api_key',",
        ),
        // A natural-language phrase in an i18n translation file.
        (
            "src/lib/i18n/locales/de-DE/translation.json",
            "\t\"Application DN Password\": \"Anwendungs-DN-Passwort\",",
        ),
        // An HTML autocomplete attribute, not an assignment of anything.
        (
            "src/routes/auth/+page.svelte",
            "autocomplete={mode === 'signup' ? 'new-password' : 'current-password'}",
        ),
    ] {
        let f = scan_bytes(file, line);
        assert!(
            f.is_empty(),
            "identifier/phrase must not flag: {line} -> {f:?}"
        );
    }
}

#[test]
fn a_bare_identifier_right_hand_side_is_never_a_weak_default() {
    // No literal appears anywhere on these lines: the right-hand side is a
    // parameter (Python) and a variable (TypeScript). A weak default needs
    // something actually written down to be weak.
    for (file, line) in [
        (
            "backend/open_webui/models/auths.py",
            "            auth_row.password = new_password",
        ),
        (
            "src/lib/apis/auths/index.ts",
            "\t\t\tnew_password: newPassword",
        ),
        ("app/models.py", "        self.password = hashed"),
        ("cfg.go", "\tcfg.Password = envPassword"),
    ] {
        let f = scan_bytes(file, line);
        assert!(
            !f.iter().any(|x| x.rule_id == "weak_default_credential"),
            "non-literal assignment must not flag: {line} -> {f:?}"
        );
    }
}

#[test]
fn quoted_weak_defaults_in_code_still_fire() {
    // The narrowing above is about LITERALS, not about code files: the same
    // files with a quoted value are real hardcoded credentials (both lines are
    // verbatim open-webui source) and must still fire.
    for (file, line) in [
        (
            "backend/open_webui/retrieval/vector/dbs/oracle23ai.py",
            "ORACLE_DB_PASSWORD = \"Welcome123456\"",
        ),
        (
            "backend/open_webui/routers/auths.py",
            "        admin_password = 'admin'",
        ),
        ("src/config.ts", "const dbPassword = 'changeit'"),
    ] {
        let f = scan_bytes(file, line);
        assert!(
            f.iter().any(|x| x.rule_id == "weak_default_credential"),
            "quoted weak credential must still fire: {line} -> {f:?}"
        );
    }
    // And an UNQUOTED value in a config format, where unquoted IS the literal.
    let ini = scan_bytes("conf/basic_auth.ini", "admin_password = password1234");
    assert!(
        ini.iter().any(|x| x.rule_id == "weak_default_credential"),
        "unquoted .ini literal must still fire: {ini:?}"
    );
}

#[test]
fn real_credential_shapes_survive_the_name_shape_narrowing() {
    // The narrowing must not touch the detection path. Each value below is a
    // credential SHAPE — provider-prefixed, base64, hex — none of which is a
    // separator-joined identifier.
    let cases: [(&str, &str, &str); 6] = [
        ("api_key = \"@\"", &gcp_key(), "gcp_api_key"),
        (
            "aws_secret_access_key = \"@\"",
            &aws_secret(),
            "aws_secret_access_key",
        ),
        (
            "client_secret = \"@\"",
            &generic_secret(),
            "generic_api_key",
        ),
        // 32 hex chars: high entropy, no separators.
        (
            "token = \"@\"",
            "a3f9d2b8c1e47f60a9b2c3d4e5f60718",
            "generic_api_key",
        ),
        // URL-safe base64 blob with underscores AND dashes, mixed case + digits:
        // separators are present but the tokens are not alphabetic words.
        (
            "private_key = \"@\"",
            "kR9_pQ2-vX7mZ4nT6yB1cE8fH3jL0aGw",
            "generic_api_key",
        ),
        // All-caps with underscores would be name-shaped -- unless it is hex,
        // which carries digits and no word tokens.
        (
            "apikey = \"@\"",
            "9F3A2B7C4D1E6F80A5B9C2D3E4F60718",
            "generic_api_key",
        ),
    ];
    for (tmpl, value, want) in cases {
        let line = tmpl.replace('@', value);
        let f = scan_bytes("app/config.py", &line);
        assert!(
            f.iter().any(|x| x.rule_id == want),
            "real credential must still fire as {want}: {line} -> {f:?}"
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
