//! Construction call sites judged by config-key specs: a TLS config that skips
//! verification, a broken cipher, a database opened with a literal password.
//!
//! The retrievers report these constructions as classic call sites, with what
//! they saw in `const_args` (see "Constructions that are call sites" in
//! `docs/retrievers.md`). The deadline lane answers whether such a call
//! blocks; it cannot say that `InsecureSkipVerify: true` violates a control.
//! These rules are the config lane's rules: one setting, one expectation, one
//! control. So a construction is judged with the config-key grammar and its
//! evaluator, unchanged, with the format [`FORMAT`] and one key per rule:
//!
//!   * `<class>` judges the construction itself, whatever its arguments
//!     (`crypto/des.NewCipher` with `absent`);
//!   * `<class>(<arg>)` judges one argument, by its keyword or property name
//!     (`requests.get(verify)`), else by position (`database/sql.Open(arg1)`).
//!
//! `<class>` is the site's `client_type.func`. A site or argument that no spec
//! names is not judged, so an md5 hash, whose meaning depends on its use,
//! stays a question for the decision model. An argument whose value is not a
//! constant abstains: the expectation compares values, and a name is not one.
//!
//! Only runtime sites are judged, as in the other construction lanes: a test
//! that skips verification against a local server is the common case there.

use crate::{eval, ConfigPacket, ProvenanceStep, Resolution};
use rvl_core::{ConstArg, ScopeClass, Site, Verdict};
use rvl_spec::SpecCache;

/// The config-key `format` of a construction rule.
pub const FORMAT: &str = "construction";

/// One judged construction or argument.
#[derive(Debug, Clone, PartialEq)]
pub struct SiteFinding {
    /// The spec key that judged it, e.g. `database/sql.Open(arg1)`.
    pub key: String,
    /// `file:line`.
    pub site: String,
    pub verdict: Verdict,
    pub reason: String,
    pub control: String,
    pub severity: String,
    pub fix: String,
}

/// How a rule key names an argument: its keyword or property name, else its
/// position.
fn selector(arg: &ConstArg) -> String {
    if arg.name.is_empty() {
        format!("arg{}", arg.index)
    } else {
        arg.name.clone()
    }
}

/// A string literal's contents, so a rule compares `0` and not `'0'`, the way
/// a config packet carries a canonical value. Anything else as written.
fn unquoted(value: &str) -> &str {
    for q in ['"', '\'', '`'] {
        if let Some(inner) = value.strip_prefix(q).and_then(|rest| rest.strip_suffix(q)) {
            return inner;
        }
    }
    value
}

fn judge(site: &Site, key: &str, value: &str, specs: &SpecCache) -> SiteFinding {
    let packet = ConfigPacket {
        snapshot_id: site.snapshot_id.clone(),
        format: FORMAT.to_string(),
        file_path: site.file_path.clone(),
        line: site.line_number,
        unit: site.symbol.clone(),
        key: key.to_string(),
        resolved_value: Some(value.to_string()),
        resolution: Resolution::AsAuthored,
        provenance: vec![ProvenanceStep::new(&site.file_path, key, "explicit")],
    };
    let f = eval::evaluate(&packet, &[], specs);
    SiteFinding {
        key: key.to_string(),
        site: format!("{}:{}", site.file_path, site.line_number),
        verdict: f.verdict,
        reason: f.reason,
        control: f.control,
        severity: f.severity,
        fix: f.fix,
    }
}

/// Judge every runtime call site a construction rule names. One finding per
/// rule that applies, in site order.
pub fn evaluate(sites: &[Site], specs: &SpecCache) -> Vec<SiteFinding> {
    let mut out = Vec::new();
    for site in sites
        .iter()
        .filter(|s| s.site_kind.is_empty() && s.scope() == ScopeClass::Runtime)
    {
        let class = format!("{}.{}", site.client_type, site.method);
        if specs.config_key(FORMAT, &class).is_some() {
            out.push(judge(site, &class, "", specs));
        }
        for arg in &site.const_args {
            let key = format!("{class}({})", selector(arg));
            if specs.config_key(FORMAT, &key).is_none() {
                continue;
            }
            if !matches!(arg.how.as_str(), "literal" | "named_constant") {
                out.push(SiteFinding {
                    site: format!("{}:{}", site.file_path, site.line_number),
                    verdict: Verdict::Abstain,
                    reason: format!(
                        "{key} is not a constant ({}), so its value cannot be judged",
                        arg.how
                    ),
                    key,
                    control: String::new(),
                    severity: String::new(),
                    fix: String::new(),
                });
                continue;
            }
            out.push(judge(site, &key, unquoted(&arg.value), specs));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvl_spec::SpecFile;

    /// The rules this lane is built for, in the artifact's own JSON: what the
    /// spec producer is asked to publish.
    const RULES: &str = include_str!("../testdata/construction_rules.json");

    fn specs() -> SpecCache {
        let file: SpecFile = serde_json::from_str(RULES).expect("the rules parse");
        SpecCache::from_file(file)
    }

    /// A site the way a retriever stream delivers it, so the credential
    /// redaction on read applies.
    fn site(file: &str, class: (&str, &str), args: &[(u32, &str, &str, &str)]) -> Site {
        let args: Vec<_> = args
            .iter()
            .map(|(index, name, value, how)| {
                serde_json::json!({"index": index, "name": name, "value": value, "how": how})
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "file_path": file, "line_number": 7, "client_type": class.0,
            "func": class.1, "symbol": "f", "const_args": args,
        }))
        .unwrap()
    }

    fn judged(s: Site) -> Vec<SiteFinding> {
        evaluate(&[s], &specs())
    }

    fn one(s: Site) -> SiteFinding {
        let mut got = judged(s);
        assert_eq!(got.len(), 1, "{got:?}");
        got.remove(0)
    }

    /// One rule's fixture: the site's client type and func, the argument
    /// (a name, `#<index>` for a positional one, `""` for the construction
    /// itself), a violating value, an allowed value (`""` when the rule
    /// allows none) and the control.
    type Case = (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    );

    #[rustfmt::skip]
    const CASES: &[Case] = &[
        ("crypto/tls.Config", "InsecureSkipVerify", "InsecureSkipVerify", "true", "false", "RC-059"),
        ("crypto/tls.Config", "MinVersion", "MinVersion", "769", "771", "RC-059"),
        ("crypto/des", "NewCipher", "", "", "", "RC-059"),
        ("crypto/des", "NewTripleDESCipher", "", "", "", "RC-059"),
        ("crypto/rc4", "NewCipher", "", "", "", "RC-059"),
        ("ssl", "CERT_NONE", "", "", "", "RC-059"),
        ("ssl", "_create_unverified_context", "", "", "", "RC-059"),
        ("cryptography.hazmat.primitives.ciphers.modes", "ECB", "", "", "", "RC-059"),
        ("Crypto.Cipher.DES", "new", "", "", "", "RC-059"),
        ("Cryptodome.Cipher.DES3", "new", "", "", "", "RC-059"),
        ("ssl.SSLContext", "check_hostname", "check_hostname", "False", "True", "RC-059"),
        ("requests", "get", "verify", "False", "'/etc/ca.pem'", "RC-059"),
        ("httpx", "Client", "verify", "False", "True", "RC-059"),
        ("tls.ConnectionOptions", "rejectUnauthorized", "rejectUnauthorized", "false", "true", "RC-059"),
        ("process.env", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_TLS_REJECT_UNAUTHORIZED", "'0'", "'1'", "RC-059"),
        ("crypto", "createCipheriv", "#0", "'des-ede3-cbc'", "'aes-256-gcm'", "RC-059"),
        ("crypto", "createDecipheriv", "#0", "'aes-128-ecb'", "'aes-128-cbc'", "RC-059"),
        ("database/sql", "Open", "#1", "\"postgres://app:hunter2@db/app\"", "\"postgres://app@db/app\"", "RC-056"),
        ("github.com/jackc/pgx/v5/pgxpool", "New", "#1", "\"postgres://app:hunter2@db\"", "\"postgres://db\"", "RC-056"),
        ("psycopg2", "connect", "#0", "'dbname=app password=hunter2'", "'dbname=app host=db'", "RC-056"),
        ("psycopg", "connect", "password", "'hunter2'", "", "RC-056"),
        ("sqlalchemy", "create_engine", "#0", "'postgresql://app:hunter2@db/app'", "'sqlite:///app.db'", "RC-056"),
        ("pg.Pool", "constructor", "connectionString", "'postgres://app:hunter2@db/app'", "'postgres://db/app'", "RC-056"),
        ("pg.Client", "constructor", "password", "'hunter2'", "", "RC-056"),
    ];

    fn case_site(c: &Case, value: &str) -> Site {
        let (ty, func, arg, ..) = *c;
        let args: Vec<(u32, &str, &str, &str)> = match arg {
            "" => vec![],
            _ => match arg.strip_prefix('#') {
                Some(i) => vec![(i.parse().unwrap(), "", value, "literal")],
                None => vec![(0, arg, value, "literal")],
            },
        };
        site("app.src", (ty, func), &args)
    }

    #[test]
    fn every_rule_has_a_violating_and_an_allowed_case() {
        for c in CASES {
            let what = format!("{}.{} {}", c.0, c.1, c.2);
            let f = one(case_site(c, c.3));
            assert_eq!(f.verdict, Verdict::Violates, "{what}: {}", f.reason);
            assert_eq!(f.control, c.5, "{what}");
            assert!(
                !f.severity.is_empty() && !f.fix.is_empty(),
                "{what}: judged"
            );
            assert!(!f.reason.contains("hunter2"), "{what}: {}", f.reason);
            if !c.4.is_empty() {
                let f = one(case_site(c, c.4));
                assert_eq!(f.verdict, Verdict::Satisfies, "{what}: {}", f.reason);
            }
        }
    }

    #[test]
    fn a_hash_is_not_judged() {
        // md5 and sha1 key caches as often as they guard integrity, so no
        // rule names them.
        assert!(judged(site("h.go", ("crypto/md5", "Sum"), &[])).is_empty());
        assert!(judged(site("h.py", ("hashlib", "md5"), &[])).is_empty());
        assert!(judged(site(
            "h.ts",
            ("crypto", "createHash"),
            &[(0, "", "'md5'", "literal")]
        ))
        .is_empty());
    }

    #[test]
    fn a_value_that_is_not_a_constant_abstains() {
        let f = one(site(
            "tls.go",
            ("crypto/tls.Config", "InsecureSkipVerify"),
            &[(0, "InsecureSkipVerify", "skip", "name")],
        ));
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
        assert!(f.reason.contains("not a constant (name)"), "{}", f.reason);
        // A password read from the environment is a name too: redacted on
        // read, but not a literal, so it is not a finding.
        let f = one(site(
            "db.py",
            ("psycopg", "connect"),
            &[(0, "password", "os.environ['PW']", "name")],
        ));
        assert_eq!(f.verdict, Verdict::Abstain, "{}", f.reason);
    }

    #[test]
    fn an_argument_no_rule_names_is_not_judged() {
        let got = judged(site(
            "db.ts",
            ("pg.Pool", "constructor"),
            &[(0, "host", "'db'", "literal"), (0, "max", "5", "literal")],
        ));
        assert!(got.is_empty(), "{got:?}");
    }

    #[test]
    fn only_runtime_sites_are_judged() {
        let s = site(
            "tls_test.go",
            ("crypto/tls.Config", "InsecureSkipVerify"),
            &[(0, "InsecureSkipVerify", "true", "literal")],
        );
        assert_ne!(s.scope(), ScopeClass::Runtime);
        assert!(judged(s).is_empty());
    }

    #[test]
    fn a_rule_is_keyed_on_the_class_and_the_argument() {
        let f = one(site(
            "t.py",
            ("requests", "get"),
            &[(1, "verify", "False", "literal")],
        ));
        assert_eq!(f.key, "requests.get(verify)");
        assert_eq!(f.site, "t.py:7");
        assert!(f.reason.starts_with("equal to False"), "{}", f.reason);
        let f = one(site("c.go", ("crypto/des", "NewCipher"), &[]));
        assert_eq!(f.key, "crypto/des.NewCipher");
        assert!(
            f.reason
                .starts_with("present where the spec forbids it: crypto/des.NewCipher;"),
            "{}",
            f.reason
        );
    }

    #[test]
    fn quotes_are_stripped_once_and_only_when_they_match() {
        assert_eq!(unquoted("'0'"), "0");
        assert_eq!(unquoted("\"a\""), "a");
        assert_eq!(unquoted("`x`"), "x");
        assert_eq!(unquoted("'a\""), "'a\"");
        assert_eq!(unquoted("false"), "false");
        assert_eq!(unquoted("'"), "'");
    }
}
