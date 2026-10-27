//! Credential redaction for retrieved source.
//!
//! Retrievers report literal arguments (`const_args`) and source text
//! (snippets, enclosing bodies, callers), so a database or crypto
//! construction carries its DSN or password as written. A scan's outputs are
//! uploaded: the `--out` document, the packet index, a submission. The
//! credential VALUE is never needed to judge a site, but its SHAPE is (a
//! literal password is a finding; a DSN still names its scheme and host). So
//! the value is replaced by [`MARKER`] and everything around it is kept:
//! `postgres://u:<redacted>@host`, `password='<redacted>'`,
//! `Server=h;Password=<redacted>;`.
//!
//! [`crate::Site`] calls this when it is deserialized, which is how every site
//! reaches `rvl` (a helper stream, a `--retrieved` file, the packet index), so
//! no consumer downstream ever holds the value.

use regex::{Captures, Regex};
use std::borrow::Cow;
use std::sync::OnceLock;

/// What a credential value is replaced by.
pub const MARKER: &str = "<redacted>";

/// A name that holds a credential: `password`, `db_password`,
/// `client_secret`, `access_token`, `secretKey`. Not `tokenizer`.
const NAME: &str = r"[A-Za-z0-9_.\-]*?(?:password|passwd|pwd|secret|token)(?:[_\-]?key)?";

struct Rules {
    /// `scheme://user:password@`
    dsn: Regex,
    /// A string literal, inside which `name=value` is data.
    literal: Regex,
    /// `name=value` inside a literal: a connection string or URL query.
    inline: Regex,
    /// `name = 'value'`, `name: "value"`, `"name": "value"` in code.
    quoted: Regex,
    name: Regex,
}

fn rules() -> &'static Rules {
    static R: OnceLock<Rules> = OnceLock::new();
    R.get_or_init(|| Rules {
        dsn: Regex::new(r#"([A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@'"`]*):([^\s@/'"`]+)@"#).unwrap(),
        literal: Regex::new(r#""(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`[^`]*`"#).unwrap(),
        inline: Regex::new(&format!(r#"(?i)\b({NAME})(\s*=\s*)([^\s;&'"`,)\]}}]+)"#)).unwrap(),
        quoted: Regex::new(&format!(
            r#"(?i)\b({NAME})(["']?\s*(?:=>|:=|=|:)\s*)(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)"#
        ))
        .unwrap(),
        name: Regex::new(&format!(r"(?i)^{NAME}$")).unwrap(),
    })
}

/// Whether `name` (an argument, field or config key) holds a credential.
/// A dotted or pathed key is judged by its last segment.
pub fn is_credential_name(name: &str) -> bool {
    let last = name.rsplit(['.', '/']).next().unwrap_or(name);
    rules().name.is_match(last)
}

/// `text` with every credential value it carries replaced by [`MARKER`].
pub fn redact(text: &str) -> Cow<'_, str> {
    let r = rules();
    let mut out = Cow::Borrowed(text);
    if let Cow::Owned(s) = r
        .dsn
        .replace_all(&out, |c: &Captures| format!("{}:{MARKER}@", &c[1]))
    {
        out = Cow::Owned(s);
    }
    if let Cow::Owned(s) = r.literal.replace_all(&out, |c: &Captures| inline(&c[0])) {
        out = Cow::Owned(s);
    }
    if let Cow::Owned(s) = r.quoted.replace_all(&out, |c: &Captures| {
        let q = &c[0][c[0].len() - 1..];
        format!("{}{}{q}{MARKER}{q}", &c[1], &c[2])
    }) {
        out = Cow::Owned(s);
    }
    if out == text {
        return Cow::Borrowed(text);
    }
    out
}

/// `name=value` pairs in `data` (a connection string, a URL query) with
/// their credential values redacted.
fn inline(data: &str) -> String {
    let r = rules();
    r.inline
        .replace_all(data, |k: &Captures| format!("{}{}{MARKER}", &k[1], &k[2]))
        .into_owned()
}

/// A configuration setting's value, which is data rather than source: the
/// whole value when the key names a credential, else the credentials in it.
pub fn redact_setting(key: &str, value: &str) -> String {
    if is_credential_name(key) && !value.is_empty() {
        return MARKER.to_string();
    }
    redact(&inline(value)).into_owned()
}

/// A constant argument's value: the whole value when the argument is named
/// as a credential, else what [`redact`] finds in it. A string keeps its
/// quotes, so the judge still sees a literal.
pub fn redact_value(name: &str, value: &str) -> String {
    if !is_credential_name(name) || value.is_empty() {
        return redact(value).into_owned();
    }
    match value.chars().next() {
        Some(q @ ('"' | '\'' | '`')) if value.len() > 1 && value.ends_with(q) => {
            format!("{q}{MARKER}{q}")
        }
        _ => MARKER.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dsn_keeps_its_scheme_user_and_host() {
        assert_eq!(
            redact(r#"sql.Open("postgres", "postgres://u:pw@db:5432/app")"#),
            r#"sql.Open("postgres", "postgres://u:<redacted>@db:5432/app")"#
        );
        assert_eq!(redact("redis://:s3cr3t@cache"), "redis://:<redacted>@cache");
    }

    #[test]
    fn a_keyword_keeps_its_name_and_quotes() {
        assert_eq!(
            redact("psycopg2.connect(host='h', password='hunter2')"),
            "psycopg2.connect(host='h', password='<redacted>')"
        );
        assert_eq!(
            redact(r#"new Pool({ user: "u", password: "hunter2" })"#),
            r#"new Pool({ user: "u", password: "<redacted>" })"#
        );
        assert_eq!(
            redact(r#"{"client_secret": "abc"}"#),
            r#"{"client_secret": "<redacted>"}"#
        );
        assert_eq!(
            redact(r#"cfg := Config{APIToken: `t0k`}"#),
            r#"cfg := Config{APIToken: `<redacted>`}"#
        );
    }

    #[test]
    fn a_connection_string_keeps_its_other_parts() {
        assert_eq!(
            redact(r#"new SqlConnection("Server=h;User Id=u;Password=p4ss;")"#),
            r#"new SqlConnection("Server=h;User Id=u;Password=<redacted>;")"#
        );
        assert_eq!(
            redact(r#"pgx.Connect(ctx, "host=h user=u password=p4ss dbname=d")"#),
            r#"pgx.Connect(ctx, "host=h user=u password=<redacted> dbname=d")"#
        );
        assert_eq!(
            redact(r#""https://h/cb?token=abc&x=1""#),
            r#""https://h/cb?token=<redacted>&x=1""#
        );
    }

    #[test]
    fn code_that_is_not_a_literal_credential_is_kept() {
        for s in [
            "psycopg2.connect(password=os.environ['PW'])",
            "db.Connect(cfg.Password)",
            r#"tokenizer = "bert""#,
            "http://host:8080/path@x",
            "git@github.com:org/repo",
            "hashlib.md5(data)",
        ] {
            assert!(
                matches!(redact(s), Cow::Borrowed(_)),
                "{s} changed to {}",
                redact(s)
            );
        }
    }

    #[test]
    fn redaction_is_idempotent() {
        let once =
            redact(r#"connect("mysql://u:pw@h", password="x", dsn="Password=y;")"#).into_owned();
        assert_eq!(redact(&once), once);
    }

    #[test]
    fn a_credential_argument_is_redacted_whole() {
        assert_eq!(redact_value("password", "'hunter2'"), "'<redacted>'");
        assert_eq!(redact_value("db.password", "hunter2"), "<redacted>");
        assert_eq!(
            redact_value("", r#""postgres://u:pw@h""#),
            r#""postgres://u:<redacted>@h""#
        );
        assert_eq!(redact_value("timeout", "5"), "5");
    }

    #[test]
    fn a_setting_value_is_data() {
        assert_eq!(redact_setting("spec.env.DB_PASSWORD", "hunter2"), MARKER);
        assert_eq!(
            redact_setting("env.DSN", "Server=h;Password=hunter2;"),
            "Server=h;Password=<redacted>;"
        );
        assert_eq!(
            redact_setting("env.DATABASE_URL", "mysql://u:pw@h/d"),
            "mysql://u:<redacted>@h/d"
        );
        assert_eq!(redact_setting("timeoutSeconds", "30"), "30");
    }
}
