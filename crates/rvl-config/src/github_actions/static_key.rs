//! Static cloud keys in a workflow (RC-072, access lifecycle and credential
//! hygiene): does a step, job or workflow hand a long-lived cloud key from
//! `secrets` to its tools, where a federated, short-lived identity would do?
//!
//! The fact `credential.static-cloud-key` is emitted only on a unit that
//! holds one. A mapping holds one when a key matches a provider's key name
//! (case-insensitive, the whole key) and its value reads
//! `${{ secrets.<NAME> }}`. The mappings read, each its own unit: a step's
//! `with`, else the step's `env` (`step:<job id>/<index>`); a job's `env`
//! (`job:<job id>`); the workflow's `env` (`workflow`). The value is the
//! provider, `aws` | `gcp` | `azure`, or `undecided:` and why:
//!
//!   * the same mapping holds a federation or session input, so the key may
//!     be one half of a short-lived identity;
//!   * an AWS-shaped key is for an S3-compatible third party (its secret's
//!     name, or an endpoint in the file, says so), which no cloud
//!     federation replaces;
//!   * the workflow file stem or the job id names a non-production
//!     environment, or the repository is sample material
//!     ([`crate::non_production`]).
//!
//! The value never holds a credential: only the secret's name is read.

use super::get;
use crate::non_production;
use serde_yaml::{Mapping, Value};

/// AWS key names, as words an optional `-` or `_` may join.
const AWS_KEYS: &[&[&str]] = &[
    &["aws", "access", "key"],
    &["aws", "access", "key", "id"],
    &["aws", "secret", "access", "key"],
    &["aws", "secret", "key"],
];

/// GCP key names, whole.
const GCP_KEYS: &[&str] = &[
    "credentials_json",
    "service_account_key",
    "google_credentials",
    "google_application_credentials",
    "google_application_credentials_json",
    "gcp_sa_key",
    "gcloud_service_key",
    "gcp_credentials",
    "gcp_service_account_key",
];

/// Azure key names, whole. `creds` counts only as an input of `azure/login`:
/// another action's `creds` is its own credential (a GitHub App's).
const AZURE_KEYS: &[&str] = &[
    "arm_client_secret",
    "azure_client_secret",
    "azure_credentials",
];
const AZURE_LOGIN_CREDS: &str = "creds";

/// Inputs that make the mapping's key one half of a federated or session
/// identity, whole and case-insensitive.
const FEDERATION_KEYS: &[&str] = &[
    "aws-session-token",
    "aws_session_token",
    "workload_identity_provider",
    "client-id",
    "arm_use_oidc",
    "azure_federated_token_file",
];

/// One mapping's static cloud key.
pub(super) struct StaticKey {
    pub provider: &'static str,
    /// The mapping's key that holds it.
    pub key: String,
    /// The secret it reads.
    pub secret: String,
    /// The same mapping holds a federation or session input.
    pub federated: bool,
}

/// Whether `key` is `words` joined by at most one `-` or `_` between each.
fn joined(key: &str, words: &[&str]) -> bool {
    let mut rest = key;
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            rest = rest.strip_prefix(['-', '_']).unwrap_or(rest);
        }
        let Some(r) = rest.strip_prefix(w) else {
            return false;
        };
        rest = r;
    }
    rest.is_empty()
}

/// The provider whose static key `key` names, if any.
fn provider(key: &str, azure_login: bool) -> Option<&'static str> {
    let key = key.to_lowercase();
    if AWS_KEYS.iter().any(|words| joined(&key, words)) {
        Some("aws")
    } else if GCP_KEYS.contains(&key.as_str()) {
        Some("gcp")
    } else if AZURE_KEYS.contains(&key.as_str()) || (azure_login && key == AZURE_LOGIN_CREDS) {
        Some("azure")
    } else {
        None
    }
}

/// The name of the first secret a `${{ ... }}` expression in `value` reads.
fn secret_name(value: &str) -> Option<String> {
    let mut rest = value;
    while let Some(start) = rest.find("${{") {
        let expr = &rest[start + 3..];
        let end = expr.find("}}").unwrap_or(expr.len());
        if let Some(name) = expr[..end].trim_start().strip_prefix("secrets.") {
            let name: String = name
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
        rest = &expr[end..];
    }
    None
}

/// The static cloud key `m` holds, if any. `azure_login` says the mapping
/// is the inputs of an `azure/login` step.
fn in_mapping(m: &Mapping, azure_login: bool) -> Option<StaticKey> {
    let (key, provider, secret) = m.iter().find_map(|(k, v)| {
        let k = k.as_str()?;
        let provider = provider(k, azure_login)?;
        let secret = secret_name(v.as_str()?)?;
        Some((k.to_string(), provider, secret))
    })?;
    let federated = m
        .keys()
        .filter_map(Value::as_str)
        .any(|k| FEDERATION_KEYS.iter().any(|f| f.eq_ignore_ascii_case(k)));
    Some(StaticKey {
        provider,
        key,
        secret,
        federated,
    })
}

/// A step's static cloud key: its `with`, else its `env`. Returns the key
/// and the mapping it was found in (`with` or `env`).
pub(super) fn in_step(step: &Mapping) -> Option<(StaticKey, &'static str)> {
    let azure_login = get(step, "uses")
        .and_then(Value::as_str)
        .is_some_and(|u| u.to_lowercase().starts_with("azure/login"));
    ["with", "env"].into_iter().find_map(|field| {
        let m = get(step, field).and_then(Value::as_mapping)?;
        in_mapping(m, azure_login && field == "with").map(|k| (k, field))
    })
}

/// The `env` mapping's static cloud key of a job or a workflow.
pub(super) fn in_env(unit: &Mapping) -> Option<StaticKey> {
    in_mapping(get(unit, "env").and_then(Value::as_mapping)?, false)
}

/// Where a unit's static key is read from, for the abstentions.
pub(super) struct Context<'a> {
    /// The scanned repository's sample token ([`non_production::root_token`]).
    pub repo: Option<&'static str>,
    /// The workflow file's stem.
    pub stem: &'a str,
    /// The job id; `None` for the workflow's own `env`.
    pub job_id: Option<&'a str>,
    /// The whole workflow file.
    pub contents: &'a str,
}

/// The fact's value: the provider, or `undecided:` and why.
pub(super) fn value(k: &StaticKey, cx: &Context) -> String {
    let why = if k.federated {
        Some("a federation or session input is beside the key".to_string())
    } else if let Some(t) = (k.provider == "aws")
        .then(|| {
            non_production::s3_compatible_secret(&k.secret)
                .or_else(|| non_production::s3_compatible_file(cx.contents))
        })
        .flatten()
    {
        Some(format!("S3-compatible third party: {t}"))
    } else if let Some(t) = non_production::workflow_token(cx.stem) {
        Some(format!("non-production workflow: {t}"))
    } else if let Some(t) = cx.job_id.and_then(non_production::workflow_token) {
        Some(format!("non-production job: {t}"))
    } else {
        cx.repo.map(|t| format!("non-production repository: {t}"))
    };
    match why {
        Some(why) => format!("{}{why}", crate::UNDECIDED_PREFIX),
        None => k.provider.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_names_match_whole_with_optional_separators() {
        for (key, want) in [
            ("aws-access-key-id", Some("aws")),
            ("AWS_ACCESS_KEY_ID", Some("aws")),
            ("awsAccessKey", Some("aws")),
            ("aws_secret_access_key", Some("aws")),
            ("AWS_SECRET_KEY", Some("aws")),
            ("aws--access-key", None),
            ("my_aws_access_key", None),
            ("credentials_json", Some("gcp")),
            ("GOOGLE_APPLICATION_CREDENTIALS_JSON", Some("gcp")),
            ("credentials-json", None),
            ("ARM_CLIENT_SECRET", Some("azure")),
            ("creds", None),
        ] {
            assert_eq!(provider(key, false), want, "{key}");
        }
        assert_eq!(provider("creds", true), Some("azure"));
    }

    #[test]
    fn the_secret_name_is_read_from_the_expression() {
        assert_eq!(
            secret_name("${{ secrets.AWS_KEY }}").as_deref(),
            Some("AWS_KEY")
        );
        assert_eq!(
            secret_name("${{ env.X }}-${{secrets.KEY_2}}").as_deref(),
            Some("KEY_2")
        );
        assert_eq!(secret_name("${{ vars.KEY }}"), None);
        assert_eq!(secret_name("example"), None);
    }
}
