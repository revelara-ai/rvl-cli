//! Deploy jobs with no check after the deploy (RC-058, integration and smoke
//! tests), shared by the GitHub Actions and GitLab CI retrievers.
//!
//! The unit is a deploy site: a CI job one of whose steps deploys a service
//! or applies infrastructure. Each one gets the fact `job.post-deploy-check`:
//!
//!   * `none` — nothing after the deploy looks like a check: no later step
//!     or downstream job, nothing in the deploy step itself, and no
//!     follow-up workflow. The expectation `not_equals: none` flags it.
//!   * `undecided:` and why — something may check the deploy, or the job
//!     reaches no production environment. Anything that resembles a check
//!     abstains: whether it gates the deploy is not read here.
//!
//! and the guard predicate `job.deploy-class`: `terraform` for an
//! infrastructure apply (Terraform, OpenTofu, Terragrunt, Pulumi,
//! CloudFormation, CDK), else `deploy`.
//!
//! A step deploys when its action is a deploy action ([`DEPLOY_USES`]) or
//! its shell runs a deploy command ([`DEPLOY_COMMANDS`]) as the command
//! word, outside a printed message. GitHub Pages, static site uploads,
//! deploy scripts and Makefile targets are no deploy site here.

use serde_yaml::{Mapping, Value};

/// The packet key a spec judges.
pub(crate) const KEY: &str = "job.post-deploy-check";
/// The guard predicate key.
pub(crate) const CLASS_KEY: &str = "job.deploy-class";
/// The value of a deploy site with nothing after it that checks it.
pub(crate) const NONE: &str = "none";

/// Deploy actions, by `owner/repo[/path]` (a longer path of the same action
/// matches too), with the word its `args` input must hold, if any, and
/// whether it applies infrastructure: ECS, Cloud Run, App Engine, Cloud
/// Functions, Azure Web Apps, Functions, Container Apps and AKS,
/// CloudFormation, deploys over SSH, Heroku, DigitalOcean App Platform,
/// Serverless, Dokku, CapRover, Railway, Render, Koyeb and Fly.
const DEPLOY_USES: &[(&str, Option<&str>, bool)] = &[
    ("aws-actions/amazon-ecs-deploy-task-definition", None, false),
    ("aws-actions/aws-cloudformation-github-deploy", None, true),
    ("google-github-actions/deploy-cloudrun", None, false),
    ("google-github-actions/deploy-appengine", None, false),
    ("google-github-actions/deploy-cloud-functions", None, false),
    ("azure/webapps-deploy", None, false),
    ("azure/functions-action", None, false),
    ("azure/container-apps-deploy-action", None, false),
    ("azure/k8s-deploy", None, false),
    ("appleboy/ssh-action", None, false),
    ("easingthemes/ssh-deploy", None, false),
    ("akhileshns/heroku-deploy", None, false),
    ("digitalocean/app_action", None, false),
    ("serverless/github-action", Some("deploy"), false),
    ("dokku/github-action", None, false),
    ("caprover/deploy-from-github", None, false),
    ("bervproject/railway-deploy", None, false),
    ("johnbeynon/render-deploy-action", None, false),
    ("koyeb/action-git-deploy", None, false),
    ("superfly/flyctl-actions", Some("deploy"), false),
];

/// Deploy commands: the tool as the command word, the words of its
/// subcommand in order right after it (flags and their values may sit
/// between them, so `helm --debug upgrade` reads and `install helm jq`
/// does not), and whether it applies infrastructure. `..` stands for any
/// words. `ansible-playbook` deploys whatever follows it.
const DEPLOY_COMMANDS: &[(&str, &[&str], bool)] = &[
    ("helm", &["upgrade"], false),
    ("helm", &["install"], false),
    ("kubectl", &["apply"], false),
    ("kubectl", &["set", "image"], false),
    ("kubectl", &["rollout", "restart"], false),
    ("kubectl", &["replace"], false),
    ("argocd", &["app", "sync"], false),
    ("terraform", &["apply"], true),
    ("tofu", &["apply"], true),
    ("terragrunt", &["apply"], true),
    ("terragrunt", &["run-all", "apply"], true),
    ("pulumi", &["up"], true),
    ("aws", &["ecs", "update-service"], false),
    ("aws", &["lambda", "update-function-code"], false),
    ("aws", &["cloudformation", "deploy"], true),
    ("sam", &["deploy"], false),
    ("cdk", &["deploy"], true),
    ("serverless", &["deploy"], false),
    ("sls", &["deploy"], false),
    ("gcloud", &["run", "deploy"], false),
    ("gcloud", &["app", "deploy"], false),
    ("gcloud", &["functions", "deploy"], false),
    ("az", &["webapp", "..", "deploy"], false),
    ("az", &["webapp", "..", "deployment"], false),
    ("az", &["functionapp", "..", "deploy"], false),
    ("az", &["functionapp", "..", "deployment"], false),
    ("az", &["containerapp", "..", "deploy"], false),
    ("fly", &["deploy"], false),
    ("flyctl", &["deploy"], false),
    ("kamal", &["deploy"], false),
    ("ansible-playbook", &[], false),
    ("docker", &["stack", "deploy"], false),
];

/// What an `ssh` command must run on the remote host to deploy there, as
/// whole words in order.
const SSH_REMOTE_DEPLOYS: &[&[&str]] = &[
    &["docker", "compose"],
    &["docker-compose"],
    &["docker", "pull"],
    &["docker", "run"],
    &["git", "pull"],
    &["systemctl", "restart"],
    &["pm2"],
];

/// Flags that take the next word as their value, so the value is skipped
/// with the flag on the way to a subcommand (`kubectl -n web apply`).
const VALUE_FLAGS: &[&str] = &[
    "-n",
    "--namespace",
    "--context",
    "--kube-context",
    "--kubeconfig",
    "--region",
    "--profile",
    "--project",
];

/// Words that run the next word as the command.
const WRAPPERS: &[&str] = &["sudo", "npx", "exec", "time", "command", "env"];

/// Command words that print a message: a deploy command inside one is
/// instructions, not a deploy.
const MESSAGE_COMMANDS: &[&str] = &["echo", "printf", "write-host", "write-output"];

/// Word stems that make a step, a job or the deploy step's own text read as
/// a check of the deploy: smoke, end-to-end and integration tests, HTTP
/// probes, health and status checks, waits on a rollout, monitors. A token
/// of the text (split on every non-alphanumeric character, lower-cased)
/// that starts with one counts, unless it is listed in [`NOT_CHECKS`].
const CHECK_STEMS: &[&str] = &[
    "smoke",
    "e2e",
    "integration",
    "playwright",
    "cypress",
    "k6",
    "newman",
    "hurl",
    "curl",
    "wget",
    "health",
    "verif",
    "validat",
    "check",
    "test",
    "lighthouse",
    "probe",
    "ping",
    "status",
    "sanity",
    "synthetic",
    "monitor",
];

/// Phrases that read as a check, matched in the lower-cased text, for the
/// checks whose name is not one word.
const CHECK_PHRASES: &[&str] = &["invoke-webrequest", "wait-on", "argocd app wait"];

/// Tokens a [`CHECK_STEMS`] stem starts that are no check: the checkout of
/// the repository.
const NOT_CHECKS: &[&str] = &["checkout"];

/// Tokens of a job id, job name, environment name or workflow file stem
/// that mark the job as reaching no production environment: previews and
/// per-developer environments, tests and demos, scheduled and canary runs,
/// and the jobs around a deploy that plan, check, version, bootstrap or tear
/// down rather than deploy. `staging` is not listed: a named environment
/// that is not a developer's is still owed a check after each deploy.
const NON_PRODUCTION_JOB_TOKENS: &[&str] = &[
    "preview",
    "previews",
    "pr",
    "prs",
    "dev",
    "develop",
    "developer",
    "developers",
    "development",
    "test",
    "tests",
    "testing",
    "e2e",
    "ephemeral",
    "review",
    "sandbox",
    "demo",
    "demos",
    "example",
    "examples",
    "local",
    "ci",
    "canary",
    "nightly",
    "plan",
    "check",
    "checks",
    "validate",
    "validation",
    "version",
    "drift",
    "destroy",
    "cleanup",
    "teardown",
    "bootstrap",
    "state",
    "backend",
    "init",
    "setup",
];

/// Text anywhere in a workflow that shows a test cluster or a rehearsal: a
/// kind, k3d or k3s cluster, an emulator, chart testing, a
/// controller test environment, a virtual cluster, test containers, a dry
/// run, or a Kubernetes test runner. Matched in the lower-cased text.
const TEST_CLUSTER_MARKERS: &[&str] = &[
    "kind create cluster",
    "kind load",
    "kind-action",
    "setup-kind",
    "kindest/",
    "k3d",
    "k3s",
    "localstack",
    "chart-testing",
    "envtest",
    "kwok",
    "vcluster",
    "testcontainers",
    "--dry-run",
    "chainsaw",
    "kuttl",
];

/// Text of a job's condition or deploy step that deploys a pull request or
/// a preview rather than production. Matched in the lower-cased text.
const PREVIEW_MARKERS: &[&str] = &["pull_request", "preview", "--alias"];

/// What one step deploys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Deploy {
    /// The action or command, e.g. `helm upgrade`.
    pub kind: String,
    /// It applies infrastructure rather than a service.
    pub infrastructure: bool,
}

impl Deploy {
    /// The [`CLASS_KEY`] value.
    pub(crate) fn class(&self) -> &'static str {
        if self.infrastructure {
            "terraform"
        } else {
            "deploy"
        }
    }
}

/// What a step's `uses:` deploys, if it is a deploy action. `with` is the
/// step's inputs.
pub(crate) fn in_uses(uses: &str, with: Option<&Mapping>) -> Option<Deploy> {
    let action = uses.split('@').next().unwrap_or(uses).to_lowercase();
    DEPLOY_USES.iter().find_map(|(name, arg, infra)| {
        let ours = action == *name || action.starts_with(&format!("{name}/"));
        let args = with
            .and_then(|w| w.get(Value::String("args".into())))
            .and_then(Value::as_str)
            .unwrap_or("");
        let wanted = arg.is_none_or(|a| args.split_whitespace().any(|w| w == a));
        (ours && wanted).then(|| Deploy {
            kind: name.to_string(),
            infrastructure: *infra,
        })
    })
}

/// The last deploy command a shell script runs, if any.
pub(crate) fn in_run(script: &str) -> Option<Deploy> {
    commands(script).iter().rev().find_map(|c| command(c))
}

/// The deploy one shell command runs, if any.
fn command(text: &str) -> Option<Deploy> {
    if text.contains("--dry-run") {
        return None;
    }
    let words: Vec<String> = text
        .split_whitespace()
        .map(|w| w.trim_matches(['"', '\'']).to_string())
        .filter(|w| !w.is_empty())
        .collect();
    let start = words
        .iter()
        .position(|w| !w.contains('=') && !WRAPPERS.contains(&w.as_str()))?;
    let tool = words[start].rsplit('/').next()?.to_lowercase();
    if MESSAGE_COMMANDS.contains(&tool.as_str()) {
        return None;
    }
    let rest = &words[start + 1..];
    if tool == "ssh" {
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        return SSH_REMOTE_DEPLOYS
            .iter()
            .any(|p| rest.windows(p.len()).any(|w| w == *p))
            .then(|| Deploy {
                kind: "ssh".into(),
                infrastructure: false,
            });
    }
    DEPLOY_COMMANDS
        .iter()
        .find(|(t, sub, _)| *t == tool && subcommand(rest, sub))
        .map(|(t, sub, infra)| Deploy {
            kind: std::iter::once(*t)
                .chain(sub.iter().copied().filter(|w| *w != ".."))
                .collect::<Vec<_>>()
                .join(" "),
            infrastructure: *infra,
        })
}

/// Whether `words` begin with the subcommand `sub`, flags and their values
/// skipped, `..` matching any run of words.
fn subcommand(words: &[String], sub: &[&str]) -> bool {
    let mut i = 0;
    let mut any = false;
    for want in sub {
        if *want == ".." {
            any = true;
            continue;
        }
        loop {
            let Some(w) = words.get(i) else {
                return false;
            };
            i += 1;
            if w.starts_with('-') {
                if VALUE_FLAGS.contains(&w.as_str()) {
                    i += 1;
                }
                continue;
            }
            if w == want {
                break;
            }
            if !any {
                return false;
            }
        }
        any = false;
    }
    true
}

/// A shell script split into its commands: at newlines, `;`, `&`, `|`
/// outside quotes, with continued lines joined, comments dropped, and a
/// here-document's body kept inside the command that reads it (so `ssh host
/// <<EOF` holds what runs remotely, and a quoted message is one command).
pub(crate) fn commands(script: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    // Here-documents opened on the current line: (command index, delimiter).
    let mut pending: Vec<(usize, String)> = Vec::new();
    let (mut single, mut double) = (false, false);
    let mut chars = script.chars().peekable();
    let end = |cur: &mut String, out: &mut Vec<String>, pending: &mut Vec<(usize, String)>| {
        let text = cur.trim().to_string();
        cur.clear();
        if text.is_empty() {
            return;
        }
        if let Some(delim) = heredoc_delimiter(&text) {
            pending.push((out.len(), delim));
        }
        out.push(text);
    };
    while let Some(c) = chars.next() {
        match c {
            '\\' if !single => match chars.next() {
                Some('\n') => cur.push(' '),
                Some(n) => {
                    cur.push(c);
                    cur.push(n);
                }
                None => cur.push(c),
            },
            '\'' if !double => {
                single = !single;
                cur.push(c);
            }
            '"' if !single => {
                double = !double;
                cur.push(c);
            }
            _ if single || double => cur.push(c),
            '#' if cur.is_empty() || cur.ends_with(char::is_whitespace) => {
                while chars.peek().is_some_and(|n| *n != '\n') {
                    chars.next();
                }
            }
            ';' | '&' | '|' => end(&mut cur, &mut out, &mut pending),
            '\n' => {
                end(&mut cur, &mut out, &mut pending);
                for (idx, delim) in pending.drain(..) {
                    let mut body = String::new();
                    while chars.peek().is_some() {
                        let line: String = chars.by_ref().take_while(|n| *n != '\n').collect();
                        if line.trim() == delim {
                            break;
                        }
                        body.push('\n');
                        body.push_str(&line);
                    }
                    out[idx].push_str(&body);
                }
            }
            _ => cur.push(c),
        }
    }
    end(&mut cur, &mut out, &mut pending);
    out
}

/// The delimiter of a here-document a command opens (`<<EOF`, `<<-'EOF'`),
/// if any. A here-string (`<<<`) is none.
fn heredoc_delimiter(text: &str) -> Option<String> {
    let at = text.find("<<")?;
    let rest = &text[at + 2..];
    if rest.starts_with('<') {
        return None;
    }
    let rest = rest.trim_start_matches('-').trim_start();
    let delim: String = rest
        .trim_start_matches(['\'', '"'])
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!delim.is_empty()).then_some(delim)
}

/// The lower-cased tokens of `text`: split on every non-alphanumeric
/// character and at a lower-to-upper case change (`deployDev`).
fn tokens(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for c in text.chars() {
        if (!c.is_alphanumeric() || (prev_lower && c.is_uppercase())) && !cur.is_empty() {
            out.push(std::mem::take(&mut cur));
        }
        if c.is_alphanumeric() {
            cur.extend(c.to_lowercase());
        }
        prev_lower = c.is_lowercase() || c.is_ascii_digit();
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// The word in `text` that reads as a check of the deploy, if any.
pub(crate) fn check_word(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    if let Some(p) = CHECK_PHRASES.iter().find(|p| lower.contains(*p)) {
        return Some(p.to_string());
    }
    tokens(text)
        .into_iter()
        .find(|t| !NOT_CHECKS.contains(&t.as_str()) && CHECK_STEMS.iter().any(|s| t.starts_with(s)))
}

/// The [`NON_PRODUCTION_JOB_TOKENS`] token of `name`, if any.
pub(crate) fn non_production_token(name: &str) -> Option<&'static str> {
    tokens(name).iter().find_map(|t| {
        NON_PRODUCTION_JOB_TOKENS
            .iter()
            .copied()
            .find(|w| *w == t.as_str())
    })
}

/// The [`TEST_CLUSTER_MARKERS`] entry a CI file holds, if any.
pub(crate) fn test_cluster(contents: &str) -> Option<&'static str> {
    let lower = contents.to_lowercase();
    TEST_CLUSTER_MARKERS
        .iter()
        .copied()
        .find(|m| lower.contains(m))
}

/// The [`PREVIEW_MARKERS`] entry `text` holds, if any.
pub(crate) fn preview(text: &str) -> Option<&'static str> {
    let lower = text.to_lowercase();
    PREVIEW_MARKERS.iter().copied().find(|m| lower.contains(m))
}

/// Every scalar of a YAML value, mapping keys included, joined by spaces.
pub(crate) fn text_of(v: &Value) -> String {
    let mut out = String::new();
    collect(v, &mut out);
    out
}

fn collect(v: &Value, out: &mut String) {
    let mut push = |s: &str| {
        out.push(' ');
        out.push_str(s);
    };
    match v {
        Value::String(s) => push(s),
        Value::Bool(b) => push(&b.to_string()),
        Value::Number(n) => push(&n.to_string()),
        Value::Sequence(seq) => seq.iter().for_each(|v| collect(v, out)),
        Value::Mapping(m) => m.iter().for_each(|(k, v)| {
            collect(k, out);
            collect(v, out);
        }),
        Value::Tagged(t) => collect(&t.value, out),
        Value::Null => {}
    }
}

/// The name of an `environment:` (a name, or a mapping with a `name`).
pub(crate) fn environment_name(env: &Value) -> Option<&str> {
    match env {
        Value::String(s) => Some(s),
        Value::Mapping(m) => m.get(Value::String("name".into()))?.as_str(),
        _ => None,
    }
}

/// The fact's value: [`NONE`], or `undecided:` and why.
pub(crate) fn value(why: Option<String>) -> String {
    match why {
        Some(why) => format!("{}{why}", crate::UNDECIDED_PREFIX),
        None => NONE.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(script: &str) -> Option<String> {
        in_run(script).map(|d| d.kind)
    }

    #[test]
    fn deploy_commands_are_read_as_the_command_word() {
        for (script, want) in [
            ("kubectl -n web apply -f k8s/", Some("kubectl apply")),
            (
                "helm --debug upgrade --install api ./chart",
                Some("helm upgrade"),
            ),
            (
                "cd infra && terraform apply -auto-approve",
                Some("terraform apply"),
            ),
            (
                "sudo kubectl rollout restart deploy/api",
                Some("kubectl rollout restart"),
            ),
            (
                "az webapp deployment source config-zip -n a",
                Some("az webapp deployment"),
            ),
            (
                "ansible-playbook -i hosts site.yml",
                Some("ansible-playbook"),
            ),
            (
                "ssh deploy@host 'cd app && docker compose up -d'",
                Some("ssh"),
            ),
            (
                "ssh host <<EOF\n  git pull\n  pm2 reload all\nEOF\n",
                Some("ssh"),
            ),
            // A tool install names the tools, not a subcommand of them.
            ("brew install helm jq oras", None),
            ("helm plugin install https://example.com/x", None),
            (
                "helm repo add x https://example.com && helm dependency build",
                None,
            ),
            ("ssh host uptime", None),
            ("terraform plan", None),
            ("kubectl apply --dry-run=client -f k8s/", None),
        ] {
            assert_eq!(kind(script).as_deref(), want, "{script}");
        }
    }

    #[test]
    fn a_deploy_command_inside_a_printed_message_is_not_a_deploy() {
        for script in [
            "echo 'run kubectl apply -f k8s/ to deploy'",
            "echo \"Deploy with: \\\n  kubectl apply -f k8s/\"",
            "echo \"To deploy:\n  helm upgrade api ./chart\"\n",
            "# kubectl apply -f k8s/",
            "Write-Host 'helm upgrade api ./chart'",
            "cat <<EOF\nkubectl apply -f k8s/\nEOF\n",
        ] {
            assert_eq!(kind(script), None, "{script}");
        }
        assert_eq!(
            kind("echo deploying\nkubectl apply -f k8s/").as_deref(),
            Some("kubectl apply")
        );
    }

    #[test]
    fn infrastructure_applies_are_their_own_class() {
        assert_eq!(in_run("pulumi up --yes").unwrap().class(), "terraform");
        assert_eq!(in_run("npx cdk deploy --all").unwrap().class(), "terraform");
        assert_eq!(in_run("fly deploy").unwrap().class(), "deploy");
        let with: Mapping = serde_yaml::from_str("args: deploy --remote-only").unwrap();
        assert_eq!(
            in_uses("superfly/flyctl-actions@1.5", Some(&with)).map(|d| d.kind),
            Some("superfly/flyctl-actions".into())
        );
        assert_eq!(
            in_uses("superfly/flyctl-actions/setup-flyctl@v1", None),
            None
        );
        assert_eq!(in_uses("actions/deploy-pages@v4", None), None);
        assert!(
            in_uses("aws-actions/aws-cloudformation-github-deploy@v1", None)
                .unwrap()
                .infrastructure
        );
    }

    #[test]
    fn check_words_and_tokens() {
        assert_eq!(check_word("Smoke test").as_deref(), Some("smoke"));
        assert_eq!(
            check_word("curl -f https://example.com/healthz").as_deref(),
            Some("curl")
        );
        assert_eq!(
            check_word("npx wait-on https://example.com").as_deref(),
            Some("wait-on")
        );
        assert_eq!(check_word("uses: actions/checkout@v4"), None);
        assert_eq!(check_word("Notify chat"), None);
        assert_eq!(non_production_token("deployDev"), Some("dev"));
        assert_eq!(
            non_production_token("api-deploy-developer"),
            Some("developer")
        );
        assert_eq!(non_production_token("deploy-staging"), None);
        assert_eq!(non_production_token("production"), None);
    }
}
