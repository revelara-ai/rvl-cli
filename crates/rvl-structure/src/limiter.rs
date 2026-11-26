//! RC-069 ingress rate limiting and load shedding: whether a deployed
//! service limits or sheds what its clients send, anywhere in its code or
//! config.
//!
//! RETRIEVAL ([`observe`]) counts the code and config files that hold
//! rate-limit or load-shedding vocabulary ([`LIMITER_VOCABULARY`]), and
//! records the service's own server entry points and deployment manifests.
//! JUDGEMENT ([`evaluate`]) violates only in a repository read as a service
//! ([`crate::repo_kind`]) whose own server and deployment survive the
//! exclusions below, in a completely walked tree with no file of that
//! vocabulary. A violation claims an absence, so the vocabulary is wide on
//! purpose: a hand-written limiter must still name what it does.
//!
//! The server entry points are narrower than [`crate::repo_kind`]'s: the
//! generic calls a client or a tool makes as well (`net.Listen(`,
//! `.listen(`, `app.run(`, `serve_forever(`, `TcpListener::bind`) do not
//! count, and the constructors of common web frameworks do. An entry point
//! does not count under a teaching directory (`chapter3/`, `lesson2/`, a
//! numbered directory), under a directory the scanner reads as
//! non-production, or on a path of a scrape-only server (`metrics`,
//! `health`, `pprof`). A deployment manifest does not count under a
//! teaching or non-production directory.
//!
//! It abstains in a sample or teaching repository, an exporter, a CSI
//! driver (by the repository's own name or its owner's), and a service whose
//! every server entry point listens on a unix socket: none of them takes
//! client traffic from the network.
//!
//! Privacy: the facts are counts and repo-relative paths, never source text.

use crate::error_reporting::{not_ours, MAX_PATHS};
use crate::inventory::read_capped;
use crate::repo_kind::{self, in_service_code, is_source, is_test_source, NOT_THE_REPO};
use crate::{RepoStructure, StructureFinding};
use rvl_config::non_production;
use rvl_core::Verdict;
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use std::path::Path;

/// What a rate limiter, a request throttle, a concurrency cap or a load
/// shedder is called in code and config, lowercased. Covers the generic
/// names (`rate limit` in its spellings, `throttl`, `limiter`, a token or
/// leaky bucket, a semaphore, backpressure, load shedding, concurrency and
/// in-flight caps), the 429 answer (`TooManyRequests`, `status 429`), the
/// NGINX directives and ingress annotations (`limit_req`, `limit_conn`,
/// `limit-rps`, `limit-connections`, `limit-burst`), and the common limiter
/// libraries (`golang.org/x/time/rate`, `tollbooth`, `redis_rate`,
/// `slowapi`, `bucket4j`, `rack-attack`). A file holding any one counts.
pub const LIMITER_VOCABULARY: &[&str] = &[
    "ratelimit",
    "rate-limit",
    "rate_limit",
    "rate limit",
    "limit-rps",
    "limit_rps",
    "limit-rpm",
    "limit_rpm",
    "limit_req",
    "limit_conn",
    "limit-connections",
    "limit-burst",
    "throttl",
    "limiter",
    "slowapi",
    "golang.org/x/time/rate",
    "tollbooth",
    "redis_rate",
    "bucket4j",
    "rack-attack",
    "leaky bucket",
    "token bucket",
    "toomanyrequests",
    "too many requests",
    "status 429",
    "concurrency limit",
    "max concurren",
    "max in flight",
    "load shed",
    "backpressure",
    "semaphore",
    "限流",
];

/// Extensions of the code and config files the vocabulary is read from.
/// Prose (Markdown, text) and data (CSV, SQL) are not read.
const READ_EXTS: &[&str] = &[
    "go",
    "py",
    "js",
    "mjs",
    "cjs",
    "jsx",
    "ts",
    "tsx",
    "rs",
    "java",
    "kt",
    "kts",
    "scala",
    "groovy",
    "gradle",
    "cs",
    "rb",
    "php",
    "ex",
    "exs",
    "erl",
    "lua",
    "c",
    "cc",
    "cpp",
    "h",
    "hpp",
    "swift",
    "sh",
    "yaml",
    "yml",
    "toml",
    "json",
    "ini",
    "cfg",
    "conf",
    "properties",
    "tf",
    "hcl",
    "xml",
    "tpl",
];

/// Code and config files with no extension, or an extension of prose, read
/// by name.
const READ_NAMES: &[&str] = &[
    "Dockerfile",
    "Procfile",
    "Caddyfile",
    "Gemfile",
    "go.mod",
    "Makefile",
];

/// Lock files: what a manifest resolved to, not what the service does.
const LOCK_NAMES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "composer.lock",
];

/// Server entry-point markers of [`crate::repo_kind`] that a client, a test
/// helper or a tool calls as well: they do not make an entry point here.
const SHARED_WITH_CLIENTS: &[&str] = &[
    "net.Listen(",
    ".listen(",
    "app.run(",
    "serve_forever(",
    "TcpListener::bind",
];

/// Web framework constructors that make a server entry point here in
/// addition to [`crate::repo_kind`]'s markers, by source extension.
const FRAMEWORKS: &[(&[&str], &[&str])] = &[
    (&["go"], &["gin.New(", "chi.NewRouter("]),
    (&["py"], &["get_wsgi_application(", "get_asgi_application("]),
    (
        &["js", "mjs", "cjs", "ts"],
        &["NestFactory.create(", "new Hono("],
    ),
    (&["java", "kt"], &["@RestController"]),
];

/// Path fragments, lowercased, of a server that only answers a scraper or an
/// operator: metrics, health, profiling and debug endpoints.
const SCRAPE_ONLY: &[&str] = &[
    "metric",
    "health",
    "pprof",
    "probe",
    "exporter",
    "telemetry",
    "debug",
];

/// Directory prefixes that, followed by a number, mark a teaching step:
/// `chapter3/`, `ch03/`, `day1/`, `lesson-2/`, `module4/`.
const TEACHING_STEPS: &[&str] = &["chapter", "ch", "day", "lesson", "module"];

/// Tokens of the repository's name or owner that mark teaching material,
/// beside [`non_production::SAMPLE_REPOSITORY_TOKENS`].
const TEACHING_REPOSITORY_TOKENS: &[&str] = &[
    "edition",
    "book",
    "academy",
    "learn",
    "class",
    "codespaces",
    "exercises",
    "bootcamp",
];

/// Tokens of the repository's name or owner that mark a server with no
/// client traffic: a metrics exporter, and a CSI driver, which serves its
/// container orchestrator on a node-local socket.
const NO_CLIENT_TRAFFIC_TOKENS: &[&str] = &["exporter", "csi"];

/// What a source file names when it listens on a unix socket.
const UNIX_SOCKET: &[&str] = &[
    "\"unix\"",
    "'unix'",
    "unix://",
    "\"unix:",
    "'unix:",
    "AF_UNIX",
    "UnixListener",
    ".sock\"",
    ".sock'",
];

/// What a source file names when it listens on a TCP port.
const TCP_SOCKET: &[&str] = &[
    "\"tcp\"",
    "'tcp'",
    "\"tcp4\"",
    "\"tcp6\"",
    "ListenAndServe(",
    "ListenAndServeTLS(",
    "AF_INET",
    "0.0.0.0",
];

/// The RC-069 facts of a repository. A record without them was not read for
/// RC-069: it abstains.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LimiterFacts {
    /// Code and config files read for [`LIMITER_VOCABULARY`].
    #[serde(default)]
    pub files_read: u32,
    /// Those that hold any of it.
    #[serde(default)]
    pub vocabulary_files: u32,
    /// The first of them, sorted, at most [`MAX_PATHS`].
    #[serde(default)]
    pub vocabulary: Vec<String>,
    /// Server entry points that count here.
    #[serde(default)]
    pub servers: u32,
    /// Those that listen on a unix socket and on no TCP port.
    #[serde(default)]
    pub unix_servers: u32,
    /// The first of the entry points, sorted, at most [`MAX_PATHS`].
    #[serde(default)]
    pub server_paths: Vec<String>,
    /// Deployment manifests that count here, sorted, at most [`MAX_PATHS`].
    #[serde(default)]
    pub deployments: Vec<String>,
    /// The token of the repository's name or owner that marks it as sample
    /// or teaching material, an exporter or a CSI driver.
    #[serde(default)]
    pub repository_token: Option<String>,
}

/// The RC-069 facts, accumulated over the walk.
#[derive(Default)]
pub(crate) struct Acc {
    facts: LimiterFacts,
}

impl Acc {
    pub(crate) fn finish(mut self, root: &Path) -> LimiterFacts {
        let f = &mut self.facts;
        for list in [&mut f.vocabulary, &mut f.server_paths, &mut f.deployments] {
            list.sort();
            list.truncate(MAX_PATHS);
        }
        f.repository_token = repository_token(root);
        self.facts
    }
}

/// Keep `rp` in `list`, sorted, while it is among the first [`MAX_PATHS`].
fn keep(list: &mut Vec<String>, rp: &str) {
    list.push(rp.to_string());
    if list.len() > MAX_PATHS {
        list.sort();
        list.truncate(MAX_PATHS);
    }
}

/// Record what the file at repo-relative `rp` says for RC-069.
pub(crate) fn observe(path: &Path, rp: &str, name: &str, ext: &str, acc: &mut Acc) {
    let f = &mut acc.facts;
    let text = OnceCell::new();
    let text = || text.get_or_init(|| read_capped(path)).as_str();
    if reads_vocabulary(rp, name, ext) {
        f.files_read += 1;
        if holds_vocabulary(text()) {
            f.vocabulary_files += 1;
            keep(&mut f.vocabulary, rp);
        }
    }
    if !in_service_code(rp) || teaching_or_non_production(rp) {
        return;
    }
    if repo_kind::may_deploy(name, ext) {
        if f.deployments.len() < MAX_PATHS && repo_kind::deployment(path, name, ext).is_some() {
            keep(&mut f.deployments, rp);
        }
    } else if is_source(ext)
        && !is_test_source(name)
        && !scrape_only(rp)
        && entry_point(ext, text())
    {
        f.servers += 1;
        if unix_only(text()) {
            f.unix_servers += 1;
        }
        keep(&mut f.server_paths, rp);
    }
}

/// Whether the file at `rp` is code or config the vocabulary is read from:
/// not vendored or build output, not under a test, example, sample, demo,
/// docs, benchmark, fixture or mock directory, not a test file, not prose,
/// data or a lock file.
fn reads_vocabulary(rp: &str, name: &str, ext: &str) -> bool {
    let mut dirs: Vec<&str> = rp.split('/').collect();
    dirs.pop();
    if not_ours(rp)
        || dirs
            .iter()
            .any(|d| NOT_THE_REPO.contains(&d.to_ascii_lowercase().as_str()))
        || is_test_source(name)
        || name.ends_with("Test.java")
        || name.ends_with("Tests.java")
        || name.ends_with("_spec.rb")
        || name.ends_with(".lock")
        || LOCK_NAMES.contains(&name)
        || name == "go.sum"
    {
        return false;
    }
    READ_EXTS.contains(&ext)
        || READ_NAMES.contains(&name)
        || name.starts_with("Dockerfile.")
        || (name.starts_with("requirements") && ext == "txt")
}

/// Whether `text` holds any of [`LIMITER_VOCABULARY`], case-insensitive.
pub(crate) fn holds_vocabulary(text: &str) -> bool {
    let text = text.to_lowercase();
    LIMITER_VOCABULARY.iter().any(|w| text.contains(w))
}

/// A server entry point for RC-069 in a source file of extension `ext`.
fn entry_point(ext: &str, text: &str) -> bool {
    repo_kind::listener_markers(ext)
        .filter(|m| !SHARED_WITH_CLIENTS.contains(m))
        .chain(
            FRAMEWORKS
                .iter()
                .filter(|(exts, _)| exts.contains(&ext))
                .flat_map(|(_, markers)| markers.iter().copied()),
        )
        .any(|m| text.contains(m))
}

/// Whether a server's source names a unix socket and no TCP port.
fn unix_only(text: &str) -> bool {
    UNIX_SOCKET.iter().any(|m| text.contains(m)) && !TCP_SOCKET.iter().any(|m| text.contains(m))
}

/// Whether `rp` is the path of a server that only answers a scraper.
fn scrape_only(rp: &str) -> bool {
    let lower = rp.to_ascii_lowercase();
    SCRAPE_ONLY.iter().any(|t| lower.contains(t))
}

/// Whether a directory of `rp` is a teaching step or `exercises`, or one the
/// scanner reads as non-production.
fn teaching_or_non_production(rp: &str) -> bool {
    let Some((dir, _)) = rp.rsplit_once('/') else {
        return false;
    };
    dir.split('/').any(teaching_step) || non_production::path_token(&format!("{dir}/")).is_some()
}

/// `chapter3`, `ch-03`, `day_1`, `lesson2`, `module4`, `exercises`, or a
/// directory whose name starts with a number (`01-intro`).
fn teaching_step(dir: &str) -> bool {
    let d = dir.to_ascii_lowercase();
    let numbered = |s: &str| {
        s.trim_start_matches(['-', '_'])
            .starts_with(|c: char| c.is_ascii_digit())
    };
    d == "exercises"
        || (numbered(&d)
            && !d
                .trim_start_matches(|c: char| c.is_ascii_digit())
                .starts_with(['.', 'x']))
        || TEACHING_STEPS
            .iter()
            .any(|p| d.strip_prefix(p).is_some_and(numbered))
}

/// The token of the repository's name, or of its origin's owner and name,
/// that marks it as sample or teaching material, an exporter or a CSI driver.
fn repository_token(root: &Path) -> Option<String> {
    let name = match root.file_name() {
        Some(name) => Some(name.to_os_string()),
        None => root
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_os_string())),
    };
    let mut names: Vec<String> = name
        .map(|n| n.to_string_lossy().into_owned())
        .into_iter()
        .collect();
    if let Some(url) = origin(root) {
        let url = url.trim_end_matches('/').trim_end_matches(".git");
        names.extend(url.rsplit(['/', ':']).take(2).map(str::to_string));
    }
    let lists = [
        non_production::SAMPLE_REPOSITORY_TOKENS,
        TEACHING_REPOSITORY_TOKENS,
        NO_CLIENT_TRAFFIC_TOKENS,
    ];
    names.iter().find_map(|n| {
        n.split(|c: char| !c.is_alphanumeric())
            .map(str::to_lowercase)
            .find(|t| lists.iter().any(|l| l.contains(&t.as_str())))
    })
}

/// The URL of the `origin` remote in the repository's `.git/config`, if
/// there is one.
fn origin(root: &Path) -> Option<String> {
    let config = crate::inventory::read_capped(&root.join(".git/config"));
    let mut in_origin = false;
    for line in config.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_origin = t == "[remote \"origin\"]";
        } else if in_origin {
            if let Some((key, value)) = t.split_once('=') {
                if key.trim() == "url" {
                    return Some(value.trim().to_string());
                }
            }
        }
    }
    None
}

const CONTROL: &str = "RC-069";
const CONTROL_NAME: &str = "ingress rate limiting and load shedding";

/// RC-069 from the facts: violates in a completely walked service with no
/// code or config file of [`LIMITER_VOCABULARY`]; satisfies (weakly: a word
/// is not a limiter) when one holds it; abstains otherwise.
pub(crate) fn evaluate(facts: &RepoStructure) -> StructureFinding {
    crate::only_in_a_service(from_the_tree(facts), &facts.repo_kind)
}

fn from_the_tree(facts: &RepoStructure) -> StructureFinding {
    let mk = |verdict, reason: String, evidence: Vec<String>| StructureFinding {
        control: CONTROL,
        control_name: CONTROL_NAME,
        verdict,
        reason,
        evidence,
        fix: "limit requests per client at the ingress (a rate-limit annotation or gateway \
              policy) or in middleware (a token bucket), cap requests in flight, and answer \
              over the cap with 429 or 503 and a Retry-After before any work is done; exempt \
              health checks, make the limits configurable, and decide what the limiter does \
              when its own store fails"
            .into(),
        severity: "medium",
        weak: verdict == Verdict::Satisfies,
    };
    let Some(l) = &facts.limiter else {
        return mk(
            Verdict::Abstain,
            "the record carries no RC-069 facts: rate-limit vocabulary not read".into(),
            vec![],
        );
    };
    if l.vocabulary_files > 0 {
        return mk(
            Verdict::Satisfies,
            format!(
                "rate-limit or load-shedding vocabulary in {} code or config file(s) (weak \
                 signal: a name, not a limiter on every route)",
                l.vocabulary_files
            ),
            l.vocabulary.clone(),
        );
    }
    if let Some(token) = &l.repository_token {
        let what = if NO_CLIENT_TRAFFIC_TOKENS.contains(&token.as_str()) {
            "an exporter or a CSI driver, which takes no client traffic from the network"
        } else {
            "sample or teaching material, not a deployed service"
        };
        return mk(
            Verdict::Abstain,
            format!("the repository's name or owner holds \"{token}\": {what}"),
            vec![],
        );
    }
    if !facts.walk_complete {
        return mk(
            Verdict::Abstain,
            "walk truncated: absence of rate-limit vocabulary is not evidence".into(),
            vec![],
        );
    }
    if l.servers == 0 || l.deployments.is_empty() {
        return mk(
            Verdict::Abstain,
            "no web server entry point and deployment manifest of the service's own, outside \
             teaching, non-production and metrics, health or debug paths"
                .into(),
            vec![],
        );
    }
    if l.unix_servers == l.servers {
        return mk(
            Verdict::Abstain,
            format!(
                "every server entry point listens on a unix socket ({}): no client traffic \
                 from the network",
                l.server_paths.join(", ")
            ),
            l.server_paths.clone(),
        );
    }
    mk(
        Verdict::Violates,
        format!(
            "a deployed service ({}; {}) and no rate-limit or load-shedding vocabulary (rate \
             limit, throttle, limiter, limit_req, token bucket, 429, load shed, backpressure, \
             semaphore, concurrency limit) in any of {} code or config file(s) outside tests, \
             examples, docs and vendored code",
            l.server_paths.join(", "),
            l.deployments.join(", "),
            l.files_read
        ),
        [l.server_paths.clone(), l.deployments.clone()].concat(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_vocabulary_matches_any_case_and_spelling() {
        for text in [
            "r.Use(RateLimit(10))",
            "nginx.ingress.kubernetes.io/limit-rps: \"5\"",
            "w.WriteHeader(http.StatusTooManyRequests)",
            "from slowapi import Limiter",
            "sem := make(chan struct{}, maxInFlight) // semaphore",
            "接口限流",
        ] {
            assert!(holds_vocabulary(text), "{text}");
        }
        for text in ["func handle(w http.ResponseWriter) {}", "limit: 10 rows"] {
            assert!(!holds_vocabulary(text), "{text}");
        }
    }

    #[test]
    fn teaching_steps_are_numbered_directories() {
        for d in [
            "Chapter3",
            "ch03",
            "day_1",
            "lesson-2",
            "module4",
            "exercises",
            "01-intro",
        ] {
            assert!(teaching_step(d), "{d}");
        }
        for d in ["cmd", "chat", "modules", "v1", "daylight", "3x", "1.21"] {
            assert!(!teaching_step(d), "{d}");
        }
    }

    #[test]
    fn a_server_on_a_unix_socket_names_no_tcp_port() {
        assert!(unix_only(
            "lis, _ := net.Listen(\"unix\", \"/run/plugin.sock\")"
        ));
        assert!(!unix_only(
            "net.Listen(\"unix\", sock)\nhttp.ListenAndServe(\":8080\", nil)"
        ));
        assert!(!unix_only("grpc.NewServer()"));
    }

    #[test]
    fn generic_listen_calls_are_not_entry_points_here() {
        assert!(!entry_point("go", "l, _ := net.Listen(\"tcp\", addr)"));
        assert!(!entry_point("js", "server.listen(3000)"));
        assert!(entry_point("go", "r := gin.New()"));
        assert!(entry_point("go", "http.ListenAndServe(\":80\", r)"));
        assert!(entry_point(
            "ts",
            "const app = await NestFactory.create(AppModule)"
        ));
    }
}
