//! What kind of repository this is: a service, a tool or a library, read from
//! what the tree shows.
//!
//! A service is deployed to run and answer: it has a server entry point (an
//! HTTP or gRPC server, a listener) and a manifest that deploys a long-running
//! process (a Kubernetes workload, a Helm chart, a Dockerfile that exposes a
//! port, a Procfile `web` process). A tool is run by someone: a CLI main with
//! no deployment, or a repository that says it is an offensive or diagnostic
//! tool (a scanner, an exploit kit, an intercepting proxy, a netcat). A
//! library has source and no main at all.
//!
//! The question it answers is narrow: may a finding that is only wrong in a
//! deployed service, such as a TLS client that skips verification, block in
//! this repository? So it is built for precision. A tool marker wins over
//! every service signal, a service needs both a server entry point and a
//! deployment manifest, and what it cannot tell is [`RepoKind::Unknown`].
//! Examples, tests, fixtures and docs are not read: a scanner that ships a
//! sample Deployment is not deployed by it.
//!
//! Privacy: the evidence is repo-relative paths and the marker that matched,
//! never source text.

use crate::inventory::{read_capped, rel, SKIP_DIRS};
use std::path::Path;

/// The kind of a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoKind {
    /// Deployed: a server entry point and a deployment manifest.
    Service,
    /// Run by someone: a CLI main and no server, or an offensive or
    /// diagnostic tool by its own account.
    Tool,
    /// Source with no main.
    Library,
    /// None of the above can be told: a server with no deployment manifest,
    /// no source, or an incomplete walk.
    Unknown,
}

impl RepoKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoKind::Service => "service",
            RepoKind::Tool => "tool",
            RepoKind::Library => "library",
            RepoKind::Unknown => "unknown",
        }
    }
}

/// A repository's kind and what it was read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoKindFacts {
    pub kind: RepoKind,
    /// `<signal>: <path>` lines, at most [`MAX_EVIDENCE`] per signal, for the
    /// kind's own signals.
    pub evidence: Vec<String>,
}

/// The evidence lines kept per signal.
pub const MAX_EVIDENCE: usize = 2;

/// Directories whose contents do not say what the repository is: samples of
/// what it works on, its tests, its docs. Matched on any path component,
/// lowercased, in addition to the inventory's vendored and build directories.
const NOT_THE_REPO: &[&str] = &[
    "test",
    "tests",
    "testdata",
    "test-data",
    "test_data",
    "testing",
    "testutil",
    "testutils",
    "mock",
    "mocks",
    "fixtures",
    "e2e",
    "integration",
    "example",
    "examples",
    "_examples",
    "sample",
    "samples",
    "demo",
    "demos",
    "doc",
    "docs",
    "benchmark",
    "benchmarks",
    "third_party",
    "third-party",
];

/// Directories an offensive tool keeps its payloads in.
const TOOL_DIRS: &[&str] = &[
    "exploit",
    "exploits",
    "payload",
    "payloads",
    "poc",
    "pocs",
    "shellcode",
    "webshell",
    "webshells",
];

/// Directories of a service repository that hold what a person runs, not
/// what is deployed: a CLI, its tools and scripts, a diagnostics command. A
/// service's own CLI may skip verification to inspect a peer (a mesh's
/// `identity` check does), so a site there is not in the service.
const RUN_BY_HAND: &[&str] = &[
    "cli",
    "tool",
    "tools",
    "hack",
    "script",
    "scripts",
    "diagnostics",
    "debug",
];

/// Whether the file at repo-relative `path` is part of what a service
/// repository deploys: no component of it is a directory the classifier does
/// not read (tests, examples, docs), a payload directory, or one that holds
/// what a person runs (a `cli/`, `tools/`, `scripts/`).
pub fn in_service_code(path: &str) -> bool {
    let mut dirs: Vec<&str> = path.split(['/', '\\']).collect();
    dirs.pop();
    !dirs.iter().any(|d| {
        let d = d.to_ascii_lowercase();
        SKIP_DIRS.contains(&d.as_str())
            || [NOT_THE_REPO, TOOL_DIRS, RUN_BY_HAND]
                .iter()
                .any(|t| t.contains(&d.as_str()))
    })
}

/// What a README says when the repository is an offensive or diagnostic tool.
/// ASCII phrases match as whole words, lowercased.
const TOOL_PHRASES: &[&str] = &[
    "penetration test",
    "penetration testing",
    "pentest",
    "pentesting",
    "red team",
    "red teaming",
    "redteam",
    "offensive security",
    "post-exploitation",
    "exploit framework",
    "exploitation framework",
    "vulnerability scanner",
    "vulnerability scanning",
    "security scanner",
    "port scanner",
    "port scanning",
    "reverse shell",
    "command and control",
    "c2 framework",
    "man-in-the-middle",
    "mitm",
    "intercepting proxy",
    "netcat",
    "diagnostic tool",
    "diagnostics tool",
    "debugging tool",
    "troubleshooting tool",
    "渗透测试",
    "漏洞扫描",
    "内网扫描",
    "红队",
];

/// Server entry points: a call that serves or listens, by source extension.
const LISTENERS: &[(&[&str], &[&str])] = &[
    (
        &["go"],
        &[
            "ListenAndServe(",
            "ListenAndServeTLS(",
            "grpc.NewServer(",
            "net.Listen(",
            "http.Server{",
            "gin.Default(",
            "echo.New(",
            "fiber.New(",
        ],
    ),
    (
        &["py"],
        &[
            "uvicorn.run(",
            "web.run_app(",
            "serve_forever(",
            "make_server(",
            "grpc.server(",
            "Flask(__name__",
            "FastAPI(",
            "app.run(",
        ],
    ),
    (
        &["js", "mjs", "cjs", "ts"],
        &[
            "createServer(",
            "express()",
            "new Koa(",
            "fastify(",
            "Fastify(",
            ".listen(",
        ],
    ),
    (
        &["rs"],
        &[
            "axum::serve",
            "HttpServer::new",
            "TcpListener::bind",
            "hyper::Server",
            "transport::Server::builder",
            "warp::serve",
            "rocket::build",
        ],
    ),
    (
        &["java", "kt"],
        &[
            "@SpringBootApplication",
            "HttpServer.create(",
            "new ServerSocket(",
            "ServerBuilder.forPort(",
            "embeddedServer(",
        ],
    ),
    (
        &["cs"],
        &[
            "WebApplication.CreateBuilder",
            "UseKestrel",
            "CreateHostBuilder",
        ],
    ),
];

/// A main a person runs, by source extension.
const MAINS: &[(&[&str], &[&str])] = &[
    (&["go"], &["func main()"]),
    (
        &["py"],
        &["if __name__ == \"__main__\"", "if __name__ == '__main__'"],
    ),
    (&["rs"], &["fn main()"]),
    (&["java", "kt"], &["public static void main(", "fun main("]),
    (&["cs"], &["static void Main(", "static async Task Main("]),
];

const SOURCE_EXTS: &[&str] = &[
    "go", "py", "js", "mjs", "cjs", "ts", "rs", "java", "kt", "cs",
];

/// Kubernetes kinds that run a long-lived process.
const WORKLOADS: &[&str] = &["Deployment", "StatefulSet", "DaemonSet"];

#[derive(Default)]
struct Signals {
    tool: Vec<String>,
    deploy: Vec<String>,
    listener: Vec<String>,
    main: Vec<String>,
    sources: u32,
    complete: bool,
}

fn note(into: &mut Vec<String>, what: &str, path: &str) {
    if into.len() < MAX_EVIDENCE {
        into.push(format!("{what}: {path}"));
    }
}

/// Classify the repository at `root`.
pub fn repo_kind(root: &Path) -> RepoKindFacts {
    let mut s = Signals {
        complete: true,
        ..Default::default()
    };
    readme_markers(root, &mut s);
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            s.complete = false;
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else {
                s.complete = false;
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let lower = name.to_ascii_lowercase();
            if ft.is_dir() {
                if SKIP_DIRS.contains(&name.as_str())
                    || NOT_THE_REPO.contains(&lower.as_str())
                    || RUN_BY_HAND.contains(&lower.as_str())
                {
                    continue;
                }
                if TOOL_DIRS.contains(&lower.as_str()) {
                    note(&mut s.tool, "payload directory", &rel(root, &entry.path()));
                }
                stack.push(entry.path());
            } else if ft.is_file() {
                file(root, &entry.path(), &name, &mut s);
            }
        }
    }
    decide(s)
}

/// The kind the signals add up to. A tool marker wins; a service needs both
/// a server and a deployment; a library is an absence, read only from a
/// complete walk.
fn decide(s: Signals) -> RepoKindFacts {
    let (kind, evidence) = if !s.tool.is_empty() {
        (RepoKind::Tool, s.tool)
    } else if !s.deploy.is_empty() && !s.listener.is_empty() {
        (RepoKind::Service, [s.deploy, s.listener].concat())
    } else if !s.listener.is_empty() {
        (RepoKind::Unknown, s.listener)
    } else if !s.main.is_empty() {
        (RepoKind::Tool, s.main)
    } else if s.sources > 0 && s.complete {
        (RepoKind::Library, Vec::new())
    } else {
        (RepoKind::Unknown, Vec::new())
    };
    RepoKindFacts { kind, evidence }
}

/// The README at the root, and what it says the repository is.
fn readme_markers(root: &Path, s: &mut Signals) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.to_ascii_lowercase().starts_with("readme") {
            continue;
        }
        let text = read_capped(&entry.path()).to_lowercase();
        if let Some(p) = TOOL_PHRASES.iter().find(|p| has_phrase(&text, p)) {
            note(&mut s.tool, &format!("README says \"{p}\""), &name);
        }
    }
}

/// `phrase` in `text` as a whole word: an ASCII phrase must not touch a
/// letter or digit on either side. A non-ASCII phrase matches anywhere.
fn has_phrase(text: &str, phrase: &str) -> bool {
    if !phrase.is_ascii() {
        return text.contains(phrase);
    }
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    text.match_indices(phrase).any(|(i, _)| {
        !word(text[..i].chars().next_back()) && !word(text[i + phrase.len()..].chars().next())
    })
}

fn file(root: &Path, path: &Path, name: &str, s: &mut Signals) {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let rp = rel(root, path);
    if name == "Dockerfile" || name.starts_with("Dockerfile.") || ext == "dockerfile" {
        if dockerfile_serves(&read_capped(path)) {
            note(&mut s.deploy, "Dockerfile that serves", &rp);
        }
    } else if name == "Chart.yaml" {
        note(&mut s.deploy, "Helm chart", &rp);
    } else if name == "Procfile" {
        if read_capped(path).lines().any(|l| l.starts_with("web:")) {
            note(&mut s.deploy, "Procfile web process", &rp);
        }
    } else if ext == "yaml" || ext == "yml" {
        if s.deploy.len() < MAX_EVIDENCE && k8s_workload(&read_capped(path)) {
            note(&mut s.deploy, "Kubernetes workload", &rp);
        }
    } else if SOURCE_EXTS.contains(&ext.as_str()) && !is_test_source(name) {
        s.sources += 1;
        // Enough evidence of both is enough: later files need not be read.
        if s.listener.len() >= MAX_EVIDENCE && s.main.len() >= MAX_EVIDENCE {
            return;
        }
        let text = read_capped(path);
        let found = |table: &[(&[&str], &[&str])]| {
            table
                .iter()
                .filter(|(exts, _)| exts.contains(&ext.as_str()))
                .flat_map(|(_, markers)| markers.iter())
                .any(|m| text.contains(m))
        };
        if found(LISTENERS) {
            note(&mut s.listener, "server entry point", &rp);
        }
        if found(MAINS) || (ext == "py" && name == "__main__.py") {
            note(&mut s.main, "main", &rp);
        }
    }
}

fn is_test_source(name: &str) -> bool {
    name.ends_with("_test.go")
        || name.starts_with("test_")
        || name.ends_with("_test.py")
        || name.contains(".test.")
        || name.contains(".spec.")
}

/// A Dockerfile that runs a server: it exposes a port.
fn dockerfile_serves(text: &str) -> bool {
    text.lines()
        .any(|l| l.trim_start().to_ascii_uppercase().starts_with("EXPOSE "))
}

/// A Kubernetes manifest (any document of it) for a long-lived workload.
fn k8s_workload(text: &str) -> bool {
    text.contains("apiVersion:")
        && text.lines().any(|l| {
            l.strip_prefix("kind:")
                .is_some_and(|k| WORKLOADS.contains(&k.trim().trim_matches('"')))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, text) in files {
            let p = dir.path().join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    const SERVER: &str = "package main\n\nfunc main() { http.ListenAndServe(\":8080\", nil) }\n";
    const CLI: &str = "package main\n\nfunc main() { flag.Parse() }\n";
    const DEPLOYMENT: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\n";

    #[test]
    fn a_server_with_a_deployment_manifest_is_a_service() {
        for deploy in [
            ("deploy/api.yaml", DEPLOYMENT),
            ("Dockerfile", "FROM scratch\nEXPOSE 8080\nCMD [\"/api\"]\n"),
            ("charts/api/Chart.yaml", "apiVersion: v2\nname: api\n"),
            ("Procfile", "web: ./api\n"),
        ] {
            let dir = repo(&[("cmd/api/main.go", SERVER), deploy]);
            let k = repo_kind(dir.path());
            assert_eq!(k.kind, RepoKind::Service, "{deploy:?}: {k:?}");
            assert!(
                k.evidence.iter().any(|e| e.ends_with(deploy.0))
                    && k.evidence.iter().any(|e| e.ends_with("cmd/api/main.go")),
                "{k:?}"
            );
        }
    }

    #[test]
    fn a_server_with_no_deployment_or_a_deployment_with_no_server_is_not_a_service() {
        let k = repo_kind(repo(&[("main.go", SERVER)]).path());
        assert_eq!(k.kind, RepoKind::Unknown, "{k:?}");
        let k = repo_kind(repo(&[("main.go", CLI), ("k8s/job.yaml", DEPLOYMENT)]).path());
        assert_eq!(k.kind, RepoKind::Tool, "{k:?}");
        // A Dockerfile that only packages a CLI exposes nothing.
        let dir = repo(&[
            ("main.go", SERVER),
            ("Dockerfile", "FROM x\nENTRYPOINT [\"/t\"]\n"),
        ]);
        assert_eq!(repo_kind(dir.path()).kind, RepoKind::Unknown);
    }

    /// Fleet tools that disable verification on purpose say what they are.
    #[test]
    fn a_tool_marker_wins_over_every_service_signal() {
        for (readme, marker) in [
            (
                "# scan\nAn intranet vulnerability scanner.\n",
                "vulnerability scanner",
            ),
            ("A reverse shell over SSH.", "reverse shell"),
            (
                "mitmproxy is an interactive, TLS-capable intercepting proxy",
                "intercepting proxy",
            ),
            (
                "一款内网综合扫描工具，方便一键自动化、全方位漏扫扫描。渗透测试",
                "渗透测试",
            ),
        ] {
            let dir = repo(&[
                ("README.md", readme),
                ("main.go", SERVER),
                ("deploy/api.yaml", DEPLOYMENT),
            ]);
            let k = repo_kind(dir.path());
            assert_eq!(k.kind, RepoKind::Tool, "{readme}: {k:?}");
            assert_eq!(k.evidence, [format!("README says \"{marker}\": README.md")]);
        }
        let dir = repo(&[("pocs/cve.yaml", "id: x\n"), ("main.go", SERVER)]);
        let k = repo_kind(dir.path());
        assert_eq!(
            (k.kind, k.evidence),
            (RepoKind::Tool, vec!["payload directory: pocs".into()])
        );
    }

    #[test]
    fn a_marker_matches_a_whole_word_only() {
        assert!(has_phrase("a mitm proxy", "mitm"));
        assert!(!has_phrase("submitmail", "mitm"));
        assert!(has_phrase("(netcat)", "netcat"));
        assert!(!has_phrase("netcats", "netcat"));
        assert!(has_phrase("一个红队工具", "红队"));
    }

    #[test]
    fn source_with_no_main_is_a_library_and_no_source_is_unknown() {
        let dir = repo(&[
            ("lib.go", "package lib\n\nfunc Dial() {}\n"),
            ("lib_test.go", CLI),
        ]);
        assert_eq!(repo_kind(dir.path()).kind, RepoKind::Library);
        assert_eq!(
            repo_kind(repo(&[("README.md", "hi")]).path()).kind,
            RepoKind::Unknown
        );
    }

    /// Samples, tests and docs say what the repository works on, not what it is.
    #[test]
    fn examples_tests_and_docs_are_not_read() {
        let dir = repo(&[
            ("lib.go", "package lib\n"),
            ("examples/server/main.go", SERVER),
            ("examples/k8s/app.yaml", DEPLOYMENT),
            ("internal/testdata/Dockerfile", "EXPOSE 80\n"),
            ("docs/deploy.yaml", DEPLOYMENT),
            ("server_test.go", SERVER),
        ]);
        let k = repo_kind(dir.path());
        assert_eq!(k.kind, RepoKind::Library, "{k:?}");
    }

    /// A service repository's CLI, scripts and tests are not what it deploys.
    #[test]
    fn a_site_in_a_cli_tools_or_test_directory_is_not_in_service_code() {
        for path in [
            "controller/api/server.go",
            "pkg/tls.go",
            "tls.go",
            "src/cliente/x.go",
        ] {
            assert!(in_service_code(path), "{path}");
        }
        for path in [
            "cli/cmd/identity.go",
            "tools/probe/main.go",
            "hack/dial.go",
            "internal/testutil/tls.go",
            "examples/client.go",
            "vendor/x/tls.go",
            "Scripts\\fetch.py",
        ] {
            assert!(!in_service_code(path), "{path}");
        }
    }

    #[test]
    fn a_workload_kind_is_read_from_any_document_of_a_manifest() {
        assert!(k8s_workload(
            "apiVersion: v1\nkind: Service\n---\napiVersion: apps/v1\nkind: \"StatefulSet\"\n"
        ));
        assert!(!k8s_workload("apiVersion: batch/v1\nkind: Job\n"));
        assert!(!k8s_workload("kind: Deployment\n"), "no apiVersion");
    }
}
