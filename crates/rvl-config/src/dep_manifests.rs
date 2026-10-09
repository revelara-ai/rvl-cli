//! Dependency-manifest retriever: family (4) of the G6 config lane
//! (po-av01j.22). One retriever, several manifest dialects — package.json,
//! go.mod, Cargo.toml, pyproject.toml, requirements*.txt, Dockerfile — all
//! emitting packets under the single format id `dep-manifests`, with the
//! dialect embedded in the KEY (`package_json.engines.node`,
//! `go_mod.toolchain`, `dockerfile.base_image_pin`) so one spec judges one
//! key identity everywhere.
//!
//! A Dockerfile also emits `dockerfile.final_stage_user`, once: the user the
//! built image starts as, from the last `USER` of the final stage (through
//! the earlier stages it is built `FROM`). The value is a class, `root` /
//! `non-root` / `absent`, never the account name. `absent` is a fact about
//! the file and not a verdict of root: with no `USER`, the base image decides,
//! and the base image is not in the repository.
//!
//! ALTITUDE BOUNDARY (do not blur it): the G7 repo-structure lane
//! (`rvl-structure`, po-av01j.7) owns STRUCTURAL dependency hygiene —
//! lockfile presence/consistency per manifest and the aggregate pin counts
//! that feed its single RC-070 finding. This module emits NO
//! lockfile-presence packets. It works at the config-SPEC altitude: per-KEY
//! resolved values with provenance chains, judged by signed
//! [`rvl_spec::ConfigKeySpec`]s and waived under `dep-manifests.<key>` class
//! rules — a namespace disjoint from the structure lane's by construction.
//!
//! PIN SHAPES, not version content: where a control cares about HOW a
//! dependency is pinned rather than which version it names, the resolved
//! value is a shape from a closed vocabulary — `exact` / `range` /
//! `floating` / `digest` (Dockerfiles use `digest` / `tag` / `latest`, the
//! trichotomy the pinning control judges). Loosest-pin keys aggregate a whole
//! section into its weakest shape, so no packet ever inventories package
//! names — this is not an SBOM. Identity appears in provenance only where the
//! fix needs it (a base-image ref, a packageManager name), mirroring the
//! GitHub Actions retriever carrying action names.
//!
//! Single-file contract: `retrieve` sees one file. Cargo `edition.workspace =
//! true` resolves through the SAME file's `[workspace.package]` when present
//! (the root-manifest case); a member manifest inheriting from another file
//! is emitted as [`Resolution::Unresolvable`] — the lane abstains rather than
//! chasing cross-file inheritance it cannot prove here.

use crate::{ConfigPacket, ConfigRetriever, ProvenanceStep, Resolution, Retrieved};

pub struct DepManifests;

const FORMAT: &str = "dep-manifests";

/// Pin shapes, tightest to loosest. `loosest` picks the highest index.
const SHAPE_DIGEST: &str = "digest";
const SHAPE_EXACT: &str = "exact";
const SHAPE_RANGE: &str = "range";
const SHAPE_FLOATING: &str = "floating";

impl ConfigRetriever for DepManifests {
    fn format_id(&self) -> &'static str {
        FORMAT
    }

    /// Basename-shaped: manifests live at any depth (monorepos), and the
    /// lane walk already excludes vendored trees (node_modules, vendor,
    /// target, testdata).
    fn matches(&self, rel_path: &str) -> bool {
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        matches!(
            name,
            "package.json" | "go.mod" | "Cargo.toml" | "pyproject.toml" | "Containerfile"
        ) || name == "Dockerfile"
            || name.starts_with("Dockerfile.")
            || name.ends_with(".dockerfile")
            || (name.starts_with("requirements") && name.ends_with(".txt"))
    }

    fn retrieve(&self, rel_path: &str, contents: &str, snapshot_id: &str) -> Retrieved {
        let name = rel_path.rsplit('/').next().unwrap_or(rel_path);
        let cx = Cx {
            rel_path,
            snapshot_id,
        };
        match name {
            "package.json" => package_json(&cx, contents),
            "go.mod" => go_mod(&cx, contents),
            "Cargo.toml" => cargo_toml(&cx, contents),
            "pyproject.toml" => pyproject(&cx, contents),
            _ if name.starts_with("requirements") && name.ends_with(".txt") => {
                requirements(&cx, contents)
            }
            _ => dockerfile(&cx, contents),
        }
    }
}

/// Per-file context shared by the dialect parsers.
struct Cx<'a> {
    rel_path: &'a str,
    snapshot_id: &'a str,
}

impl Cx<'_> {
    fn packet(
        &self,
        unit: &str,
        key: &str,
        value: Option<String>,
        resolution: Resolution,
        provenance: Vec<ProvenanceStep>,
    ) -> ConfigPacket {
        ConfigPacket {
            snapshot_id: self.snapshot_id.to_string(),
            format: FORMAT.to_string(),
            file_path: self.rel_path.to_string(),
            line: 0,
            unit: unit.to_string(),
            key: crate::key_ledger::declared(FORMAT, key),
            resolved_value: value,
            resolution,
            provenance,
        }
    }
}

/// The loosest of a set of shapes: floating > range > exact > digest.
fn loosest(shapes: &[&'static str]) -> Option<&'static str> {
    const ORDER: &[&str] = &[SHAPE_DIGEST, SHAPE_EXACT, SHAPE_RANGE, SHAPE_FLOATING];
    shapes
        .iter()
        .max_by_key(|s| ORDER.iter().position(|o| o == *s).unwrap_or(0))
        .copied()
}

// --- package.json ---------------------------------------------------------

fn package_json(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let Ok(doc) = serde_json::from_str::<serde_json::Value>(contents) else {
        out.unparseable = 1;
        return out;
    };
    let Some(root) = doc.as_object() else {
        out.unparseable = 1;
        return out;
    };
    let unit = "manifest";

    // package_json.engines.node: the runtime bound (RC-070 class).
    match root
        .get("engines")
        .and_then(|e| e.get("node"))
        .and_then(|v| v.as_str())
    {
        Some(range) => out.packets.push(cx.packet(
            unit,
            "package_json.engines.node",
            Some(range.to_string()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(cx.rel_path, "engines.node", "explicit")],
        )),
        None => out.packets.push(cx.packet(
            unit,
            "package_json.engines.node",
            Some("unconstrained".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(cx.rel_path, "engines.node", "absent"),
                ProvenanceStep::new("", "engines.node", "platform-default"),
            ],
        )),
    }

    // package_json.package_manager.pin: the corepack pin SHAPE. The version
    // content is dropped; only the shape and the manager name (identity for
    // the fix) survive.
    match root.get("packageManager").and_then(|v| v.as_str()) {
        Some(pm) => {
            let (mgr, rest) = pm.split_once('@').unwrap_or((pm, ""));
            let shape = if rest.contains('+') {
                SHAPE_DIGEST // name@x.y.z+sha256.<hash>
            } else if is_exact_semver(rest) {
                SHAPE_EXACT
            } else {
                SHAPE_FLOATING
            };
            out.packets.push(cx.packet(
                unit,
                "package_json.package_manager.pin",
                Some(shape.to_string()),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    cx.rel_path,
                    &format!("packageManager = {mgr}"),
                    "explicit",
                )],
            ));
        }
        None => out.packets.push(cx.packet(
            unit,
            "package_json.package_manager.pin",
            Some("unconstrained".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(cx.rel_path, "packageManager", "absent"),
                ProvenanceStep::new("", "packageManager", "platform-default"),
            ],
        )),
    }

    // package_json.overrides.count: how many dependency overrides this
    // manifest forces (npm overrides + yarn resolutions + pnpm.overrides).
    // A count only — never the overridden names.
    let section_len =
        |v: Option<&serde_json::Value>| v.and_then(|s| s.as_object()).map(|o| o.len()).unwrap_or(0);
    let count = section_len(root.get("overrides"))
        + section_len(root.get("resolutions"))
        + section_len(root.get("pnpm").and_then(|p| p.get("overrides")));
    out.packets.push(cx.packet(
        unit,
        "package_json.overrides.count",
        Some(count.to_string()),
        Resolution::AsAuthored,
        vec![ProvenanceStep::new(
            cx.rel_path,
            "overrides/resolutions/pnpm.overrides",
            if count > 0 { "explicit" } else { "absent" },
        )],
    ));
    out
}

/// A bare `x.y.z` (numeric triple) — the shape `packageManager` requires.
fn is_exact_semver(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

// --- go.mod ---------------------------------------------------------------

fn go_mod(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let mut has_module = false;
    let mut go_directive: Option<String> = None;
    let mut toolchain: Option<String> = None;
    let mut replace_count = 0usize;
    let mut in_replace_block = false;

    for raw in contents.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if in_replace_block {
            if line == ")" {
                in_replace_block = false;
            } else if line.contains("=>") {
                replace_count += 1;
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("module ") {
            has_module = !rest.trim().is_empty();
        } else if let Some(rest) = line.strip_prefix("go ") {
            go_directive = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("toolchain ") {
            toolchain = Some(rest.trim().to_string());
        } else if line == "replace (" {
            in_replace_block = true;
        } else if line.starts_with("replace ") && line.contains("=>") {
            replace_count += 1;
        }
    }

    if !has_module {
        // Matched the go.mod path shape but is not a module file: coverage
        // says the lane saw and skipped it, same contract as a jobless
        // workflow.
        out.unparseable = 1;
        return out;
    }
    let unit = "module";

    match go_directive {
        Some(v) => out.packets.push(cx.packet(
            unit,
            "go_mod.go",
            Some(v),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(cx.rel_path, "go", "explicit")],
        )),
        // A module without a go directive is assumed go 1.16 (documented).
        None => out.packets.push(cx.packet(
            unit,
            "go_mod.go",
            Some("1.16".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(cx.rel_path, "go", "absent"),
                ProvenanceStep::new("", "go directive", "platform-default"),
            ],
        )),
    }

    match toolchain {
        Some(v) => out.packets.push(cx.packet(
            unit,
            "go_mod.toolchain",
            Some(v),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(cx.rel_path, "toolchain", "explicit")],
        )),
        // Absent toolchain line = the documented `local` selection rule.
        None => out.packets.push(cx.packet(
            unit,
            "go_mod.toolchain",
            Some("local".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(cx.rel_path, "toolchain", "absent"),
                ProvenanceStep::new("", "toolchain", "platform-default"),
            ],
        )),
    }

    out.packets.push(cx.packet(
        unit,
        "go_mod.replace.count",
        Some(replace_count.to_string()),
        Resolution::AsAuthored,
        vec![ProvenanceStep::new(
            cx.rel_path,
            "replace",
            if replace_count > 0 {
                "explicit"
            } else {
                "absent"
            },
        )],
    ));
    out
}

// --- Cargo.toml -----------------------------------------------------------

fn cargo_toml(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();
    // A manifest is a DOCUMENT: `toml::Table`. Since toml 0.9 `toml::Value`
    // parses one value, so it refuses every manifest (po-av01j.234).
    let Ok(doc) = contents.parse::<toml::Table>() else {
        out.unparseable = 1;
        return out;
    };

    // cargo_toml.package.edition — only for real packages; a virtual
    // workspace manifest has no edition of its own.
    if let Some(pkg) = doc.get("package").and_then(|p| p.as_table()) {
        let ws_edition = doc
            .get("workspace")
            .and_then(|w| w.get("package"))
            .and_then(|p| p.get("edition"))
            .and_then(|e| e.as_str());
        match pkg.get("edition") {
            Some(toml::Value::String(s)) => out.packets.push(cx.packet(
                "package",
                "cargo_toml.package.edition",
                Some(s.clone()),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    cx.rel_path,
                    "package.edition",
                    "explicit",
                )],
            )),
            Some(v) if v.get("workspace").and_then(|w| w.as_bool()) == Some(true) => {
                match ws_edition {
                    // Root manifest inheriting from its own [workspace.package].
                    Some(ws) => out.packets.push(cx.packet(
                        "package",
                        "cargo_toml.package.edition",
                        Some(ws.to_string()),
                        Resolution::AsAuthored,
                        vec![
                            ProvenanceStep::new(cx.rel_path, "package.edition", "absent"),
                            ProvenanceStep::new(
                                cx.rel_path,
                                "workspace.package.edition",
                                "inherited",
                            ),
                        ],
                    )),
                    // A member manifest inherits from ANOTHER file; the
                    // single-file contract abstains rather than chasing it.
                    None => out.packets.push(cx.packet(
                        "package",
                        "cargo_toml.package.edition",
                        None,
                        Resolution::Unresolvable,
                        vec![
                            ProvenanceStep::new(
                                cx.rel_path,
                                "package.edition = { workspace = true }",
                                "explicit",
                            ),
                            ProvenanceStep::new(
                                "",
                                "workspace.package.edition (workspace root manifest)",
                                "workspace-setting",
                            ),
                        ],
                    )),
                }
            }
            // The documented default edition for an unset field.
            _ => out.packets.push(cx.packet(
                "package",
                "cargo_toml.package.edition",
                Some("2015".to_string()),
                Resolution::PlatformDefault,
                vec![
                    ProvenanceStep::new(cx.rel_path, "package.edition", "absent"),
                    ProvenanceStep::new("", "edition", "platform-default"),
                ],
            )),
        }
    }

    // cargo_toml.workspace_dependencies.loosest_pin — the weakest pin shape
    // across [workspace.dependencies]. Shape only; no crate names.
    if let Some(deps) = doc
        .get("workspace")
        .and_then(|w| w.get("dependencies"))
        .and_then(|d| d.as_table())
    {
        let shapes: Vec<&'static str> = deps.values().filter_map(cargo_dep_shape).collect();
        if let Some(worst) = loosest(&shapes) {
            out.packets.push(cx.packet(
                "workspace",
                "cargo_toml.workspace_dependencies.loosest_pin",
                Some(worst.to_string()),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    cx.rel_path,
                    &format!("workspace.dependencies ({} entries)", shapes.len()),
                    "explicit",
                )],
            ));
        }
    }
    out
}

/// The pin shape of one Cargo dependency entry; `None` for entries that carry
/// no registry pin question (pure path deps).
fn cargo_dep_shape(v: &toml::Value) -> Option<&'static str> {
    match v {
        toml::Value::String(req) => Some(cargo_req_shape(req)),
        toml::Value::Table(t) => {
            if let Some(req) = t.get("version").and_then(|v| v.as_str()) {
                return Some(cargo_req_shape(req));
            }
            if t.contains_key("git") {
                // A git dep pinned to a rev or tag is exact; branch-or-HEAD
                // floats with the remote.
                return if t.contains_key("rev") || t.contains_key("tag") {
                    Some(SHAPE_EXACT)
                } else {
                    Some(SHAPE_FLOATING)
                };
            }
            if t.contains_key("path") {
                return None; // in-repo; no pin shape to judge
            }
            Some(SHAPE_FLOATING)
        }
        _ => Some(SHAPE_FLOATING),
    }
}

/// Cargo version-requirement shape. Bare `1.2.3` is caret semantics — a
/// RANGE; only `=` makes it exact; wildcards float.
fn cargo_req_shape(req: &str) -> &'static str {
    let req = req.trim();
    if req.is_empty() || req == "*" || req.contains('*') {
        SHAPE_FLOATING
    } else if req.starts_with('=') {
        SHAPE_EXACT
    } else {
        SHAPE_RANGE
    }
}

// --- pyproject.toml -------------------------------------------------------

fn pyproject(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let Ok(doc) = contents.parse::<toml::Table>() else {
        out.unparseable = 1;
        return out;
    };
    let unit = "project";
    let project = doc.get("project");

    // pyproject.requires_python: PEP 621 first, then the poetry spelling.
    let pep621 = project
        .and_then(|p| p.get("requires-python"))
        .and_then(|v| v.as_str());
    let poetry = doc
        .get("tool")
        .and_then(|t| t.get("poetry"))
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.get("python"))
        .and_then(|v| v.as_str());
    match (pep621, poetry) {
        (Some(v), _) => out.packets.push(cx.packet(
            unit,
            "pyproject.requires_python",
            Some(v.to_string()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(
                cx.rel_path,
                "project.requires-python",
                "explicit",
            )],
        )),
        (None, Some(v)) => out.packets.push(cx.packet(
            unit,
            "pyproject.requires_python",
            Some(v.to_string()),
            Resolution::AsAuthored,
            vec![
                ProvenanceStep::new(cx.rel_path, "project.requires-python", "absent"),
                ProvenanceStep::new(cx.rel_path, "tool.poetry.dependencies.python", "explicit"),
            ],
        )),
        (None, None) => out.packets.push(cx.packet(
            unit,
            "pyproject.requires_python",
            Some("unconstrained".to_string()),
            Resolution::PlatformDefault,
            vec![
                ProvenanceStep::new(cx.rel_path, "project.requires-python", "absent"),
                ProvenanceStep::new("", "requires-python", "platform-default"),
            ],
        )),
    }

    // pyproject.dependencies.loosest_pin over [project] dependencies.
    if let Some(deps) = project
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
    {
        let shapes: Vec<&'static str> = deps
            .iter()
            .filter_map(|d| d.as_str())
            .map(pep508_shape)
            .collect();
        if let Some(worst) = loosest(&shapes) {
            out.packets.push(cx.packet(
                unit,
                "pyproject.dependencies.loosest_pin",
                Some(worst.to_string()),
                Resolution::AsAuthored,
                vec![ProvenanceStep::new(
                    cx.rel_path,
                    &format!("project.dependencies ({} entries)", shapes.len()),
                    "explicit",
                )],
            ));
        }
    }
    out
}

/// The pin shape of one PEP 508 requirement string.
fn pep508_shape(req: &str) -> &'static str {
    // Environment markers narrow applicability, not the pin.
    let req = req.split(';').next().unwrap_or(req).trim();
    if req.contains('@') {
        // Direct URL/VCS reference.
        return url_ref_shape(req);
    }
    if req.contains("==") {
        SHAPE_EXACT
    } else if req.contains(['<', '>', '~', '!']) {
        SHAPE_RANGE
    } else {
        SHAPE_FLOATING // bare name: any release satisfies it
    }
}

/// Shape of a direct URL / VCS requirement (shared by pyproject and
/// requirements.txt): a 40-hex rev pins exactly, `#sha256=` is a digest, a
/// tag/branch ref is a range, a bare URL floats with the remote.
fn url_ref_shape(req: &str) -> &'static str {
    if req.contains("#sha256=") {
        return SHAPE_DIGEST;
    }
    match req.rsplit_once('@') {
        Some((_, rev)) => {
            let rev = rev.trim();
            if rev.len() == 40 && rev.bytes().all(|b| b.is_ascii_hexdigit()) {
                SHAPE_EXACT
            } else if rev.is_empty() {
                SHAPE_FLOATING
            } else {
                SHAPE_RANGE // a named tag or branch: mutable but named
            }
        }
        None => SHAPE_FLOATING,
    }
}

// --- requirements*.txt ----------------------------------------------------

fn requirements(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();

    // Join backslash continuations first: pip hash mode spreads one
    // requirement (with its --hash options) over several physical lines.
    let mut logical: Vec<String> = Vec::new();
    let mut pending = String::new();
    for raw in contents.lines() {
        let piece = raw.trim();
        if let Some(stripped) = piece.strip_suffix('\\') {
            pending.push_str(stripped);
            pending.push(' ');
            continue;
        }
        pending.push_str(piece);
        logical.push(std::mem::take(&mut pending));
    }
    if !pending.is_empty() {
        logical.push(pending);
    }

    let mut shapes: Vec<&'static str> = Vec::new();
    for line in &logical {
        let line = match line.find(" #") {
            Some(i) => line[..i].trim(),
            None => line.trim(),
        };
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue; // blank, comment, or an option line (-r, -e, --index-url, ...)
        }
        shapes.push(requirement_shape(line));
    }

    if let Some(worst) = loosest(&shapes) {
        out.packets.push(cx.packet(
            "manifest",
            "requirements_txt.loosest_pin",
            Some(worst.to_string()),
            Resolution::AsAuthored,
            vec![ProvenanceStep::new(
                cx.rel_path,
                &format!("{} requirements", shapes.len()),
                "explicit",
            )],
        ));
    }
    // A requirements file with no requirement lines (empty, comments, or
    // only includes) is valid and emits nothing.
    out
}

/// The pin shape of one requirements.txt line.
fn requirement_shape(line: &str) -> &'static str {
    if line.contains("--hash=") {
        return SHAPE_DIGEST; // hash-checking mode: content-addressed
    }
    if line.contains("://") {
        return url_ref_shape(line);
    }
    if line.contains("==") {
        SHAPE_EXACT
    } else if line.contains(['<', '>', '~', '!']) {
        SHAPE_RANGE
    } else {
        SHAPE_FLOATING
    }
}

// --- Dockerfile -----------------------------------------------------------

/// Final-stage user classes: the closed vocabulary of
/// `dockerfile.final_stage_user`. No `USER` anywhere in the stage chain is
/// [`crate::ABSENT_RENDERING`].
const USER_ROOT: &str = "root";
const USER_NON_ROOT: &str = "non-root";

/// The user one build stage ends with, and what decided it.
#[derive(Clone)]
struct StageUser {
    /// `root`, `non-root` or `absent`; `None` when only the build invocation
    /// knows the value.
    class: Option<&'static str>,
    /// The line that decides: the last `USER`, or the stage's `FROM` when
    /// there is none.
    line: u32,
    provenance: Vec<ProvenanceStep>,
}

fn dockerfile(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let mut arg_defaults: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    // Names an ENV sets. ENV wins over ARG in a substitution, and its value
    // is not tracked, so a USER that reads one of these is not resolved.
    let mut env_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut stage_of_alias: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    // One entry per FROM, in order. The index is the stage index.
    let mut stage_users: Vec<StageUser> = Vec::new();

    // Physical lines that are not instructions: the rest of a continued
    // instruction, and the body of a heredoc.
    let mut escape = '\\';
    let mut saw_instruction = false;
    let mut continued = false;
    let mut takes_heredoc = false;
    let mut heredocs: std::collections::VecDeque<Heredoc> = std::collections::VecDeque::new();

    for (line_no, raw) in contents.lines().enumerate() {
        if !continued {
            if let Some(open) = heredocs.front() {
                if open.ends_at(raw) {
                    heredocs.pop_front();
                }
                continue;
            }
        }
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            // `# escape=` is a parser directive only before the first
            // instruction. A comment does not end a continued instruction.
            if !saw_instruction {
                if let Some(c) = escape_directive(comment) {
                    escape = c;
                }
            }
            continue;
        }
        saw_instruction = true;
        let is_continuation = continued;
        continued = line.ends_with(escape);
        if is_continuation {
            if takes_heredoc {
                heredocs.extend(line.split_whitespace().filter_map(Heredoc::parse));
            }
            continue;
        }

        let mut tokens = line.split_whitespace();
        let Some(instr) = tokens.next() else { continue };
        let instr = instr.to_ascii_uppercase();
        takes_heredoc = matches!(instr.as_str(), "RUN" | "COPY" | "ADD");
        if takes_heredoc {
            heredocs.extend(tokens.clone().filter_map(Heredoc::parse));
        }

        if instr == "ARG" {
            // ARG NAME=default — the in-file default a ${NAME} FROM resolves
            // through.
            if let Some((name, default)) = tokens.next().and_then(|a| a.split_once('=')) {
                arg_defaults.insert(name.to_string(), default.trim_matches('"').to_string());
            }
            continue;
        }
        if instr == "ENV" {
            // ENV NAME=value ... or the legacy ENV NAME value.
            let pairs: Vec<&str> = tokens.collect();
            match pairs.first() {
                Some(first) if !first.contains('=') => {
                    env_names.insert(first.to_string());
                }
                _ => env_names.extend(
                    pairs
                        .iter()
                        .filter_map(|t| t.split_once('='))
                        .map(|(name, _)| name.to_string()),
                ),
            }
            continue;
        }
        if instr == "USER" {
            // A USER before the first FROM is not valid and belongs to no stage.
            if let Some(stage) = stage_users.last_mut() {
                *stage = authored_user(
                    cx,
                    tokens.next(),
                    &arg_defaults,
                    &env_names,
                    (line_no + 1) as u32,
                );
            }
            continue;
        }
        if instr != "FROM" {
            continue;
        }

        // FROM [--platform=...] <image> [AS <name>]
        let mut rest: Vec<&str> = tokens.collect();
        rest.retain(|t| !t.starts_with("--"));
        let Some(image) = rest.first().copied() else {
            continue;
        };
        // An alias from a PRIOR line makes this FROM an internal stage
        // reference, not a base image.
        let parent = stage_of_alias.get(&image.to_ascii_lowercase()).copied();
        let stage_idx = stage_users.len();
        if let Some(pos) = rest.iter().position(|t| t.eq_ignore_ascii_case("as")) {
            if let Some(alias) = rest.get(pos + 1) {
                stage_of_alias.insert(alias.to_ascii_lowercase(), stage_idx);
            }
        }
        let unit = format!("stage:{stage_idx}");

        // The stage starts with the user of what it is built FROM: the user
        // of an earlier stage, or the base image's own, which this file does
        // not state.
        let from = ProvenanceStep::new(cx.rel_path, &format!("FROM {image}"), "reference");
        stage_users.push(match parent {
            Some(parent) => {
                let mut user = stage_users[parent].clone();
                if let Some(decider) = user.provenance.last_mut() {
                    if decider.role == "explicit" {
                        decider.role = "inherited".to_string();
                    }
                }
                user.provenance.insert(0, from);
                user
            }
            None => StageUser {
                class: Some(crate::ABSENT_RENDERING),
                line: (line_no + 1) as u32,
                provenance: vec![from, ProvenanceStep::new(cx.rel_path, "USER", "absent")],
            },
        });

        if parent.is_some() || image.eq_ignore_ascii_case("scratch") {
            continue; // internal stage ref, or the reserved empty base
        }

        // ${VAR} / ${VAR:-fallback} substitution through in-file ARG defaults.
        let mut provenance = Vec::new();
        let resolved = if image.contains('$') {
            match resolve_arg(image, &arg_defaults) {
                Some((name, value)) => {
                    provenance.push(ProvenanceStep::new(
                        cx.rel_path,
                        &format!("ARG {name}={value}"),
                        "arg-default",
                    ));
                    value
                }
                None => {
                    provenance.push(ProvenanceStep::new(
                        cx.rel_path,
                        &format!("FROM {image}"),
                        "explicit",
                    ));
                    provenance.push(ProvenanceStep::new("", "build argument", "build-arg"));
                    let mut p = cx.packet(
                        &unit,
                        "dockerfile.base_image_pin",
                        None,
                        Resolution::Unresolvable,
                        provenance,
                    );
                    p.line = (line_no + 1) as u32;
                    out.packets.push(p);
                    continue;
                }
            }
        } else {
            image.to_string()
        };

        provenance.push(ProvenanceStep::new(
            cx.rel_path,
            &format!("FROM {resolved}"),
            "explicit",
        ));
        let shape = base_image_pin(&resolved);
        let mut p = cx.packet(
            &unit,
            "dockerfile.base_image_pin",
            Some(shape.to_string()),
            Resolution::AsAuthored,
            provenance,
        );
        p.line = (line_no + 1) as u32;
        out.packets.push(p);
    }

    // The image a Dockerfile builds is its last stage, so that stage's user
    // is the user the container starts as.
    match stage_users.pop() {
        Some(user) => {
            let resolution = match user.class {
                Some(_) => Resolution::AsAuthored,
                None => Resolution::Unresolvable,
            };
            let mut p = cx.packet(
                &format!("stage:{}", stage_users.len()),
                "dockerfile.final_stage_user",
                user.class.map(str::to_string),
                resolution,
                user.provenance,
            );
            p.line = user.line;
            out.packets.push(p);
        }
        // Matched the Dockerfile path shape but has no FROM: not a build
        // definition this lane recognizes.
        None => out.unparseable = 1,
    }
    out
}

/// The user a `USER <user>[:<group>]` instruction sets. A `$NAME` user
/// resolves through the in-file ARG defaults, as a FROM image does; a value
/// that only the build invocation or an ENV can give is not guessed.
fn authored_user(
    cx: &Cx,
    arg: Option<&str>,
    arg_defaults: &std::collections::HashMap<String, String>,
    env_names: &std::collections::HashSet<String>,
    line: u32,
) -> StageUser {
    let authored = ProvenanceStep::new(
        cx.rel_path,
        &format!("USER {}", arg.unwrap_or_default()),
        "explicit",
    );
    let unresolved = |source: &str, role: &str| StageUser {
        class: None,
        line,
        provenance: vec![authored.clone(), ProvenanceStep::new("", source, role)],
    };
    let name = user_name(arg.unwrap_or_default());
    if name.is_empty() {
        return StageUser {
            class: None,
            line,
            provenance: vec![authored],
        };
    }
    let mut provenance = Vec::new();
    let name = if name.contains('$') {
        match resolve_arg(name, arg_defaults) {
            Some((var, _)) if env_names.contains(&var) => {
                return unresolved("environment variable", "non-literal");
            }
            Some((var, value)) => {
                provenance.push(ProvenanceStep::new(
                    cx.rel_path,
                    &format!("ARG {var}={value}"),
                    "arg-default",
                ));
                value
            }
            None => return unresolved("build argument", "build-arg"),
        }
    } else {
        name.to_string()
    };
    provenance.push(authored);
    // Root is UID 0 by number or by its Linux name. The Windows counterpart
    // is the ContainerAdministrator account.
    let is_root =
        name == "root" || name == "ContainerAdministrator" || name.parse::<u64>() == Ok(0);
    StageUser {
        class: Some(if is_root { USER_ROOT } else { USER_NON_ROOT }),
        line,
        provenance,
    }
}

/// The user part of a `USER` argument: quotes off, and the `:<group>` off.
/// A `:` inside `${NAME:-fallback}` is not the group separator.
fn user_name(arg: &str) -> &str {
    let arg = arg.trim_matches(['"', '\'']);
    let mut depth = 0usize;
    for (i, c) in arg.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            ':' if depth == 0 => return &arg[..i],
            _ => {}
        }
    }
    arg
}

/// The character a `# escape=<c>` parser directive sets, given the comment
/// text after the `#`.
fn escape_directive(comment: &str) -> Option<char> {
    let (name, value) = comment.split_once('=')?;
    if !name.trim().eq_ignore_ascii_case("escape") {
        return None;
    }
    match value.trim() {
        "\\" => Some('\\'),
        "`" => Some('`'),
        _ => None,
    }
}

/// An open heredoc of a RUN, COPY or ADD: its body runs up to the line that
/// is the delimiter, and no line of the body is an instruction.
struct Heredoc {
    delimiter: String,
    /// `<<-`: leading tabs do not count.
    strip_tabs: bool,
}

impl Heredoc {
    /// A whole word of the form `[fd]<<[-]DELIM`, with DELIM optionally
    /// quoted. A shell `<<` shift and a `<<<` here-string are not that word.
    fn parse(word: &str) -> Option<Self> {
        let rest = word
            .trim_start_matches(|c: char| c.is_ascii_digit())
            .strip_prefix("<<")?;
        let (strip_tabs, rest) = match rest.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, rest),
        };
        let delimiter = ['"', '\'']
            .into_iter()
            .find_map(|q| rest.strip_prefix(q)?.strip_suffix(q))
            .unwrap_or(rest);
        let mut chars = delimiter.chars();
        let first = chars.next()?;
        ((first.is_ascii_alphabetic() || first == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_'))
        .then(|| Self {
            delimiter: delimiter.to_string(),
            strip_tabs,
        })
    }

    fn ends_at(&self, raw: &str) -> bool {
        let line = raw.trim_end_matches('\r');
        let line = if self.strip_tabs {
            line.trim_start_matches('\t')
        } else {
            line
        };
        line == self.delimiter
    }
}

/// Substitute a `${NAME}` / `${NAME:-fallback}` / `$NAME` image token through
/// the in-file ARG defaults. Returns `(name, resolved)` or `None` when the
/// value can only come from the build invocation.
fn resolve_arg(
    image: &str,
    defaults: &std::collections::HashMap<String, String>,
) -> Option<(String, String)> {
    let body = image
        .strip_prefix("${")
        .and_then(|s| s.strip_suffix('}'))
        .or_else(|| image.strip_prefix('$'))?;
    let (name, fallback) = match body.split_once(":-") {
        Some((n, f)) => (n, Some(f)),
        None => (body, None),
    };
    match defaults.get(name) {
        Some(v) if !v.is_empty() => Some((name.to_string(), v.clone())),
        _ => fallback.map(|f| (name.to_string(), f.to_string())),
    }
}

/// The pinning trichotomy of a base-image reference: `digest` (immutable),
/// `tag` (named, mutable), `latest` (explicitly or implicitly floating).
fn base_image_pin(image: &str) -> &'static str {
    if image.contains("@sha256:") {
        return "digest";
    }
    // A ':' in the last path segment is a tag (earlier ones are a registry
    // port, e.g. registry:5000/app).
    let last = image.rsplit('/').next().unwrap_or(image);
    match last.split_once(':') {
        Some((_, "latest")) | None => "latest",
        Some((_, _)) => "tag",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retrieve(path: &str, contents: &str) -> Retrieved {
        DepManifests.retrieve(path, contents, "snap")
    }

    fn find<'a>(got: &'a Retrieved, unit: &str, key: &str) -> &'a ConfigPacket {
        got.packets
            .iter()
            .find(|p| p.unit == unit && p.key == key)
            .unwrap_or_else(|| panic!("no packet {unit}:{key} in {:?}", got.packets))
    }

    #[test]
    fn matches_manifest_basenames_at_any_depth() {
        let r = DepManifests;
        for p in [
            "package.json",
            "web/package.json",
            "go.mod",
            "svc/api/go.mod",
            "Cargo.toml",
            "crates/x/Cargo.toml",
            "pyproject.toml",
            "requirements.txt",
            "requirements-dev.txt",
            "Dockerfile",
            "Dockerfile.backend",
            "build/app.dockerfile",
            "Containerfile",
        ] {
            assert!(r.matches(p), "should match {p}");
        }
        for p in [
            "package-lock.json",
            "notes.txt",
            "go.sum",
            "Cargo.lock",
            "src/main.rs",
            ".github/workflows/ci.yml",
        ] {
            assert!(!r.matches(p), "should not match {p}");
        }
    }

    #[test]
    fn all_packets_ride_the_dep_manifests_format() {
        let got = retrieve("package.json", r#"{"name":"x"}"#);
        assert!(!got.packets.is_empty());
        assert!(got.packets.iter().all(|p| p.format == "dep-manifests"));
    }

    // --- package.json ---

    #[test]
    fn engines_node_explicit_resolves_as_authored() {
        let got = retrieve("package.json", r#"{"engines":{"node":">=20"}}"#);
        let p = find(&got, "manifest", "package_json.engines.node");
        assert_eq!(p.resolved_value.as_deref(), Some(">=20"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance[0].key_path, "engines.node");
        assert_eq!(p.provenance[0].role, "explicit");
    }

    #[test]
    fn absent_engines_resolves_unconstrained_platform_default() {
        let got = retrieve("package.json", r#"{"name":"x"}"#);
        let p = find(&got, "manifest", "package_json.engines.node");
        assert_eq!(p.resolved_value.as_deref(), Some("unconstrained"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
        assert_eq!(p.provenance.len(), 2);
        assert_eq!(p.provenance[0].role, "absent");
        assert_eq!(p.provenance[1].role, "platform-default");
    }

    #[test]
    fn package_manager_pin_is_a_shape_never_the_version() {
        let exact = retrieve("package.json", r#"{"packageManager":"pnpm@9.1.0"}"#);
        let p = find(&exact, "manifest", "package_json.package_manager.pin");
        assert_eq!(p.resolved_value.as_deref(), Some("exact"));
        assert!(
            p.provenance[0].key_path.contains("pnpm"),
            "manager identity rides provenance: {:?}",
            p.provenance
        );
        assert!(
            !p.provenance[0].key_path.contains("9.1.0"),
            "version content is dropped: {:?}",
            p.provenance
        );

        let digest = retrieve(
            "package.json",
            r#"{"packageManager":"yarn@4.2.2+sha256.abcdef"}"#,
        );
        assert_eq!(
            find(&digest, "manifest", "package_json.package_manager.pin")
                .resolved_value
                .as_deref(),
            Some("digest")
        );

        let absent = retrieve("package.json", r#"{"name":"x"}"#);
        let p = find(&absent, "manifest", "package_json.package_manager.pin");
        assert_eq!(p.resolved_value.as_deref(), Some("unconstrained"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn overrides_count_sums_all_three_spellings_without_names() {
        let got = retrieve(
            "package.json",
            r#"{"overrides":{"a":"1","b":"2"},"resolutions":{"c":"3"},"pnpm":{"overrides":{"d":"4"}}}"#,
        );
        let p = find(&got, "manifest", "package_json.overrides.count");
        assert_eq!(p.resolved_value.as_deref(), Some("4"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance[0].role, "explicit");

        let none = retrieve("package.json", r#"{"name":"x"}"#);
        let p = find(&none, "manifest", "package_json.overrides.count");
        assert_eq!(p.resolved_value.as_deref(), Some("0"));
        assert_eq!(p.provenance[0].role, "absent");
    }

    #[test]
    fn malformed_package_json_degrades_to_unparseable() {
        let got = retrieve("package.json", "{not json");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    // --- go.mod ---

    #[test]
    fn go_and_toolchain_directives_read_as_authored() {
        let got = retrieve(
            "go.mod",
            "module example.com/svc\n\ngo 1.22.3\n\ntoolchain go1.22.5\n",
        );
        let go = find(&got, "module", "go_mod.go");
        assert_eq!(go.resolved_value.as_deref(), Some("1.22.3"));
        assert_eq!(go.resolution, Resolution::AsAuthored);
        let tc = find(&got, "module", "go_mod.toolchain");
        assert_eq!(tc.resolved_value.as_deref(), Some("go1.22.5"));
        assert_eq!(tc.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn absent_go_and_toolchain_resolve_documented_defaults() {
        let got = retrieve("go.mod", "module example.com/svc\n");
        let go = find(&got, "module", "go_mod.go");
        assert_eq!(go.resolved_value.as_deref(), Some("1.16"));
        assert_eq!(go.resolution, Resolution::PlatformDefault);
        assert_eq!(go.provenance[1].role, "platform-default");
        let tc = find(&got, "module", "go_mod.toolchain");
        assert_eq!(tc.resolved_value.as_deref(), Some("local"));
        assert_eq!(tc.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn replace_count_counts_single_line_and_block_directives() {
        let got = retrieve(
            "go.mod",
            "module m\n\ngo 1.22\n\nreplace a.com/x => ../x\n\nreplace (\n\tb.com/y => b.com/y2 v1.0.0\n\tc.com/z v1.1.0 => ./z\n)\n",
        );
        let p = find(&got, "module", "go_mod.replace.count");
        assert_eq!(p.resolved_value.as_deref(), Some("3"));
        assert_eq!(p.provenance[0].role, "explicit");

        let none = retrieve("go.mod", "module m\n\ngo 1.22\n");
        let p = find(&none, "module", "go_mod.replace.count");
        assert_eq!(p.resolved_value.as_deref(), Some("0"));
        assert_eq!(p.provenance[0].role, "absent");
    }

    #[test]
    fn go_mod_without_module_line_is_unparseable() {
        let got = retrieve("go.mod", "// just a comment\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    // --- Cargo.toml ---

    #[test]
    fn cargo_edition_explicit_absent_and_virtual_manifest() {
        let explicit = retrieve(
            "Cargo.toml",
            "[package]\nname = \"x\"\nedition = \"2021\"\n",
        );
        let p = find(&explicit, "package", "cargo_toml.package.edition");
        assert_eq!(p.resolved_value.as_deref(), Some("2021"));
        assert_eq!(p.resolution, Resolution::AsAuthored);

        let absent = retrieve("Cargo.toml", "[package]\nname = \"x\"\n");
        let p = find(&absent, "package", "cargo_toml.package.edition");
        assert_eq!(p.resolved_value.as_deref(), Some("2015"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);

        // A virtual workspace manifest has no package: no edition packet.
        let virt = retrieve("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
        assert!(
            !virt
                .packets
                .iter()
                .any(|p| p.key == "cargo_toml.package.edition"),
            "virtual manifest emits no edition: {:?}",
            virt.packets
        );
    }

    #[test]
    fn workspace_inherited_edition_resolves_through_the_same_file() {
        let got = retrieve(
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/*\"]\n\n[workspace.package]\nedition = \"2021\"\n\n[package]\nname = \"root\"\nedition.workspace = true\n",
        );
        let p = find(&got, "package", "cargo_toml.package.edition");
        assert_eq!(p.resolved_value.as_deref(), Some("2021"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance.len(), 2);
        assert_eq!(p.provenance[1].key_path, "workspace.package.edition");
        assert_eq!(p.provenance[1].role, "inherited");
    }

    #[test]
    fn member_manifest_workspace_edition_is_unresolvable_here() {
        // The value lives in ANOTHER file (the workspace root); the
        // single-file contract abstains rather than guessing.
        let got = retrieve(
            "crates/x/Cargo.toml",
            "[package]\nname = \"x\"\nedition.workspace = true\n",
        );
        let p = find(&got, "package", "cargo_toml.package.edition");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance.last().unwrap().role, "workspace-setting");
    }

    #[test]
    fn workspace_deps_loosest_pin_aggregates_shape_only() {
        let got = retrieve(
            "Cargo.toml",
            "[workspace]\nmembers = []\n\n[workspace.dependencies]\nserde = \"1.0\"\nexactly = \"=1.2.3\"\nanything = \"*\"\ngitdep = { git = \"https://x/y\", rev = \"abc\" }\n",
        );
        let p = find(
            &got,
            "workspace",
            "cargo_toml.workspace_dependencies.loosest_pin",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("floating"));
        assert!(
            p.provenance[0].key_path.contains("4 entries"),
            "count, never names: {:?}",
            p.provenance
        );
        assert!(
            !format!("{:?}", p).contains("serde"),
            "no crate names anywhere in the packet: {p:?}"
        );

        let tight = retrieve(
            "Cargo.toml",
            "[workspace]\n\n[workspace.dependencies]\na = \"=1.2.3\"\n",
        );
        assert_eq!(
            find(
                &tight,
                "workspace",
                "cargo_toml.workspace_dependencies.loosest_pin"
            )
            .resolved_value
            .as_deref(),
            Some("exact")
        );

        // No workspace deps section: no packet.
        let none = retrieve(
            "Cargo.toml",
            "[package]\nname = \"x\"\nedition = \"2021\"\n",
        );
        assert!(
            !none
                .packets
                .iter()
                .any(|p| p.key == "cargo_toml.workspace_dependencies.loosest_pin"),
            "{:?}",
            none.packets
        );
    }

    #[test]
    fn malformed_cargo_toml_degrades_to_unparseable() {
        let got = retrieve("Cargo.toml", "[package\nname=");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    /// Keys this parser does not read, in every TOML value type. A manifest
    /// is mostly such keys, and the parse is of the whole document: one the
    /// `toml` crate refuses costs every packet of the file (po-av01j.234).
    const UNKNOWN_KEYS: &str = "\
released = 2026-10-08T12:00:00Z\n\
ratio = 1.5\n\
flags = [true, false]\n\
nested.dotted.key = \"v\"\n\
inline = { a = 1, b = [\"x\"], c = { d = 07:30:00 } }\n\
\n\
[[unknown.array_of_tables]]\n\
n = 1\n\
\n\
[[unknown.array_of_tables]]\n\
n = 2\n";

    #[test]
    fn cargo_toml_reads_known_keys_among_unknown_ones() {
        let got = retrieve(
            "Cargo.toml",
            &format!(
                "[package]\nname = \"x\"\nedition = \"2021\"\nfuture-key = 1979-05-27\n\n\
                 [package.metadata.anything]\n{UNKNOWN_KEYS}\n\
                 [workspace.dependencies]\nserde = \"1\"\nodd = {{ version = \"=1.0.0\", future = 1.0 }}\n\n\
                 [future-table]\n{UNKNOWN_KEYS}"
            ),
        );
        assert_eq!(got.unparseable, 0, "unknown keys are not a parse failure");
        let p = find(&got, "package", "cargo_toml.package.edition");
        assert_eq!(p.resolved_value.as_deref(), Some("2021"));
        let p = find(
            &got,
            "workspace",
            "cargo_toml.workspace_dependencies.loosest_pin",
        );
        assert_eq!(p.resolved_value.as_deref(), Some(SHAPE_RANGE));
    }

    #[test]
    fn pyproject_reads_known_keys_among_unknown_ones() {
        let got = retrieve(
            "pyproject.toml",
            &format!(
                "[project]\nname = \"x\"\nrequires-python = \">=3.11\"\n\
                 dependencies = [\"requests==2.31.0\"]\n\n\
                 [tool.future]\n{UNKNOWN_KEYS}"
            ),
        );
        assert_eq!(got.unparseable, 0, "unknown keys are not a parse failure");
        let p = find(&got, "project", "pyproject.requires_python");
        assert_eq!(p.resolved_value.as_deref(), Some(">=3.11"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
    }

    #[test]
    fn malformed_pyproject_degrades_to_unparseable() {
        let got = retrieve("pyproject.toml", "[project\nname=");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    // --- pyproject.toml ---

    #[test]
    fn requires_python_pep621_poetry_fallback_and_absence() {
        let pep = retrieve(
            "pyproject.toml",
            "[project]\nname = \"x\"\nrequires-python = \">=3.11\"\n",
        );
        let p = find(&pep, "project", "pyproject.requires_python");
        assert_eq!(p.resolved_value.as_deref(), Some(">=3.11"));
        assert_eq!(p.resolution, Resolution::AsAuthored);

        let poetry = retrieve(
            "pyproject.toml",
            "[tool.poetry]\nname = \"x\"\n\n[tool.poetry.dependencies]\npython = \"^3.11\"\n",
        );
        let p = find(&poetry, "project", "pyproject.requires_python");
        assert_eq!(p.resolved_value.as_deref(), Some("^3.11"));
        assert_eq!(p.provenance.len(), 2, "the fallthrough is chained: {p:?}");
        assert_eq!(p.provenance[1].key_path, "tool.poetry.dependencies.python");

        let absent = retrieve("pyproject.toml", "[project]\nname = \"x\"\n");
        let p = find(&absent, "project", "pyproject.requires_python");
        assert_eq!(p.resolved_value.as_deref(), Some("unconstrained"));
        assert_eq!(p.resolution, Resolution::PlatformDefault);
    }

    #[test]
    fn pyproject_dependencies_loosest_pin() {
        let got = retrieve(
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = [\"requests==2.31.0\", \"flask>=2\", \"numpy\"]\n",
        );
        let p = find(&got, "project", "pyproject.dependencies.loosest_pin");
        assert_eq!(p.resolved_value.as_deref(), Some("floating"));
        assert!(p.provenance[0].key_path.contains("3 entries"));

        let pinned = retrieve(
            "pyproject.toml",
            "[project]\nname = \"x\"\ndependencies = [\"requests==2.31.0\"]\n",
        );
        assert_eq!(
            find(&pinned, "project", "pyproject.dependencies.loosest_pin")
                .resolved_value
                .as_deref(),
            Some("exact")
        );

        let empty = retrieve("pyproject.toml", "[project]\nname = \"x\"\n");
        assert!(
            !empty
                .packets
                .iter()
                .any(|p| p.key == "pyproject.dependencies.loosest_pin"),
            "{:?}",
            empty.packets
        );
    }

    // --- requirements*.txt ---

    #[test]
    fn requirements_pin_shapes_and_loosest() {
        let got = retrieve(
            "requirements.txt",
            "# deps\nrequests==2.31.0\nflask>=2.0  # web\nnumpy\n-r other.txt\n",
        );
        let p = find(&got, "manifest", "requirements_txt.loosest_pin");
        assert_eq!(p.resolved_value.as_deref(), Some("floating"));
        assert!(
            p.provenance[0].key_path.contains("3 requirements"),
            "option lines and comments do not count: {:?}",
            p.provenance
        );

        let hashed = retrieve(
            "requirements.txt",
            "requests==2.31.0 \\\n    --hash=sha256:abc123\n",
        );
        assert_eq!(
            find(&hashed, "manifest", "requirements_txt.loosest_pin")
                .resolved_value
                .as_deref(),
            Some("digest"),
            "hash-checking mode is the tightest shape"
        );

        let ranged = retrieve("requirements-dev.txt", "pytest>=8,<9\n");
        assert_eq!(
            find(&ranged, "manifest", "requirements_txt.loosest_pin")
                .resolved_value
                .as_deref(),
            Some("range")
        );
    }

    #[test]
    fn empty_or_comment_only_requirements_emit_nothing() {
        let got = retrieve("requirements.txt", "# nothing here\n\n-r base.txt\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 0, "an include-only file is not malformed");
    }

    // --- Dockerfile ---

    #[test]
    fn base_image_pin_shapes_digest_tag_latest() {
        let got = retrieve(
            "Dockerfile",
            "FROM golang:1.22 AS build\nRUN make\nFROM alpine@sha256:0123abcd\nCOPY --from=build /app /app\n",
        );
        let build = find(&got, "stage:0", "dockerfile.base_image_pin");
        assert_eq!(build.resolved_value.as_deref(), Some("tag"));
        assert!(build.provenance[0].key_path.contains("golang:1.22"));
        let run = find(&got, "stage:1", "dockerfile.base_image_pin");
        assert_eq!(run.resolved_value.as_deref(), Some("digest"));

        let latest = retrieve("Dockerfile", "FROM alpine:latest\n");
        assert_eq!(
            find(&latest, "stage:0", "dockerfile.base_image_pin")
                .resolved_value
                .as_deref(),
            Some("latest")
        );
        let bare = retrieve("Dockerfile", "FROM alpine\n");
        assert_eq!(
            find(&bare, "stage:0", "dockerfile.base_image_pin")
                .resolved_value
                .as_deref(),
            Some("latest"),
            "no tag is implicitly :latest"
        );
        // A registry port's ':' is not a tag.
        let port = retrieve("Dockerfile", "FROM registry.local:5000/app\n");
        assert_eq!(
            find(&port, "stage:0", "dockerfile.base_image_pin")
                .resolved_value
                .as_deref(),
            Some("latest")
        );
    }

    #[test]
    fn stage_alias_and_scratch_froms_emit_no_packet() {
        let got = retrieve(
            "Dockerfile",
            "FROM golang:1.22 AS builder\nFROM builder AS test\nFROM scratch\n",
        );
        let pins: Vec<&ConfigPacket> = got
            .packets
            .iter()
            .filter(|p| p.key == "dockerfile.base_image_pin")
            .collect();
        assert_eq!(pins.len(), 1, "only the real base emits: {:?}", got.packets);
        assert_eq!(pins[0].unit, "stage:0");
    }

    #[test]
    fn arg_default_resolves_and_bare_build_arg_is_unresolvable() {
        let got = retrieve("Dockerfile", "ARG BASE=alpine:3.20\nFROM ${BASE}\n");
        let p = find(&got, "stage:0", "dockerfile.base_image_pin");
        assert_eq!(p.resolved_value.as_deref(), Some("tag"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance[0].role, "arg-default");

        let unresolved = retrieve("Dockerfile", "ARG BASE\nFROM ${BASE}\n");
        let p = find(&unresolved, "stage:0", "dockerfile.base_image_pin");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
        assert_eq!(p.provenance.last().unwrap().role, "build-arg");
    }

    #[test]
    fn dockerfile_from_lines_carry_line_numbers() {
        let got = retrieve("Dockerfile", "# header\nFROM alpine:3.20\n");
        assert_eq!(got.packets[0].line, 2);
    }

    #[test]
    fn dockerfile_without_from_is_unparseable() {
        let got = retrieve("Dockerfile", "# empty scaffold\nRUN echo hi\n");
        assert!(got.packets.is_empty());
        assert_eq!(got.unparseable, 1);
    }

    // --- Dockerfile final-stage USER ---

    const USER_KEY: &str = "dockerfile.final_stage_user";

    /// The one final-stage user packet of a Dockerfile.
    fn final_user(contents: &str) -> ConfigPacket {
        let got = retrieve("Dockerfile", contents);
        let mut users = got.packets.iter().filter(|p| p.key == USER_KEY);
        let p = users
            .next()
            .unwrap_or_else(|| panic!("no {USER_KEY} packet in {:?}", got.packets));
        assert!(users.next().is_none(), "one user fact per Dockerfile");
        p.clone()
    }

    #[test]
    fn final_stage_user_is_root_non_root_or_absent() {
        for (user, want) in [
            ("root", "root"),
            ("0", "root"),
            ("root:root", "root"),
            ("0:0", "root"),
            ("0:1000", "root"),
            ("ROOT", "non-root"), // user names are case-sensitive on Linux
            ("ContainerAdministrator", "root"),
            ("app", "non-root"),
            ("1000", "non-root"),
            ("65532:65532", "non-root"),
            ("nobody:0", "non-root"),
            ("\"app\"", "non-root"),
            ("ContainerUser", "non-root"),
        ] {
            let p = final_user(&format!("FROM alpine:3.20\nUSER {user}\n"));
            assert_eq!(p.resolved_value.as_deref(), Some(want), "USER {user}");
            assert_eq!(p.resolution, Resolution::AsAuthored);
            assert_eq!(p.unit, "stage:0");
            assert_eq!(p.line, 2, "the packet points at the USER line");
        }

        let absent = final_user("# build\nFROM alpine:3.20\nRUN true\n");
        assert_eq!(absent.resolved_value.as_deref(), Some("absent"));
        assert_eq!(absent.resolution, Resolution::AsAuthored);
        assert_eq!(absent.line, 2, "an absent USER points at the stage's FROM");
        assert_eq!(absent.provenance.last().unwrap().role, "absent");
        assert!(
            absent
                .provenance
                .iter()
                .any(|s| s.key_path.contains("alpine:3.20")),
            "the base image that decides the user is in the chain: {:?}",
            absent.provenance
        );
    }

    #[test]
    fn the_last_user_of_the_final_stage_wins() {
        // Drop to root to install, then back to an unprivileged user.
        let p = final_user("FROM alpine:3.20\nUSER app\nUSER root\nRUN apk add curl\nUSER app\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.line, 5);

        let p = final_user("FROM alpine:3.20\nUSER app\nuser root\n");
        assert_eq!(
            p.resolved_value.as_deref(),
            Some("root"),
            "instructions are case-insensitive, and the last one decides"
        );
    }

    #[test]
    fn a_user_in_an_earlier_stage_does_not_reach_the_final_stage() {
        let p = final_user(
            "FROM golang:1.22 AS build\nUSER builder\nRUN make\nFROM alpine:3.20\nCOPY --from=build /app /app\n",
        );
        assert_eq!(p.unit, "stage:1");
        assert_eq!(p.resolved_value.as_deref(), Some("absent"));
        assert_eq!(p.line, 4);
    }

    #[test]
    fn a_final_stage_built_from_an_earlier_stage_inherits_its_user() {
        let p = final_user(
            "FROM alpine:3.20 AS base\nUSER app\nFROM golang:1.22 AS build\nUSER root\nFROM base\nCOPY --from=build /app /app\n",
        );
        assert_eq!(p.unit, "stage:2");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.line, 2, "the packet points at the USER that decides");
        assert_eq!(p.provenance.last().unwrap().role, "inherited");

        // The final stage's own USER overrides the inherited one.
        let p = final_user("FROM alpine:3.20 AS base\nUSER app\nFROM base\nUSER root\n");
        assert_eq!(p.resolved_value.as_deref(), Some("root"));
        assert_eq!(p.line, 4);

        // Inherited absence names the external base at the root of the chain.
        let p = final_user("FROM alpine:3.20 AS base\nRUN true\nFROM base AS mid\nFROM mid\n");
        assert_eq!(p.unit, "stage:2");
        assert_eq!(p.resolved_value.as_deref(), Some("absent"));
        assert!(p
            .provenance
            .iter()
            .any(|s| s.key_path.contains("alpine:3.20")));
    }

    #[test]
    fn a_scratch_final_stage_still_reports_its_user() {
        let p =
            final_user("FROM golang:1.22 AS build\nFROM scratch\nCOPY --from=build /app /app\n");
        assert_eq!(p.unit, "stage:1");
        assert_eq!(p.resolved_value.as_deref(), Some("absent"));

        let p = final_user("FROM scratch\nCOPY app /app\nUSER 65532:65532\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
    }

    #[test]
    fn a_user_from_an_arg_default_resolves_and_a_bare_build_arg_abstains() {
        let p = final_user("FROM alpine:3.20\nARG UID=1000\nARG GID=1000\nUSER ${UID}:${GID}\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.resolution, Resolution::AsAuthored);
        assert_eq!(p.provenance[0].role, "arg-default");

        let p = final_user("FROM alpine:3.20\nARG UID=0\nUSER $UID\n");
        assert_eq!(p.resolved_value.as_deref(), Some("root"));

        // Only the build invocation knows: abstain, never guess.
        for user in ["$UID", "${APP_USER}", "app${SUFFIX}"] {
            let p = final_user(&format!("FROM alpine:3.20\nARG UID\nUSER {user}\n"));
            assert_eq!(p.resolution, Resolution::Unresolvable, "USER {user}");
            assert_eq!(p.resolved_value, None, "USER {user}");
            assert_eq!(p.provenance.last().unwrap().role, "build-arg");
            assert_eq!(p.line, 3);
        }

        // ENV wins over an ARG default of the same name, and its value is
        // not tracked: abstain.
        for env in ["ENV UID=1000", "ENV UID 1000", "ENV A=b UID=1000"] {
            let p = final_user(&format!("FROM alpine:3.20\nARG UID=0\n{env}\nUSER $UID\n"));
            assert_eq!(p.resolution, Resolution::Unresolvable, "{env}");
            assert_eq!(p.resolved_value, None, "{env}");
        }

        // A later unresolvable USER is not hidden by an earlier literal one.
        let p = final_user("FROM alpine:3.20\nUSER app\nUSER $RUN_AS\n");
        assert_eq!(p.resolution, Resolution::Unresolvable);
    }

    #[test]
    fn user_text_that_is_not_an_instruction_is_not_read() {
        // A continuation line of a RUN.
        let p =
            final_user("FROM alpine:3.20\nUSER app\nRUN adduser \\\n  USER root \\\n  && true\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.line, 2);

        // A comment inside a continuation does not end it.
        let p = final_user("FROM alpine:3.20\nUSER app\nRUN true \\\n  # note\n  USER root\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));

        // A heredoc body.
        let p = final_user(
            "FROM alpine:3.20\nUSER app\nRUN <<EOF\nUSER root\nEOF\nCOPY <<-\"CONF\" /etc/app.conf\nUSER root\n\tCONF\n",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.line, 2);

        // An instruction after the heredoc ends is read again.
        let p = final_user("FROM alpine:3.20\nRUN <<EOF\necho hi\nEOF\nUSER app\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.line, 5);

        // A shell `<<` that is not a heredoc does not swallow the file.
        let p = final_user("FROM alpine:3.20\nRUN echo $((1 << 2))\nUSER app\n");
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));

        // With the backtick escape directive, a trailing backslash is a path.
        let p = final_user(
            "# escape=`\nFROM mcr.microsoft.com/windows/nanoserver:ltsc2022\nWORKDIR C:\\app\\\nUSER ContainerUser\n",
        );
        assert_eq!(p.resolved_value.as_deref(), Some("non-root"));
        assert_eq!(p.line, 4);
    }

    #[test]
    fn a_from_on_a_continuation_line_is_not_a_stage() {
        let got = retrieve(
            "Dockerfile",
            "FROM alpine:3.20\nRUN echo \\\n  from ubuntu:latest\nUSER app\n",
        );
        assert_eq!(got.packets.len(), 2, "{:?}", got.packets);
        assert_eq!(find(&got, "stage:0", USER_KEY).line, 4);
    }

    #[test]
    fn a_user_with_no_value_abstains() {
        let p = final_user("FROM alpine:3.20\nUSER\n");
        assert_eq!(p.resolution, Resolution::Unresolvable);
        assert_eq!(p.resolved_value, None);
    }
}
