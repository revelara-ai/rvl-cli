//! Dependency-manifest retriever: family (4) of the G6 config lane
//! (po-av01j.22). One retriever, several manifest dialects — package.json,
//! go.mod, Cargo.toml, pyproject.toml, requirements*.txt, Dockerfile — all
//! emitting packets under the single format id `dep-manifests`, with the
//! dialect embedded in the KEY (`package_json.engines.node`,
//! `go_mod.toolchain`, `dockerfile.base_image_pin`) so one spec judges one
//! key identity everywhere.
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
            key: key.to_string(),
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
    let Ok(doc) = contents.parse::<toml::Value>() else {
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
    let Ok(doc) = contents.parse::<toml::Value>() else {
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

fn dockerfile(cx: &Cx, contents: &str) -> Retrieved {
    let mut out = Retrieved::default();
    let mut arg_defaults: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut stage_aliases: Vec<String> = Vec::new();
    let mut stage_idx = 0usize;
    let mut saw_from = false;

    for (line_no, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let Some(instr) = tokens.next() else { continue };
        let instr = instr.to_ascii_uppercase();

        if instr == "ARG" {
            // ARG NAME=default — the in-file default a ${NAME} FROM resolves
            // through.
            if let Some((name, default)) = tokens.next().and_then(|a| a.split_once('=')) {
                arg_defaults.insert(name.to_string(), default.trim_matches('"').to_string());
            }
            continue;
        }
        if instr != "FROM" {
            continue;
        }
        saw_from = true;

        // FROM [--platform=...] <image> [AS <name>]
        let mut rest: Vec<&str> = tokens.collect();
        rest.retain(|t| !t.starts_with("--"));
        let Some(image) = rest.first().copied() else {
            continue;
        };
        // An alias from a PRIOR line makes this FROM an internal stage
        // reference, not a base image.
        let is_internal = stage_aliases.contains(&image.to_ascii_lowercase());
        if let Some(pos) = rest.iter().position(|t| t.eq_ignore_ascii_case("as")) {
            if let Some(alias) = rest.get(pos + 1) {
                stage_aliases.push(alias.to_ascii_lowercase());
            }
        }
        let unit = format!("stage:{stage_idx}");
        stage_idx += 1;

        if is_internal || image.eq_ignore_ascii_case("scratch") {
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

    if !saw_from {
        // Matched the Dockerfile path shape but has no FROM: not a build
        // definition this lane recognizes.
        out.unparseable = 1;
    }
    out
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
        assert_eq!(
            got.packets.len(),
            1,
            "only the real base emits: {:?}",
            got.packets
        );
        assert_eq!(got.packets[0].unit, "stage:0");
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
}
