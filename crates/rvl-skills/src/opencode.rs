//! OpenCode lens-agent registration. OpenCode's tier-3 download is a skills
//! directory, so the `/rvl:scan` lenses (Claude Code agent files, either
//! `agents/<id>.md` or, in the skills-plus-agent-fallback layout, the agent
//! skills `rvl-<id>/SKILL.md`) never became OpenCode agents and the scan
//! could not fan out. OpenCode reads agents from `~/.config/opencode/agents/<id>.md`
//! (OpenCode 1.18.33 or later is the supported floor), but its frontmatter
//! is not Claude Code's: `tools:` is a map there, not a comma list, and
//! `model:` must name a provider. A lens copied verbatim would fail
//! OpenCode's config parse, so each one is rewritten as a subagent that
//! keeps the lens's description, body and tool limits.

/// Rewrite one Claude Code lens agent as an OpenCode subagent. A file that
/// already declares an OpenCode `mode:` is OpenCode-native and passes
/// through unchanged.
pub fn subagent(id: &str, source: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(source);
    let (frontmatter, body) = split_frontmatter(&text);
    if frontmatter.lines().any(|l| l.starts_with("mode:")) {
        return source.to_vec();
    }
    let mut description = crate::agents::frontmatter_description(&text);
    if description.is_empty() {
        description = format!("Revelara reliability lens {id}");
    }
    let mut out = String::from("---\n");
    // A JSON string is a valid YAML double-quoted scalar: no escaping rules
    // of our own for colons or quotes in the description.
    out.push_str(&format!(
        "description: {}\nmode: subagent\n",
        serde_json::Value::String(description)
    ));
    if let Some(tools) = tools(frontmatter) {
        let has = |names: &[&str]| tools.iter().any(|t| names.contains(&t.as_str()));
        let denied: Vec<&str> = [
            ("edit", has(&["Edit", "Write", "MultiEdit", "NotebookEdit"])),
            ("bash", has(&["Bash"])),
            ("webfetch", has(&["WebFetch", "WebSearch"])),
        ]
        .into_iter()
        .filter(|(_, granted)| !granted)
        .map(|(perm, _)| perm)
        .collect();
        if !denied.is_empty() {
            out.push_str("permission:\n");
            for perm in denied {
                out.push_str(&format!("  {perm}: deny\n"));
            }
        }
    }
    out.push_str("---\n");
    out.push_str(body);
    out.into_bytes()
}

/// The frontmatter text (without its `---` fences) and the body after it.
/// No frontmatter means an empty one and the whole text as body.
fn split_frontmatter(text: &str) -> (&str, &str) {
    let Some(rest) = text.strip_prefix("---\n") else {
        return ("", text);
    };
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        if line.trim_end() == "---" {
            return (&rest[..offset], &rest[offset + line.len()..]);
        }
        offset += line.len();
    }
    ("", text)
}

/// The Claude Code `tools:` allow-list, in any of its spellings (comma
/// list, flow list, block list). None when the key is absent, which in
/// Claude Code means every tool, so nothing is denied.
fn tools(frontmatter: &str) -> Option<Vec<String>> {
    let mut lines = frontmatter.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(value) = line.strip_prefix("tools:") else {
            continue;
        };
        let mut names: Vec<String> = value
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(unquote)
            .filter(|t| !t.is_empty())
            .collect();
        while let Some(item) = lines.peek().and_then(|l| l.trim().strip_prefix("- ")) {
            names.push(unquote(item));
            lines.next();
        }
        return Some(names);
    }
    None
}

fn unquote(s: &str) -> String {
    s.trim().trim_matches(|c| c == '"' || c == '\'').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const RUST_LENS: &str = "---\nname: rvl-rust-pro\ndescription: \"Rust reliability: panics\"\n\
                             tools: Read, Grep, Glob\nmodel: sonnet\n---\nReview the Rust code.\n";
    const GO_LENS: &str = "---\nname: rvl-golang-pro\ndescription: Go reliability lens\n---\n\
                           Review the Go code.\n";

    /// `rvl plugin install opencode` into a temp home: every lens in the
    /// download is in OpenCode's agent list (its global agents directory,
    /// which `rvl plugin agents opencode` also reads), as a subagent the
    /// scan can dispatch to.
    #[test]
    fn opencode_registers_lens_agents() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let content: BTreeMap<String, Vec<u8>> = [
            ("rvl-scan/SKILL.md", "scan skill"),
            ("agents/rvl-rust-pro.md", RUST_LENS),
            ("agents/rvl-golang-pro.md", GO_LENS),
        ]
        .into_iter()
        .map(|(n, c)| (n.to_string(), c.as_bytes().to_vec()))
        .collect();

        let h = crate::harness::by_name("opencode").unwrap();
        let receipt = h.install(&home, &content, "1.0.0").unwrap();
        assert_eq!(receipt.files_written, 5, "3 download files + 2 agents");
        assert!(home
            .join(".config/opencode/skills/rvl-scan/SKILL.md")
            .exists());

        let store = crate::store::SkillsStore::open(&dir.path().join("cache")).unwrap();
        store
            .record_installed(
                "opencode",
                crate::store::InstalledInfo {
                    version: "1.0.0".into(),
                    location: receipt.location.display().to_string(),
                    installed_at: "2026-10-27".into(),
                },
            )
            .unwrap();
        let (agents_dir, _) =
            crate::agents::installed_agents_dir(&store, &home, "opencode").unwrap();
        assert_eq!(agents_dir, home.join(".config/opencode/agents"));
        let listed = crate::agents::list_agents(&agents_dir).unwrap();
        assert_eq!(
            listed.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["rvl-golang-pro", "rvl-rust-pro"]
        );
        assert_eq!(listed[1].description, "Rust reliability: panics");
        for agent in &listed {
            let file =
                std::fs::read_to_string(agents_dir.join(format!("{}.md", agent.id))).unwrap();
            assert!(file.contains("\nmode: subagent\n"), "{file}");
            assert!(
                !file.contains("model:"),
                "Claude model aliases are not OpenCode models"
            );
        }

        let removed = h.remove(&home, Some(&content)).unwrap();
        assert_eq!(removed.files_removed, Some(5));
        assert!(!agents_dir.join("rvl-rust-pro.md").exists());
    }

    /// The skills-plus-agent-fallback layout the server gives OpenCode has
    /// no `agents/` directory: skills are `<name>/SKILL.md` and each agent
    /// is the skill `rvl-<id>/SKILL.md`. Those agent skills are the lenses,
    /// so `rvl plugin agents opencode` lists each `rvl-<id>`.
    #[test]
    fn opencode_registers_the_lenses_of_a_fallback_layout_download() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let content: BTreeMap<String, Vec<u8>> = [
            ("scan/SKILL.md", "scan skill"),
            ("scan/reference.md", "scan reference"),
            ("rvl-rust-pro/SKILL.md", RUST_LENS),
            ("rvl-golang-pro/SKILL.md", GO_LENS),
        ]
        .into_iter()
        .map(|(n, c)| (n.to_string(), c.as_bytes().to_vec()))
        .collect();

        let h = crate::harness::by_name("opencode").unwrap();
        let receipt = h.install(&home, &content, "1.0.0").unwrap();
        assert_eq!(receipt.files_written, 6, "4 download files + 2 agents");
        let store = crate::store::SkillsStore::open(&dir.path().join("cache")).unwrap();
        store
            .record_installed(
                "opencode",
                crate::store::InstalledInfo {
                    version: "1.0.0".into(),
                    location: receipt.location.display().to_string(),
                    installed_at: "2026-10-28".into(),
                },
            )
            .unwrap();
        let (agents_dir, _) =
            crate::agents::installed_agents_dir(&store, &home, "opencode").unwrap();
        let listed = crate::agents::list_agents(&agents_dir).unwrap();
        assert_eq!(
            listed.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["rvl-golang-pro", "rvl-rust-pro"]
        );
        assert_eq!(listed[1].description, "Rust reliability: panics");
        let rust = std::fs::read_to_string(agents_dir.join("rvl-rust-pro.md")).unwrap();
        assert!(rust.contains("\nmode: subagent\n"), "{rust}");

        let removed = h.remove(&home, Some(&content)).unwrap();
        assert_eq!(removed.files_removed, Some(6));
        assert!(!agents_dir.join("rvl-rust-pro.md").exists());
    }

    /// A download that has `agents/<id>.md` takes its lenses from there
    /// only: an `rvl-` skill beside them is not also a lens.
    #[test]
    fn top_level_agents_win_over_rvl_skills() {
        let home = tempfile::tempdir().unwrap();
        let content: BTreeMap<String, Vec<u8>> = [
            ("rvl-scan/SKILL.md", "scan skill"),
            ("agents/rvl-rust-pro.md", RUST_LENS),
        ]
        .into_iter()
        .map(|(n, c)| (n.to_string(), c.as_bytes().to_vec()))
        .collect();
        let h = crate::harness::by_name("opencode").unwrap();
        h.install(home.path(), &content, "1.0.0").unwrap();
        let agents_dir = home.path().join(".config/opencode/agents");
        let listed = crate::agents::list_agents(&agents_dir).unwrap();
        assert_eq!(
            listed.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(),
            ["rvl-rust-pro"]
        );
    }

    #[test]
    fn a_tool_allow_list_becomes_deny_permissions() {
        let out = String::from_utf8(subagent("rvl-rust-pro", RUST_LENS.as_bytes())).unwrap();
        assert_eq!(
            out,
            "---\ndescription: \"Rust reliability: panics\"\nmode: subagent\npermission:\n  \
             edit: deny\n  bash: deny\n  webfetch: deny\n---\nReview the Rust code.\n"
        );
        let block = "---\ndescription: d\ntools:\n  - Read\n  - \"Bash\"\n---\nbody\n";
        let out = String::from_utf8(subagent("x", block.as_bytes())).unwrap();
        assert!(
            out.contains("  edit: deny\n") && !out.contains("bash: deny"),
            "{out}"
        );
        let flow = "---\ndescription: d\ntools: [Read, Edit, WebFetch, Bash]\n---\nbody\n";
        let out = String::from_utf8(subagent("x", flow.as_bytes())).unwrap();
        assert!(!out.contains("permission:"), "{out}");
    }

    #[test]
    fn no_tool_list_denies_nothing_and_a_missing_description_is_filled() {
        let out = String::from_utf8(subagent("rvl-golang-pro", GO_LENS.as_bytes())).unwrap();
        assert!(!out.contains("permission:"), "{out}");
        let out = String::from_utf8(subagent("rvl-x", b"plain body\n")).unwrap();
        assert_eq!(
            out,
            "---\ndescription: \"Revelara reliability lens rvl-x\"\nmode: subagent\n---\nplain body\n"
        );
    }

    #[test]
    fn an_opencode_native_agent_passes_through() {
        let native = b"---\ndescription: d\nmode: subagent\nmodel: anthropic/x\n---\nbody\n";
        assert_eq!(subagent("x", native), native.to_vec());
    }
}
