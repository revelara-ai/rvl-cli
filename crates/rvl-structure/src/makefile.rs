//! Which targets of the root Makefile run golangci-lint, for RC-040: a CI
//! step that runs `make lint` runs golangci-lint when the recipe of `lint`,
//! of a prerequisite, or of a target it runs with `$(MAKE)` does.
//!
//! A small reader, not make: it reads variable assignments, rule lines and
//! their tab-indented recipes, skips `define` blocks, pattern rules and
//! targets named by a variable, and reads no `include`d file. A recipe line
//! whose failure make ignores (a `-` prefix) or that lets a failure through
//! (`|| true`) runs no linter that can fail the build.
//!
//! Privacy: the result is target names, never recipe text.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The root Makefile names, in the order make looks for them.
const MAKEFILES: &[&str] = &["GNUmakefile", "makefile", "Makefile"];

/// How deep a chain of prerequisites and `$(MAKE)` calls is followed.
const MAX_DEPTH: usize = 4;

/// What a recipe line lets a failure through with.
const IGNORES_FAILURE: &[&str] = &["|| true", "||true", "|| :", "|| exit 0"];

/// The root Makefile's rules: each target's prerequisites and recipe lines,
/// and the variables assigned outside recipes.
#[derive(Default)]
struct Makefile {
    prerequisites: BTreeMap<String, Vec<String>>,
    recipes: BTreeMap<String, Vec<String>>,
    variables: BTreeMap<String, String>,
}

fn parse(text: &str) -> Makefile {
    let mut m = Makefile::default();
    let joined = text.replace("\\\n", " ");
    let mut current: Vec<String> = Vec::new();
    let mut in_define = false;
    for line in joined.lines() {
        if in_define {
            in_define = line.trim() != "endef";
            continue;
        }
        if let Some(recipe) = line.strip_prefix('\t') {
            for t in &current {
                m.recipes
                    .entry(t.clone())
                    .or_default()
                    .push(recipe.to_string());
            }
            continue;
        }
        let code = line.split('#').next().unwrap_or("");
        let t = code.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("define ") || t == "define" {
            in_define = true;
            current.clear();
            continue;
        }
        // A conditional may wrap a target's recipe lines.
        if ["ifeq", "ifneq", "ifdef", "ifndef", "else", "endif"]
            .iter()
            .any(|d| t == *d || t.starts_with(&format!("{d} ")))
        {
            continue;
        }
        if let Some((name, value)) = assignment(t) {
            m.variables
                .insert(name.to_string(), value.trim().to_string());
            current.clear();
            continue;
        }
        let Some((targets, rest)) = t.split_once(':') else {
            current.clear();
            continue;
        };
        let rest = rest.trim_start_matches(':');
        let (prereqs, inline) = rest.split_once(';').unwrap_or((rest, ""));
        current = targets
            .split_whitespace()
            .filter(|t| !t.contains('%') && !t.contains('$') && !t.starts_with('.'))
            .map(str::to_string)
            .collect();
        for target in &current {
            m.prerequisites.entry(target.clone()).or_default().extend(
                prereqs
                    .split_whitespace()
                    .filter(|p| *p != "|")
                    .map(str::to_string),
            );
            if !inline.trim().is_empty() {
                m.recipes
                    .entry(target.clone())
                    .or_default()
                    .push(inline.to_string());
            }
        }
    }
    m
}

/// A variable assignment outside a recipe: `NAME = value`, with `:=`, `::=`,
/// `?=`, `+=` or `!=`.
fn assignment(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let colon = line.find(':');
    if colon.is_some_and(|c| c < eq && !line[c..eq].trim_start_matches(':').is_empty()) {
        // `target: VAR = value` is a target-specific variable, not a rule's
        // prerequisites; either way it names no recipe.
        return None;
    }
    let name = line[..eq].trim_end_matches([':', '?', '+', '!']).trim();
    let name = name.strip_prefix("override ").unwrap_or(name).trim();
    let name = name.strip_prefix("export ").unwrap_or(name).trim();
    (!name.is_empty() && !name.contains(char::is_whitespace)).then(|| (name, &line[eq + 1..]))
}

/// Whether a variable named `name` runs golangci-lint: its name or its value
/// ends in `golangci-lint` (`GOLANGCI_LINT`, `$(BIN)/golangci-lint`, a
/// `go run .../golangci-lint@v2`).
fn golangci_variable(m: &Makefile, name: &str) -> bool {
    let ends = |s: &str| {
        s.to_ascii_lowercase()
            .replace('_', "-")
            .ends_with("golangci-lint")
    };
    ends(name)
        || m.variables.get(name).is_some_and(|v| {
            let last = v.split_whitespace().last().unwrap_or("");
            ends(last.split('@').next().unwrap_or(last))
        })
}

/// The command of one shell segment: the variable it is named by, if it is
/// `$(NAME)` or `${NAME}` alone, and its words.
fn command(segment: &str) -> (Option<&str>, Vec<&str>) {
    let s = segment.trim_start();
    for (open, close) in [("$(", ')'), ("${", '}')] {
        if let Some(rest) = s.strip_prefix(open) {
            if let Some((name, after)) = rest.split_once(close) {
                if after.is_empty() || after.starts_with(char::is_whitespace) {
                    return (Some(name), after.split_whitespace().collect());
                }
            }
        }
    }
    let words = s.split_whitespace().collect::<Vec<_>>();
    (None, words)
}

/// What one recipe line does that matters here: whether it runs
/// golangci-lint, and the targets it runs with `make` or `$(MAKE)`.
fn recipe_line(m: &Makefile, line: &str) -> (bool, Vec<String>) {
    let line = line.trim_start();
    let ignored = line.trim_start_matches(['@', '+']).starts_with('-')
        || IGNORES_FAILURE.iter().any(|x| line.contains(x));
    let line = line.trim_start_matches(['@', '-', '+']);
    let mut lints = false;
    let mut calls = Vec::new();
    for segment in line.split(['&', '|', ';']) {
        let (var, words) = command(segment);
        let (tool, args): (Option<&str>, &[&str]) = match var {
            Some("MAKE") => (Some("make"), &words[..]),
            Some(name) if golangci_variable(m, name) => (Some("golangci-lint"), &words[..]),
            Some(_) => (None, &[]),
            None => match words.split_first() {
                Some((first, rest)) => (first.rsplit('/').next(), rest),
                None => (None, &[]),
            },
        };
        match tool {
            Some("golangci-lint") if args.first() == Some(&"run") => lints |= !ignored,
            Some("make" | "gmake") => calls.extend(make_targets(args)),
            _ => {}
        }
    }
    (lints, calls)
}

/// The targets a `make` command line names: its words that are neither a
/// flag nor a variable assignment. `None` when it reads another Makefile
/// (`-C`, `-f`), which this reader does not.
pub(crate) fn make_targets(args: &[&str]) -> Vec<String> {
    if args.iter().any(|a| {
        matches!(*a, "-C" | "-f" | "--file" | "--makefile" | "--directory")
            || a.starts_with("--directory=")
            || a.starts_with("--file=")
            || a.starts_with("--makefile=")
            || (a.starts_with("-C") && a.len() > 2)
            || (a.starts_with("-f") && a.len() > 2)
    }) {
        return Vec::new();
    }
    args.iter()
        .filter(|a| !a.starts_with('-') && !a.contains('='))
        .map(|a| a.trim_matches(['"', '\'']).to_string())
        .collect()
}

/// Whether `target` runs golangci-lint, through its recipe, a prerequisite
/// or a `$(MAKE)` call, `depth` steps down a chain.
fn runs_golangci(m: &Makefile, target: &str, depth: usize, seen: &mut BTreeSet<String>) -> bool {
    if depth > MAX_DEPTH || !seen.insert(target.to_string()) {
        return false;
    }
    let mut next: Vec<String> = m.prerequisites.get(target).cloned().unwrap_or_default();
    for line in m.recipes.get(target).into_iter().flatten() {
        let (lints, calls) = recipe_line(m, line);
        if lints {
            return true;
        }
        next.extend(calls);
    }
    next.iter().any(|t| runs_golangci(m, t, depth + 1, seen))
}

/// The targets of the root Makefile that run golangci-lint, sorted. Empty
/// without a root Makefile.
pub(crate) fn golangci_targets(root: &Path) -> Vec<String> {
    let Some(path) = MAKEFILES.iter().map(|n| root.join(n)).find(|p| p.is_file()) else {
        return Vec::new();
    };
    let m = parse(&crate::inventory::read_capped(&path));
    let targets: BTreeSet<&String> = m.prerequisites.keys().chain(m.recipes.keys()).collect();
    targets
        .into_iter()
        .filter(|t| runs_golangci(&m, t, 0, &mut BTreeSet::new()))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(text: &str) -> Vec<String> {
        let m = parse(text);
        let all: BTreeSet<&String> = m.prerequisites.keys().chain(m.recipes.keys()).collect();
        all.into_iter()
            .filter(|t| runs_golangci(&m, t, 0, &mut BTreeSet::new()))
            .cloned()
            .collect()
    }

    #[test]
    fn a_variable_named_or_valued_golangci_lint_runs_it() {
        let text = "GOLANGCI_LINT ?= $(LOCALBIN)/golangci-lint\n\
                    LINTER := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.0\n\
                    lint: lint-custom #HELP Run golangci linter.\n\
                    \t$(GOLANGCI_LINT) run --build-tags $(TAGS)\n\
                    lint-other:\n\
                    \t@$(LINTER) run ./...\n\
                    lint-custom:\n\
                    \tgo vet ./...\n";
        assert_eq!(targets(text), ["lint", "lint-other"]);
    }

    #[test]
    fn prerequisites_and_make_calls_are_followed_to_a_fixed_depth() {
        let text = "verify: tidy lint\n\
                    lint:\n\
                    \tgolangci-lint run\n\
                    ci:\n\
                    \t$(MAKE) verify\n\
                    a: b\nb: c\nc: d\nd: e\ne: lint\n\
                    loop: loop2\nloop2: loop\n";
        let got = targets(text);
        for t in ["verify", "lint", "ci", "b", "c", "d", "e"] {
            assert!(got.contains(&t.to_string()), "{t}: {got:?}");
        }
        // a -> b -> c -> d -> e -> lint is one step past MAX_DEPTH.
        assert!(!got.contains(&"a".to_string()), "{got:?}");
        assert!(!got.contains(&"loop".to_string()), "{got:?}");
    }

    #[test]
    fn an_ignored_failure_or_another_makefile_runs_no_gate() {
        let text = "lint:\n\t-golangci-lint run\nlint2:\n\tgolangci-lint run || true\n\
                    sub:\n\t$(MAKE) -C tools lint\n";
        assert!(targets(text).is_empty(), "{:?}", targets(text));
        assert!(make_targets(&["-C", "sub", "lint"]).is_empty());
        assert_eq!(make_targets(&["-j4", "lint", "GOFLAGS=-v"]), ["lint"]);
    }
}
