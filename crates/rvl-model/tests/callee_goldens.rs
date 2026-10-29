//! The callee definition finder against the training exporter's output.
//!
//! `testdata/callee-goldens/callee-goldens.jsonl` holds, for every line of
//! each fixture file beside it (and the lines just out of each file), the
//! callee name and block the training exporter's function gives
//! (`SOURCE.md` says how they were written). [`callee_definition`] must give
//! the same bytes on each.

use std::path::PathBuf;

use rvl_model::render::{callee_definition, DEFINITION_MAX_LINES};
use serde_json::Value;

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/callee-goldens")
}

/// A golden row: file, line, and the expected callee, `None` for none.
type Golden = (String, usize, Option<(String, String)>);

fn goldens() -> Vec<Golden> {
    let text = std::fs::read_to_string(goldens_dir().join("callee-goldens.jsonl")).unwrap();
    text.lines()
        .map(|l| {
            let r: Value = serde_json::from_str(l).unwrap();
            let s = |k: &str| r[k].as_str().unwrap().to_string();
            let callee = (!s("name").is_empty()).then(|| (s("name"), s("block")));
            (s("file"), r["line"].as_u64().unwrap() as usize, callee)
        })
        .collect()
}

fn expected(file: &str, line: usize) -> Option<(String, String)> {
    goldens()
        .into_iter()
        .find(|(f, l, _)| f == file && *l == line)
        .unwrap_or_else(|| panic!("no golden for {file}:{line}"))
        .2
}

#[test]
fn every_line_of_the_fixtures_gives_the_exporters_callee_byte_for_byte() {
    let goldens = goldens();
    let mut files = std::collections::BTreeSet::new();
    let mut found = 0;
    for (file, line, want) in &goldens {
        let source = std::fs::read_to_string(goldens_dir().join(file)).unwrap();
        assert_eq!(&callee_definition(&source, *line), want, "{file}:{line}");
        files.insert(file.as_str());
        found += want.is_some() as usize;
    }
    assert_eq!(
        (files.len(), goldens.len(), found),
        (9, 273, 22),
        "fixture files, lines checked, lines with a callee"
    );
}

#[test]
fn the_goldens_hold_the_cases_that_matter() {
    let name = |file: &str, line: usize| expected(file, line).map(|(n, _)| n);
    // Two calls on the site line: the rightmost with a definition wins.
    assert_eq!(name("client.py", 29), Some("fetch".into()));
    assert_eq!(name("Gateway.java", 17), Some("request".into()));
    // A call into another file has no block.
    assert_eq!(name("client.py", 15), None);
    assert_eq!(name("api.ts", 4), None);
    // A definition near the end of the file: the block stops at its last line.
    let (_, block) = expected("client.py", 42).unwrap();
    assert!(block.starts_with("  35 | async def drain(queue):\n"));
    assert!(block.ends_with("\n  43 | "), "{block:?}");
    // A long definition: DEFINITION_MAX_LINES lines.
    let (_, block) = expected("long.py", 2).unwrap();
    assert_eq!(block.lines().count(), DEFINITION_MAX_LINES);
    // Each language's definition form.
    for (file, line, callee) in [
        ("store.go", 22, "newRequest"),
        ("store.go", 26, "do"),
        ("api.ts", 15, "fetchUser"),
        ("api.ts", 16, "pages"),
        ("worker.js", 11, "handler"),
        ("lib.rs", 20, "connect"),
        ("lib.rs", 21, "send"),
        ("Fetcher.cs", 10, "Normalize"),
    ] {
        assert_eq!(name(file, line), Some(callee.into()), "{file}:{line}");
    }
    // Go's RE2 classes: no-break space, a vertical tab and a non-ASCII
    // letter are not whitespace or word characters there.
    assert_eq!(name("edges.txt", 5), None);
    assert_eq!(name("edges.txt", 8), None);
    assert_eq!(name("edges.txt", 10), None);
    // A CRLF file's lines keep their `\r`.
    assert!(expected("edges.txt", 3)
        .unwrap()
        .1
        .contains("def crlf(x):\r\n"));
}
