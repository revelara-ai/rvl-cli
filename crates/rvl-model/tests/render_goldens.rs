//! The renderer against the training renderer's goldens.
//!
//! `testdata/render-goldens/render-goldens.jsonl` holds inputs of the
//! decision model's private training renderer with the text it wrote and
//! the ids the shipped model's tokenizer gives that text, under both
//! layouts (`SOURCE.md` says where they come from). Each golden
//! is rendered here and tokenized with the vendored tokenizer, and must
//! match both exactly.
//!
//! A golden input is a label-export row, whose question is the judges' text;
//! [`question_of`] reads the expectation and the frame out of that text as
//! the training renderer does. rvl gets them structured, from the spec cache.

use std::path::PathBuf;

use regex::Regex;
use rvl_core::Snippet;
use rvl_model::render::{render_input, ConstArg, Frame, Layout, Question, Site, SitePacket};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokenizers::Tokenizer;

const TOKENIZER_SHA256: &str = "9fd55248d51d33976b324fc11592e28071da7d41e0e9401dfb7082e30574b7b1";

fn goldens_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/render-goldens")
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn snippets(v: &Value, key: &str) -> Vec<Snippet> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|c| Snippet {
                    file: str_of(c, "file").into(),
                    line: c["line"].as_u64().expect("a snippet line") as u32,
                    symbol: str_of(c, "symbol").into(),
                    source: str_of(c, "source").into(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn site_packet_of(sp: &Value) -> SitePacket {
    SitePacket {
        symbol: str_of(sp, "symbol").into(),
        enclosing_function_body: str_of(sp, "enclosing_function_body").into(),
        client_type: str_of(sp, "client_type").into(),
        client_construction_scope: str_of(sp, "client_construction_scope").into(),
        client_construction: snippets(sp, "client_construction"),
        callers: snippets(sp, "callers"),
        const_args: sp
            .get("const_args")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|c| ConstArg {
                        name: str_of(c, "name").into(),
                        index: c.get("index").and_then(Value::as_u64).map(|i| i as u32),
                        value: str_of(c, "value").into(),
                    })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// The question of an export row, read out of its text by the same
/// expressions the training renderer uses.
fn question_of(row: &Value) -> Question {
    let text = row["question"]["text"].as_str().unwrap_or("");
    let group = |re: &str, i: usize| {
        Regex::new(re)
            .unwrap()
            .captures(text)
            .and_then(|c| c.get(i))
            .map_or("", |m| m.as_str())
            .to_string()
    };
    if str_of(row, "kind") != "frame_question" {
        return Question::Bound {
            expectation: group(
                r"(?s)Published expectation for this class: (.*?)(?:\n\n|\z)",
                1,
            ),
        };
    }
    let cells = group(r"(?m)^Cells of the RC-\d+ frame:\n((?:  \S.*\n?)+)", 1);
    Question::Frame(Frame {
        control: str_of(row, "control").into(),
        control_name: group(r"(?m)^Control meaning: RC-\d+ - (.+)$", 1),
        question: group(r"(?m)^Question \((RC-\d+), (v\d+)\): (.+)$", 3),
        cells: cells.lines().map(str::to_string).collect(),
    })
}

fn site_of(input: &Value) -> Site {
    let row = &input["row"];
    let packet = &row["packet"];
    Site {
        class: str_of(row, "class").into(),
        scope: str_of(row, "scope").into(),
        language: str_of(row, "language").into(),
        file: str_of(row, "file").into(),
        site: str_of(row, "site").into(),
        snippet: str_of(packet, "snippet").into(),
        imports: str_of(packet, "imports").into(),
        callee_name: str_of(packet, "callee_name").into(),
        callee_definition: str_of(packet, "callee_definition").into(),
        enclosing_name: str_of(packet, "enclosing_name").into(),
        enclosing_function: str_of(packet, "enclosing_function").into(),
        packet: site_packet_of(&input["site_packet"]),
    }
}

#[test]
fn every_golden_renders_and_tokenizes_exactly() {
    let dir = goldens_dir();
    let tokenizer_bytes = std::fs::read(dir.join("tokenizer.json")).unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(&tokenizer_bytes)),
        TOKENIZER_SHA256,
        "the vendored tokenizer is not the shipped model's"
    );
    let tokenizer = Tokenizer::from_bytes(&tokenizer_bytes).unwrap();
    let goldens = std::fs::read_to_string(dir.join("render-goldens.jsonl")).unwrap();
    let mut checked = [0usize; 2];
    for (n, line) in goldens.lines().filter(|l| !l.trim().is_empty()).enumerate() {
        let g: Value = serde_json::from_str(line).unwrap();
        let input = &g["input"];
        assert_eq!(
            str_of(input, "evidence"),
            "none",
            "golden {n}: rvl renders no evidence citations"
        );
        assert_eq!(
            str_of(&g, "tokenizer_sha256"),
            TOKENIZER_SHA256,
            "golden {n}"
        );
        let layout = match str_of(&g, "layout") {
            "full" => Layout::Full,
            "compact" => Layout::Compact,
            other => panic!("golden {n}: layout {other:?}"),
        };
        let id = str_of(&input["row"], "id");
        let text = render_input(&site_of(input), &question_of(&input["row"]), layout);
        assert_eq!(
            text,
            str_of(&g, "text"),
            "golden {n} ({id}, {layout:?}): text"
        );
        let want: Vec<u32> = g["token_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u32)
            .collect();
        let got = tokenizer.encode(text.as_str(), true).unwrap();
        assert_eq!(
            got.get_ids(),
            want.as_slice(),
            "golden {n} ({id}, {layout:?}): token ids"
        );
        checked[(layout == Layout::Compact) as usize] += 1;
    }
    assert_eq!(
        checked,
        [60, 60],
        "goldens checked per layout (full, compact)"
    );
}

#[test]
fn a_site_packet_comes_from_rvls_site() {
    let site: rvl_core::Site = serde_json::from_str(
        r#"{"file_path":"svc/fetch.go","line_number":41,"symbol":"fetch","client_type":"net/http.Client",
            "enclosing_function_body":"func fetch() {}","client_construction_scope":"field",
            "client_construction":[{"file":"svc/new.go","line":12,"symbol":"net/http.Client","source":"&http.Client{}"}],
            "const_args":[{"index":0,"value":"5","how":"literal"}]}"#,
    )
    .unwrap();
    let sp = SitePacket::from(&site);
    assert_eq!(sp.symbol, "fetch");
    assert_eq!(sp.client_construction_scope, "field");
    assert_eq!(sp.client_construction[0].line, 12);
    assert_eq!(
        sp.const_args,
        vec![ConstArg {
            name: String::new(),
            index: Some(0),
            value: "5".into()
        }]
    );
    let text = render_input(
        &Site {
            class: "net/http.Client.Do".into(),
            site: "svc/fetch.go:41".into(),
            packet: sp,
            ..Site::default()
        },
        &Question::Bound {
            expectation: "bounded".into(),
        },
        Layout::Compact,
    );
    assert_eq!(
        text,
        "Class: net/http.Client.Do\nExpectation: bounded\nScope: unknown\nSite svc/fetch.go:41:\n\n\n\
         Constant arguments: 0=5\n\nHow net/http.Client is built (found by field):\nsvc/new.go:12\n&http.Client{}\n\n\
         Enclosing function fetch:\nfunc fetch() {}\n\nImports:\n(none found)"
    );
}
