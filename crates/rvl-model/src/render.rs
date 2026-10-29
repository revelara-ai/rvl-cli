//! The decision model's input text.
//!
//! The model was trained on text written by the decision model's private
//! training renderer, and it must see the same text at scan time, byte for
//! byte: an input it was not trained on is a silent drift in its decisions.
//! [`render_input`] writes that text from what rvl has at a site: the export
//! fields of the site ([`Site`]), the retriever's site packet
//! ([`SitePacket`]) and the question asked of it ([`Question`]: the bound
//! question, or a served frame's).
//!
//! The training renderer counts length caps in Unicode code points and
//! collapses and strips whitespace by Python's definition of it; so does this
//! module. The goldens test (`tests/render_goldens.rs`) holds the two to the
//! same bytes and the same token ids.
//!
//! The token ids are the model's input as they are: truncated to the
//! bundle's `max_length`, never padded (`classify`). A model is to be
//! measured the same way, each input at its own length.

use rvl_core::Snippet;

/// The cap on the site snippet, a callee definition and an enclosing function.
pub const SNIPPET_MAX_CHARS: usize = 6000;
/// The cap on each client construction.
pub const CONSTRUCTION_MAX_CHARS: usize = 1500;
/// The cap on each caller.
pub const CALLER_MAX_CHARS: usize = 1500;
/// Callers rendered, at most.
pub const CALLERS_MAX: usize = 2;
/// Client constructions rendered, at most.
pub const CONSTRUCTIONS_MAX: usize = 3;
/// The cap on the constant-arguments line.
pub const CONST_ARGS_MAX_CHARS: usize = 400;

/// How the input is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Every part, a frame's cells and the language included.
    Full,
    /// The layout of the shipped model, for a short context: a frame's
    /// question without its cells, and the site code before everything else,
    /// so a tokenizer that cuts the tail cuts the least useful text.
    Compact,
}

/// What the model is asked about the site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Question {
    /// Whether the blocking call is bounded, with the class's published
    /// expectation.
    Bound { expectation: String },
    /// A frame's question.
    Frame(Frame),
}

/// A served frame: the control it belongs to, its question and its cells.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    /// `RC-022`.
    pub control: String,
    /// The control's name, `Retry, Backoff and Request Coalescing`.
    pub control_name: String,
    /// The frame's question.
    pub question: String,
    /// One line per cell, `M1  [violates] No retry at any layer`.
    pub cells: Vec<String>,
}

/// A site, as the model reads it.
#[derive(Debug, Clone, Default)]
pub struct Site {
    /// The class of the call, `net/http.Client.Do`.
    pub class: String,
    /// The site's scope; empty is `unknown`.
    pub scope: String,
    /// The site's language; empty is the one the file name gives.
    pub language: String,
    pub file: String,
    /// `file:line`.
    pub site: String,
    pub snippet: String,
    pub imports: String,
    pub callee_name: String,
    pub callee_definition: String,
    pub enclosing_name: String,
    /// When empty, the site packet's enclosing function body stands in.
    pub enclosing_function: String,
    pub packet: SitePacket,
}

/// What the retriever knows about a site beyond its code: the constant
/// arguments, how the client was built, who calls the enclosing function.
#[derive(Debug, Clone, Default)]
pub struct SitePacket {
    /// The enclosing function's name.
    pub symbol: String,
    pub enclosing_function_body: String,
    pub client_type: String,
    pub client_construction_scope: String,
    pub client_construction: Vec<Snippet>,
    pub callers: Vec<Snippet>,
    pub const_args: Vec<ConstArg>,
}

/// A constant argument. A nameless one renders by its index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConstArg {
    pub name: String,
    pub index: Option<u32>,
    pub value: String,
}

impl From<&rvl_core::Site> for SitePacket {
    fn from(s: &rvl_core::Site) -> SitePacket {
        SitePacket {
            symbol: s.symbol.clone(),
            enclosing_function_body: s.enclosing_function_body.clone(),
            client_type: s.client_type.clone(),
            client_construction_scope: s.client_construction_scope.clone(),
            client_construction: s.client_construction.clone(),
            callers: s.callers.clone(),
            const_args: s
                .const_args
                .iter()
                .map(|a| ConstArg {
                    name: a.name.clone(),
                    index: Some(a.index),
                    value: a.value.clone(),
                })
                .collect(),
        }
    }
}

/// The import block of a file, in the training packets' form: each import
/// line under its 1-based line number, `   3 | import (`, with the lines a
/// statement continues onto (a Go `import (` block, a parenthesized Python
/// import, a multi-line JavaScript `import {` or Rust `use`). Which lines
/// import is read from the file name's suffix; a file of another language,
/// or one with no import, gives the empty block, which renders
/// `(none found)`. Uncapped, as the training renderer leaves it.
pub fn imports_block(file: &str, source: &str) -> String {
    let Some(syntax) = ImportSyntax::of(file) else {
        return String::new();
    };
    let mut out = Vec::new();
    let mut open: Option<&str> = None;
    for (i, line) in source.lines().enumerate() {
        let t = line.trim_start();
        let closes = match open {
            Some(close) => t.contains(close) || (close == "\\" && !t.ends_with('\\')),
            None => match syntax.opens(t) {
                None => continue,
                Some(close) => {
                    open = Some(close);
                    close == "\\" && !t.ends_with('\\')
                }
            },
        };
        out.push(format!("{:>4} | {line}", i + 1));
        if closes || open == Some("") {
            open = None;
        }
    }
    out.join("\n")
}

/// Lines of a callee definition shown.
pub const DEFINITION_MAX_LINES: usize = 40;

/// Names that appear with parentheses on almost every line and never name a
/// callee worth showing.
const CALL_NOISE: [&str; 34] = [
    "if", "for", "while", "switch", "return", "range", "catch", "max", "min", "len", "print",
    "str", "int", "float", "list", "dict", "set", "tuple", "bool", "make", "new", "append", "fmt",
    "log", "await", "defer", "go", "func", "function", "def", "assert", "super", "self", "this",
];

/// A pattern of the training exporter, which is Go's RE2 syntax, compiled
/// with Go's meaning: there `\s` is `[\t\n\f\r ]` and `\w` is
/// `[0-9A-Za-z_]`, where the regex crate's are Unicode (and its ASCII `\s`
/// has `\v`). A `\w` inside a class becomes a nested class, which is the
/// same union.
fn re2(pattern: &str) -> regex::Regex {
    let pattern = pattern
        .replace(r"\s", r"[\t\n\f\r ]")
        .replace(r"\w", "[0-9A-Za-z_]");
    regex::Regex::new(&pattern).expect("a valid pattern")
}

/// The definition of the callee at a site, in the training packets' form:
/// in the same file, the definition of a name called on the site line
/// (1-based), and the `DEFINITION_MAX_LINES` lines from its first line,
/// each under its number, `  12 | def fetch(url):`. The rightmost call on
/// the line is tried first: in `out = self._call_once(prompt)` that is
/// `_call_once`. Definitions are found by their first line: a Python `def`,
/// a Go `func` (with or without a receiver), a JavaScript/TypeScript
/// `function` or `const`/`let`/`var` binding, a Rust `fn`, and a
/// Java/C#-style method header; the site line itself is not one. A name
/// defined in another file, or a line out of the file, gives `None`.
///
/// A port of the training exporter's, byte for byte, its patterns included:
/// the file is split on `\n` alone, so a CRLF line keeps its `\r`.
pub fn callee_definition(source: &str, line: usize) -> Option<(String, String)> {
    static CALL_NAME: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let call_name = CALL_NAME.get_or_init(|| re2(r"([A-Za-z_][A-Za-z0-9_]*)\s*\("));
    let all: Vec<&str> = source.split('\n').collect();
    if line < 1 || line > all.len() {
        return None;
    }
    let mut names: Vec<&str> = Vec::new();
    for m in call_name.captures_iter(all[line - 1]) {
        let name = m.get(1).expect("the name group").as_str();
        if !CALL_NOISE.contains(&name) && !names.contains(&name) {
            names.push(name);
        }
    }
    for name in names.into_iter().rev() {
        let name_re = regex::escape(name);
        let def = re2(&format!(
            r"^\s*(async\s+)?(def|fn|pub\s+fn|pub\(crate\)\s+fn|function\*?|func(\s*\([^)]*\))?)\s+{name_re}\s*[(<\[]|^\s*(export\s+)?(const|let|var)\s+{name_re}\s*(:\s*[^=]+)?=|^\s*((public|private|protected|internal|static|final|async|override|virtual|abstract)\s+)*[\w<>\[\],.?]+\s+{name_re}\s*\([^;]*$"
        ));
        let Some(at) = (0..all.len()).find(|&at| at != line - 1 && def.is_match(all[at])) else {
            continue;
        };
        let end = (at + DEFINITION_MAX_LINES).min(all.len());
        let mut block = String::new();
        for (n, text) in all.iter().enumerate().take(end).skip(at) {
            block.push_str(&format!("{:>4} | {text}\n", n + 1));
        }
        return Some((name.to_string(), block.trim_end_matches('\n').to_string()));
    }
    None
}

/// How a language writes an import statement.
#[derive(Clone, Copy)]
enum ImportSyntax {
    Go,
    Python,
    JavaScript,
    Jvm,
    Rust,
    CSharp,
    Ruby,
    Php,
    C,
}

impl ImportSyntax {
    fn of(file: &str) -> Option<ImportSyntax> {
        let suffix = file.rfind('.').map(|d| file[d + 1..].to_lowercase())?;
        Some(match suffix.as_str() {
            "go" => ImportSyntax::Go,
            "py" => ImportSyntax::Python,
            "ts" | "tsx" | "js" | "jsx" | "mjs" | "cjs" => ImportSyntax::JavaScript,
            "java" | "kt" | "scala" => ImportSyntax::Jvm,
            "rs" => ImportSyntax::Rust,
            "cs" => ImportSyntax::CSharp,
            "rb" => ImportSyntax::Ruby,
            "php" => ImportSyntax::Php,
            "c" | "h" | "cc" | "cpp" | "cxx" | "hpp" | "hh" => ImportSyntax::C,
            _ => return None,
        })
    }

    /// When `t`, a line without its indent, starts an import: what closes
    /// the statement, `""` when the line itself does, `"\\"` when a line
    /// that does not end in a backslash does.
    fn opens(self, t: &str) -> Option<&'static str> {
        let word = |w: &str| t.strip_prefix(w).filter(|r| r.starts_with([' ', '\t']));
        let until = |close: &'static str, done: bool| Some(if done { "" } else { close });
        match self {
            ImportSyntax::Go => {
                let rest = word("import")?.trim_start();
                until(")", !rest.starts_with('('))
            }
            ImportSyntax::Python => {
                let rest =
                    word("import").or_else(|| word("from").filter(|r| r.contains(" import")))?;
                if rest.ends_with('\\') {
                    Some("\\")
                } else {
                    until(")", !rest.contains('(') || rest.contains(')'))
                }
            }
            ImportSyntax::JavaScript => {
                if let Some(rest) =
                    word("import").or_else(|| word("export").filter(|r| r.contains("from")))
                {
                    until("from", rest.contains("from") || rest.contains(['\'', '"']))
                } else if t.contains("require(") {
                    until("", true)
                } else {
                    None
                }
            }
            ImportSyntax::Jvm => word("import").and(until("", true)),
            ImportSyntax::Rust => {
                let rest = word("use")
                    .or_else(|| word("pub").and_then(|r| r.trim_start().strip_prefix("use ")))
                    .or_else(|| word("extern").filter(|r| r.trim_start().starts_with("crate ")))?;
                until(";", rest.contains(';'))
            }
            ImportSyntax::CSharp => {
                let rest = word("global").map_or(t, str::trim_start);
                let rest = rest.strip_prefix("using").filter(|r| r.starts_with(' '))?;
                (!rest.contains('(') && rest.trim_end().ends_with(';')).then_some("")
            }
            ImportSyntax::Ruby => ["require", "require_relative", "load"]
                .into_iter()
                .any(|w| word(w).is_some() || t.starts_with(&format!("{w}(")))
                .then_some(""),
            ImportSyntax::Php => {
                if let Some(rest) = word("use") {
                    until(";", rest.contains(';'))
                } else {
                    ["require", "require_once", "include", "include_once"]
                        .into_iter()
                        .any(|w| word(w).is_some() || t.starts_with(&format!("{w}(")))
                        .then_some("")
                }
            }
            ImportSyntax::C => t
                .strip_prefix('#')
                .is_some_and(|r| {
                    r.trim_start().starts_with("include") || r.trim_start().starts_with("import")
                })
                .then_some(""),
        }
    }
}

/// The model's input for `site` asked `question`, laid out as `layout`.
pub fn render_input(site: &Site, question: &Question, layout: Layout) -> String {
    let sp = &site.packet;
    let (enclosing_name, enclosing) =
        if !sp.enclosing_function_body.is_empty() && site.enclosing_function.is_empty() {
            (sp.symbol.as_str(), sp.enclosing_function_body.as_str())
        } else {
            (
                site.enclosing_name.as_str(),
                site.enclosing_function.as_str(),
            )
        };
    let mut out = vec![format!("Class: {}", site.class)];
    match question {
        Question::Bound { expectation } => {
            out.push(format!("Expectation: {}", collapse(expectation)))
        }
        Question::Frame(f) => {
            let control = format!("Control: {} {}", f.control, py_strip(&f.control_name));
            out.push(control.trim_end_matches(py_space).to_string());
            out.push(format!("Question: {}", py_strip(&f.question)));
            let cells: Vec<String> = f
                .cells
                .iter()
                .map(|c| collapse(c))
                .filter(|c| !c.is_empty())
                .collect();
            if layout == Layout::Full && !cells.is_empty() {
                out.push("Cells:".into());
                out.extend(cells);
            }
        }
    }
    out.push(format!("Scope: {}", or(&site.scope, "unknown")));
    let enclosing_lines = |out: &mut Vec<String>| {
        if !enclosing.is_empty() {
            out.push(String::new());
            out.push(format!("Enclosing function {enclosing_name}:"));
            out.push(head(enclosing, SNIPPET_MAX_CHARS).into());
        }
    };
    let callee_lines = |out: &mut Vec<String>| {
        if !site.callee_definition.is_empty() {
            out.push(String::new());
            out.push(format!(
                "Definition of {}, called at the site:",
                site.callee_name
            ));
            out.push(head(&site.callee_definition, SNIPPET_MAX_CHARS).into());
        }
    };
    let import_lines = |out: &mut Vec<String>| {
        out.push(String::new());
        out.push("Imports:".into());
        out.push(or(&site.imports, "(none found)").into());
    };
    if layout == Layout::Full {
        out.push(format!("Language: {}", language_of(site)));
        out.push(String::new());
    }
    out.push(format!("Site {}:", site.site));
    out.push(head(&site.snippet, SNIPPET_MAX_CHARS).into());
    site_packet_lines(sp, &mut out);
    match layout {
        Layout::Full => {
            import_lines(&mut out);
            callee_lines(&mut out);
            enclosing_lines(&mut out);
            caller_lines(sp, &mut out);
        }
        Layout::Compact => {
            enclosing_lines(&mut out);
            callee_lines(&mut out);
            caller_lines(sp, &mut out);
            import_lines(&mut out);
        }
    }
    out.join("\n")
}

fn site_packet_lines(sp: &SitePacket, out: &mut Vec<String>) {
    let args: Vec<String> = sp
        .const_args
        .iter()
        .map(|a| {
            let key = match (a.name.as_str(), a.index) {
                ("", Some(i)) => i.to_string(),
                ("", None) => String::new(),
                (name, _) => name.to_string(),
            };
            format!("{key}={}", a.value)
        })
        .collect();
    if !args.is_empty() {
        out.push(String::new());
        out.push(format!(
            "Constant arguments: {}",
            head(&args.join(", "), CONST_ARGS_MAX_CHARS)
        ));
    }
    let built: Vec<&Snippet> = sp
        .client_construction
        .iter()
        .filter(|c| !c.source.is_empty())
        .collect();
    if !built.is_empty() {
        out.push(String::new());
        out.push(format!(
            "How {} is built (found by {}):",
            or(&sp.client_type, "the client"),
            or(&sp.client_construction_scope, "unknown")
        ));
        for c in built.into_iter().take(CONSTRUCTIONS_MAX) {
            out.push(format!(
                "{}:{}\n{}",
                c.file,
                c.line,
                head(&c.source, CONSTRUCTION_MAX_CHARS)
            ));
        }
    } else if !sp.client_type.is_empty() {
        out.push(String::new());
        out.push(format!(
            "How {} is built: not found in the repository",
            sp.client_type
        ));
    }
}

fn caller_lines(sp: &SitePacket, out: &mut Vec<String>) {
    for c in sp
        .callers
        .iter()
        .filter(|c| !c.source.is_empty())
        .take(CALLERS_MAX)
    {
        out.push(String::new());
        out.push(format!("Caller {} at {}:{}:", c.symbol, c.file, c.line));
        out.push(head(&c.source, CALLER_MAX_CHARS).into());
    }
}

/// The recorded language, else the one the file name's suffix gives.
fn language_of(site: &Site) -> String {
    let recorded = py_strip(&site.language).to_lowercase();
    if !recorded.is_empty() {
        return recorded;
    }
    let Some(dot) = site.file.rfind('.') else {
        return "unknown".into();
    };
    match site.file[dot..].to_lowercase().as_str() {
        ".go" => "go",
        ".py" => "python",
        ".ts" | ".tsx" => "typescript",
        ".js" | ".jsx" | ".mjs" => "javascript",
        ".java" => "java",
        ".kt" => "kotlin",
        ".rs" => "rust",
        ".rb" => "ruby",
        ".cs" => "csharp",
        ".php" => "php",
        _ => "unknown",
    }
    .into()
}

fn or<'a>(s: &'a str, default: &'a str) -> &'a str {
    if s.is_empty() {
        default
    } else {
        s
    }
}

/// The first `n` code points of `s`.
fn head(s: &str, n: usize) -> &str {
    s.char_indices().nth(n).map_or(s, |(i, _)| &s[..i])
}

/// Whitespace as Python's `str.isspace` has it: Unicode White_Space and the
/// information separators U+001C to U+001F.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(s: &str) -> &str {
    s.trim_matches(py_space)
}

/// `" ".join(s.split())`.
fn collapse(s: &str) -> String {
    s.split(py_space)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_count_code_points() {
        assert_eq!(head("héllo", 2), "hé");
        assert_eq!(head("hé", 5), "hé");
    }

    #[test]
    fn whitespace_is_pythons() {
        assert_eq!(collapse(" a\u{1f}b\u{a0} c\n"), "a b c");
        assert_eq!(py_strip("\u{1c} x \u{3000}"), "x");
    }

    #[test]
    fn a_nameless_constant_argument_renders_by_its_index() {
        let sp = SitePacket {
            const_args: vec![
                ConstArg {
                    name: String::new(),
                    index: Some(1),
                    value: "5".into(),
                },
                ConstArg {
                    name: "timeout".into(),
                    index: Some(2),
                    value: "3".into(),
                },
                ConstArg {
                    name: String::new(),
                    index: None,
                    value: "x".into(),
                },
            ],
            ..SitePacket::default()
        };
        let mut out = Vec::new();
        site_packet_lines(&sp, &mut out);
        assert_eq!(
            out,
            vec![
                "".to_string(),
                "Constant arguments: 1=5, timeout=3, =x".into()
            ]
        );
    }

    #[test]
    fn an_import_block_is_each_import_line_under_its_number() {
        let go = "package svc\n\nimport (\n\t\"context\"\n\t\"net/http\"\n)\n\nimport \"os\"\n\nfunc f() {}\n";
        assert_eq!(
            imports_block("svc/a.go", go),
            "   3 | import (\n   4 | \t\"context\"\n   5 | \t\"net/http\"\n   6 | )\n   8 | import \"os\""
        );
        let py = "import requests\nfrom app import (\n    a,\n    b,\n)\nfrom x import \\\n    y\nx = 1\n    import json\n# from the start\n";
        assert_eq!(
            imports_block("app/c.py", py),
            "   1 | import requests\n   2 | from app import (\n   3 |     a,\n   4 |     b,\n   5 | )\n\
             \x20  6 | from x import \\\n   7 |     y\n   9 |     import json"
        );
        let ts = "import {\n  a,\n} from \"x\";\nimport \"y\";\nconst z = require('z');\nexport { q } from './q';\nconst n = 1;\n";
        assert_eq!(
            imports_block("web/a.ts", ts),
            "   1 | import {\n   2 |   a,\n   3 | } from \"x\";\n   4 | import \"y\";\n\
             \x20  5 | const z = require('z');\n   6 | export { q } from './q';"
        );
        let rs = "use std::{\n    fs,\n};\npub use a::b;\nfn main() { let used = 1; }\n";
        assert_eq!(
            imports_block("src/main.rs", rs),
            "   1 | use std::{\n   2 |     fs,\n   3 | };\n   4 | pub use a::b;"
        );
        let cs = "using System.Net.Http;\nglobal using Foo;\nusing (var c = new HttpClient()) {}\n";
        assert_eq!(
            imports_block("A.cs", cs),
            "   1 | using System.Net.Http;\n   2 | global using Foo;"
        );
        assert_eq!(
            imports_block(
                "A.java",
                "package a;\nimport java.net.http.HttpClient;\nclass A {}\n"
            ),
            "   2 | import java.net.http.HttpClient;"
        );
        assert_eq!(
            imports_block(
                "a.c",
                "#include <curl/curl.h>\n# include \"x.h\"\nint main() {}\n"
            ),
            "   1 | #include <curl/curl.h>\n   2 | # include \"x.h\""
        );
        assert_eq!(
            imports_block("a.rb", "require 'net/http'\nputs 1\n"),
            "   1 | require 'net/http'"
        );
        assert_eq!(imports_block("Makefile", "import x\n"), "");
        assert_eq!(imports_block("a.go", "package a\n"), "");
    }

    #[test]
    fn the_language_falls_back_to_the_file_suffix() {
        let site = |language: &str, file: &str| Site {
            language: language.into(),
            file: file.into(),
            ..Site::default()
        };
        assert_eq!(language_of(&site(" Go ", "a.py")), "go");
        assert_eq!(language_of(&site("", "a/B.TSX")), "typescript");
        assert_eq!(language_of(&site("", "Makefile")), "unknown");
        assert_eq!(language_of(&site("", "a.b/c")), "unknown");
    }
}
