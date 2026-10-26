//! The decision model's input text.
//!
//! The model was trained on text written by a reference renderer
//! (`testdata/render-goldens/prepare.py`, `render_input`), and it must see
//! the same text at scan time, byte for byte: an input it was not trained on
//! is a silent drift in its decisions. [`render_input`] writes that text from
//! what rvl has at a site: the export fields of the site ([`Site`]), the
//! retriever's site packet ([`SitePacket`]) and the question asked of it
//! ([`Question`]: the bound question, or a served frame's).
//!
//! The reference counts length caps in Unicode code points and collapses and
//! strips whitespace by Python's definition of it; so does this module.
//! The goldens test (`tests/render_goldens.rs`) holds the two to the same
//! bytes and the same token ids.

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
