//! Generated protobuf builder sites: message construction, not a client call.
//!
//! Hand-written Java that builds a protobuf message calls the generated
//! class's static factory, `Ad.newBuilder().setText(..).build()`. The java
//! retriever attributes `Ad` through its import and reports
//! `hipstershop.Demo.Ad.newBuilder` as a call site, which no spec will ever
//! decide: building a message does no I/O. Each one is an undecided surface
//! that lowers coverage and reads as noise.
//!
//! The generated classes are usually built by protoc during the build and are
//! not in the repository, so the generated-file banner rule cannot see them.
//! The `.proto` files that declare the messages ARE in the repository. This
//! module reads them, derives the Java class name protoc gives each message,
//! and drops a `newBuilder*` site whose receiver is one of those classes.
//!
//! THE CHAIN GOES WITH ITS ROOT. Without the generated classes on the
//! classpath the retriever cannot type `Ad.newBuilder()`, so each link of the
//! fluent chain on it (`.setText(..)`, `.build()`) is a site of its own whose
//! receiver is the chain's text attributed through the import,
//! `hipstershop.Demo.Ad.newBuilder.setText`. With the classes present the
//! receiver is protoc's `Ad.Builder`. Both are dropped with the root; the
//! count is of builder chains, one per `newBuilder*` call.
//!
//! EVIDENCE, NOT NAME GUESSING. A `newBuilder` on a type no `.proto` here
//! declares is kept: it may be a client's builder, and the retriever's
//! builder rules own that case.

use std::collections::HashSet;
use std::path::Path;

/// Drop the `newBuilder*` sites on protobuf message classes declared by the
/// repository's `.proto` files, and the links of the fluent chain on each,
/// returning the filtered stream and the number of builder chains dropped.
/// The `.proto` files are read only when the stream holds a candidate, so a
/// repository without one pays nothing.
pub fn strip_proto_builder_packets(text: &str, root: &Path) -> (String, usize) {
    let mut messages: Option<HashSet<String>> = None;
    let mut kept = String::with_capacity(text.len());
    let mut dropped = 0usize;
    for line in text.lines() {
        if line.contains("newBuilder") || line.contains(".Builder\"") {
            if let Some((client_type, func)) = java_call_site(line) {
                let messages = messages.get_or_insert_with(|| proto_message_classes(root));
                if func.starts_with("newBuilder") && messages.contains(&client_type) {
                    dropped += 1;
                    continue;
                }
                if builder_chain_message(&client_type).is_some_and(|m| messages.contains(m)) {
                    continue;
                }
            }
        }
        kept.push_str(line);
        kept.push('\n');
    }
    (kept, dropped)
}

/// The receiver class and method of a Java call site.
fn java_call_site(line: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or_default();
    let call_site = s("site_kind").is_empty() && s("lang") == "java";
    call_site.then(|| (s("client_type").to_string(), s("func").to_string()))
}

/// The message class a chain link's receiver builds: `M` for protoc's
/// `M.Builder`, or for the untyped chain text `M.newBuilder[.link]*`.
fn builder_chain_message(client_type: &str) -> Option<&str> {
    if let Some(m) = client_type.strip_suffix(".Builder") {
        return Some(m);
    }
    let (m, rest) = client_type.split_once(".newBuilder")?;
    // `newBuilder` or a `newBuilder*` overload, then the end or a link.
    let factory = rest.split('.').next().unwrap_or_default();
    factory.chars().all(char::is_alphanumeric).then_some(m)
}

/// The Java class of every message declared by a `.proto` file under `root`.
fn proto_message_classes(root: &Path) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(ft) = entry.file_type() else { continue };
            let path = entry.path();
            if ft.is_dir() {
                if !crate::SKIP_DIRS.contains(&entry.file_name().to_string_lossy().as_ref()) {
                    stack.push(path);
                }
            } else if ft.is_file() && path.extension().is_some_and(|e| e == "proto") {
                let stem = path.file_stem().unwrap_or_default().to_string_lossy();
                if let Ok(src) = std::fs::read_to_string(&path) {
                    out.extend(java_message_classes(&stem, &src));
                }
            }
        }
    }
    out
}

/// The Java class protoc generates for each message of one `.proto` file:
/// `<java package>[.<outer class>].<Message>[.<Nested>]`. The outer class is
/// left out under `java_multiple_files`; it is `java_outer_classname`, or the
/// file name in camel case, with `OuterClass` appended when a top-level type
/// already has that name.
fn java_message_classes(stem: &str, src: &str) -> Vec<String> {
    let tokens = tokenize(src);
    let mut package = String::new();
    let mut java_package = None;
    let mut outer = None;
    let mut multiple_files = false;
    let mut top_level = HashSet::new();
    // Message paths, outermost first; and the open blocks, `Some(name)` for
    // a message, `None` for anything else (enum, service, oneof, extend).
    let mut messages: Vec<Vec<String>> = Vec::new();
    let mut open: Vec<Option<String>> = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        let next = |k: usize| tokens.get(i + k).map(String::as_str).unwrap_or_default();
        match t {
            "{" => open.push(None),
            "}" => {
                open.pop();
            }
            "package" if open.is_empty() => package = next(1).to_string(),
            "option" if open.is_empty() && next(2) == "=" => {
                let value = next(3).trim_matches('"').to_string();
                match next(1) {
                    "java_package" => java_package = Some(value),
                    "java_outer_classname" => outer = Some(value),
                    "java_multiple_files" => multiple_files = value == "true",
                    _ => {}
                }
            }
            "message" | "enum" | "service" if next(2) == "{" => {
                let name = next(1).to_string();
                if open.is_empty() {
                    top_level.insert(name.clone());
                }
                if t == "message" && open.iter().all(Option::is_some) {
                    let mut path: Vec<String> = open.iter().flatten().cloned().collect();
                    path.push(name.clone());
                    messages.push(path);
                    open.push(Some(name));
                } else {
                    open.push(None);
                }
                i += 3;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    let mut prefix = java_package.unwrap_or(package);
    if !multiple_files {
        let mut outer = outer.unwrap_or_else(|| camel_case(stem));
        if top_level.contains(&outer) {
            outer.push_str("OuterClass");
        }
        if !prefix.is_empty() {
            prefix.push('.');
        }
        prefix.push_str(&outer);
    }
    messages
        .into_iter()
        .map(|path| {
            let name = path.join(".");
            if prefix.is_empty() {
                name
            } else {
                format!("{prefix}.{name}")
            }
        })
        .collect()
}

/// protoc's file-name-to-class rule: `ad_service.proto` is `AdService`, a
/// letter after a digit or a separator is upper case.
fn camel_case(stem: &str) -> String {
    let mut out = String::new();
    let mut upper = true;
    for c in stem.chars() {
        if c.is_ascii_alphabetic() {
            out.push(if upper { c.to_ascii_uppercase() } else { c });
            upper = false;
        } else if c.is_ascii_digit() {
            out.push(c);
            upper = true;
        } else {
            upper = true;
        }
    }
    out
}

/// The tokens of a `.proto` file with its comments removed: words (dotted
/// names and numbers included), quoted strings, and one-character symbols.
fn tokenize(src: &str) -> Vec<String> {
    let chars: Vec<char> = src.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let after = char_at(&chars, i + 1);
        if c == '/' && after == '/' {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && after == '*' {
            i += 2;
            while i < chars.len() && !(chars[i] == '*' && char_at(&chars, i + 1) == '/') {
                i += 1;
            }
            i += 2;
        } else if c == '"' || c == '\'' {
            let start = i;
            i += 1;
            while i < chars.len() && chars[i] != c {
                i += if chars[i] == '\\' { 2 } else { 1 };
            }
            i += 1;
            out.push(chars[start..i.min(chars.len())].iter().collect());
        } else if c.is_alphanumeric() || c == '_' || c == '.' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || matches!(chars[i], '_' | '.')) {
                i += 1;
            }
            out.push(chars[start..i].iter().collect());
        } else {
            if !c.is_whitespace() {
                out.push(c.to_string());
            }
            i += 1;
        }
    }
    out
}

fn char_at(chars: &[char], i: usize) -> char {
    chars.get(i).copied().unwrap_or('\0')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../helpers/javaindex/testdata/fixture_proto")
    }

    fn site(client_type: &str, func: &str) -> String {
        serde_json::json!({
            "site_key": "k",
            "file_path": "src/main/java/hipstershop/AdService.java",
            "func": func,
            "client_type": client_type,
            "site_kind": "",
            "lang": "java",
        })
        .to_string()
    }

    #[test]
    fn the_default_outer_class_is_the_file_name() {
        let src = "syntax = \"proto3\";\npackage hipstershop;\n\
                   message Ad { string text = 1; }\n\
                   message AdResponse { repeated Ad ads = 1; }";
        let mut got = java_message_classes("demo", src);
        got.sort();
        assert_eq!(got, ["hipstershop.Demo.Ad", "hipstershop.Demo.AdResponse"]);
    }

    #[test]
    fn java_options_nesting_and_comments_shape_the_class() {
        let src = r#"
            // message Commented { }
            /* message Blocked { } */
            package shop.v1;
            option java_package = "com.shop.proto";
            option java_outer_classname = "ShopProtos";
            message Order {
                message Line { int32 qty = 1; }
                enum State { OPEN = 0; }
                oneof pay { string card = 2; }
            }
            service Orders { rpc Get(Order) returns (Order) {} }
        "#;
        let mut got = java_message_classes("shop", src);
        got.sort();
        assert_eq!(
            got,
            [
                "com.shop.proto.ShopProtos.Order",
                "com.shop.proto.ShopProtos.Order.Line"
            ]
        );
    }

    #[test]
    fn multiple_files_drops_the_outer_class_and_a_clash_renames_it() {
        let multi = "package p; option java_multiple_files = true; message Ad {}";
        assert_eq!(java_message_classes("demo", multi), ["p.Ad"]);
        let clash = "package p; message AdService {}";
        assert_eq!(
            java_message_classes("ad_service", clash),
            ["p.AdServiceOuterClass.AdService"]
        );
    }

    #[test]
    fn camel_case_follows_protoc() {
        assert_eq!(camel_case("ad_service"), "AdService");
        assert_eq!(camel_case("v2beta1-api"), "V2Beta1Api");
    }

    /// The fixture's AdService.java calls `Ad.newBuilder()...build()`; the
    /// javaindex packet for that call is dropped, the vendor client's builder
    /// and a method that is not a builder factory are kept.
    #[test]
    fn a_message_builder_site_is_dropped_and_others_are_kept() {
        let stream = [
            site("hipstershop.Demo.Ad", "newBuilder"),
            site("hipstershop.Demo.AdResponse", "newBuilder"),
            site("com.acme.vendor.Widget", "newBuilder"),
            site("hipstershop.Demo.Ad", "getText"),
            r#"{"kind":"repo_config"}"#.to_string(),
        ]
        .join("\n");
        let (kept, dropped) = strip_proto_builder_packets(&stream, &fixture());
        assert_eq!(dropped, 2, "{kept}");
        assert!(!kept.contains("hipstershop.Demo.AdResponse"), "{kept}");
        assert!(kept.contains("com.acme.vendor.Widget"), "{kept}");
        assert!(kept.contains("getText"), "{kept}");
        assert!(kept.contains("repo_config"), "{kept}");
    }

    /// Untyped, each link of `Ad.newBuilder().setText(..).build()` is a site
    /// on the chain text; typed, on protoc's `Ad.Builder`. Both go with the
    /// root and are not counted again; the vendor builder's chain stays.
    #[test]
    fn the_links_of_a_message_builder_chain_go_with_it() {
        let stream = [
            site("hipstershop.Demo.Ad", "newBuilder"),
            site("hipstershop.Demo.Ad.newBuilder", "setRedirectUrl"),
            site("hipstershop.Demo.Ad.newBuilder.setRedirectUrl", "setText"),
            site(
                "hipstershop.Demo.Ad.newBuilder.setRedirectUrl.setText",
                "build",
            ),
            site("hipstershop.Demo.AdResponse.Builder", "build"),
            site("com.acme.vendor.Widget.newBuilder", "build"),
            site("com.acme.vendor.Widget.Builder", "build"),
            site("hipstershop.Demo.Adx.newBuilder", "build"),
        ]
        .join("\n");
        let (kept, dropped) = strip_proto_builder_packets(&stream, &fixture());
        assert_eq!(dropped, 1, "{kept}");
        assert!(!kept.contains("hipstershop.Demo.Ad."), "{kept}");
        assert!(!kept.contains("hipstershop.Demo.AdResponse"), "{kept}");
        assert_eq!(kept.matches("com.acme.vendor.Widget").count(), 2, "{kept}");
        assert!(kept.contains("hipstershop.Demo.Adx.newBuilder"), "{kept}");
    }

    #[test]
    fn a_site_of_another_kind_or_language_is_kept() {
        let mut job = site("hipstershop.Demo.Ad", "newBuilder");
        job = job.replace(
            "\"site_kind\":\"\"",
            "\"site_kind\":\"unsized_construction\"",
        );
        let kotlin = site("hipstershop.Demo.Ad", "newBuilder").replace("java", "kotlin");
        let (_, dropped) = strip_proto_builder_packets(&format!("{job}\n{kotlin}"), &fixture());
        assert_eq!(dropped, 0);
    }
}
