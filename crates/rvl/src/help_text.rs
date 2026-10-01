//! Help text is a customer surface, and this module is its gate.
//!
//! Internal issue ids kept reaching `--help`: a doc comment on a clap item IS
//! its help, so a rationale written for the next engineer ("renamed because
//! ..., po-xxxxx.185 item 2") shipped to users, who cannot open the tracker
//! and did not ask why we built it. Same class as the internal-codename rule,
//! and like that rule it only holds if a machine checks it.
//!
//! The rule for authors: `///` on a command, flag or value says what it DOES.
//! Why it exists, and the issue that asked for it, go in a `//` comment
//! beside it, which clap does not read.

#![cfg(test)]

use crate::Cli;
use clap::CommandFactory;

/// The internal issue ids in `text`: `po-` plus five of `[a-z0-9]`, with any
/// `.N` child suffixes, standing as its own token. Matched by hand because
/// this crate does not otherwise need a regex engine.
fn issue_ids(text: &str) -> Vec<String> {
    let b = text.as_bytes();
    let is_id = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let mut found = Vec::new();
    let mut i = 0;
    while let Some(off) = text[i..].find("po-") {
        let start = i + off;
        let mut end = start + 3;
        while end < b.len() && is_id(b[end]) {
            end += 1;
        }
        i = end;
        let own_token =
            start == 0 || !(b[start - 1].is_ascii_alphanumeric() || b[start - 1] == b'-');
        if !own_token || end - (start + 3) != 5 {
            continue;
        }
        // `.208`, `.133.4`: a dot counts only when digits follow it, so the
        // full stop ending a sentence is not swallowed.
        while end + 1 < b.len() && b[end] == b'.' && b[end + 1].is_ascii_digit() {
            end += 1;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
        }
        found.push(text[start..end].to_string());
        i = end;
    }
    found
}

/// Every string of `cmd` that can reach a user, hidden items included (a
/// hidden flag is still printed by shell completions and by `--help` once
/// someone unhides it), then the same for each subcommand.
fn collect(cmd: &clap::Command, path: &str, out: &mut Vec<(String, String)>) {
    let path = if path.is_empty() {
        cmd.get_name().to_string()
    } else {
        format!("{path} {}", cmd.get_name())
    };
    out.push((
        format!("{path} --help"),
        cmd.clone().render_long_help().to_string(),
    ));
    out.push((format!("{path} -h"), cmd.clone().render_help().to_string()));
    for arg in cmd.get_arguments() {
        let values = arg.get_possible_values();
        let texts = [arg.get_help(), arg.get_long_help()]
            .into_iter()
            .flatten()
            .chain(values.iter().filter_map(|v| v.get_help()))
            .map(ToString::to_string);
        for text in texts {
            out.push((format!("{path} <{}>", arg.get_id()), text));
        }
    }
    for sub in cmd.get_subcommands() {
        collect(sub, &path, out);
    }
}

#[test]
fn no_internal_issue_id_reaches_help_output() {
    let mut root = Cli::command();
    root.build();
    let mut surfaces = Vec::new();
    collect(&root, "", &mut surfaces);
    // The walk must actually have descended, or a green result means nothing.
    assert!(
        surfaces.iter().any(|(at, _)| at == "rvl scan --help"),
        "help walk did not reach `rvl scan`"
    );

    let mut leaks: Vec<String> = surfaces
        .iter()
        .flat_map(|(at, text)| {
            issue_ids(text)
                .into_iter()
                .map(move |id| format!("{at}: {id}"))
        })
        .collect();
    leaks.sort();
    leaks.dedup();
    assert!(
        leaks.is_empty(),
        "{} internal issue id(s) in customer-facing help. A `///` comment on a \
         clap item is its help text: say what the item does there, and move \
         the rationale and the issue id to a `//` comment beside it.\n  {}",
        leaks.len(),
        leaks.join("\n  ")
    );
}

#[test]
fn issue_id_matcher_finds_ids_and_only_ids() {
    assert_eq!(
        issue_ids("parity (po-av01j.163), see po-aml3h. And po-av01j.133.4"),
        ["po-av01j.163", "po-aml3h", "po-av01j.133.4"]
    );
    // Not ids: wrong length, part of a longer word, uppercase.
    assert!(issue_ids("po-tab repo-av01j typo-av01j po-av01jx PO-AV01J po-").is_empty());
}
