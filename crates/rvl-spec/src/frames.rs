//! Decision frames: the questions the decision model answers about a site.
//!
//! The signed spec cache carries them at `specs.frames`, an additive section
//! (no schema bump). A frame belongs to a control and asks one question of
//! one habitat (`call_site`, `config` or `repository`). Its cells are the
//! answers the training labels use, each with a verdict: an `M` cell
//! (`manifestation`) violates, an `S` cell (`satisfying`) satisfies, a `C`
//! cell (`context`) is not applicable.
//!
//! A frame that does not parse is dropped and counted, never fatal: frames
//! come from their own producer, and a malformed one must not cost a scan
//! its specs.

use serde::Deserialize;

/// The habitat of a frame asked of a call site.
pub const CALL_SITE: &str = "call_site";

/// One served frame.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Frame {
    /// `RC-022`.
    pub control: String,
    /// `v2`.
    #[serde(default)]
    pub version: String,
    /// `call_site` | `config` | `repository`.
    pub habitat: String,
    pub question: String,
    #[serde(default)]
    pub cells: Vec<Cell>,
    /// Lower-case substrings of the spec class the frame applies to. Absent
    /// means every class.
    #[serde(default)]
    pub class_markers: Option<Vec<String>>,
}

/// One cell of a frame.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Cell {
    /// `M1`, `S2`, `C1`.
    pub id: String,
    /// `manifestation` | `satisfying` | `context`.
    pub kind: String,
    /// `violates` | `satisfies` | `not_applicable` | `unsure`.
    pub verdict: String,
    pub definition: String,
}

impl Frame {
    /// Whether the frame applies to a site of spec class `class`
    /// (`net/http.Client.Do`).
    pub fn covers_class(&self, class: &str) -> bool {
        match &self.class_markers {
            None => true,
            Some(markers) => {
                let class = class.to_lowercase();
                markers
                    .iter()
                    .any(|m| !m.is_empty() && class.contains(m.as_str()))
            }
        }
    }

    pub fn cell(&self, id: &str) -> Option<&Cell> {
        self.cells.iter().find(|c| c.id == id)
    }
}

#[derive(Default, Deserialize)]
struct Section {
    #[serde(default)]
    frames: Vec<serde_json::Value>,
}

/// The frames of a spec payload, and how many did not parse.
pub fn parse(text: &str) -> (Vec<Frame>, usize) {
    let section: Section = serde_json::from_str(text).unwrap_or_default();
    let total = section.frames.len();
    let frames: Vec<Frame> = section
        .frames
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect();
    let rejected = total - frames.len();
    (frames, rejected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPECS: &str = r#"{"apis":[],"frames":[
        {"control":"RC-022","version":"v2","habitat":"call_site","question":"Retried?",
         "cells":[{"id":"M1","kind":"manifestation","verdict":"violates","definition":"No retry"}],
         "class_markers":["http"],"later_field":1},
        {"control":"RC-019","version":"v1","habitat":"call_site","question":"Bounded?","cells":[]},
        {"control":"RC-001"}
    ]}"#;

    #[test]
    fn frames_parse_and_a_malformed_one_is_counted_not_fatal() {
        let (frames, rejected) = parse(SPECS);
        assert_eq!(frames.len(), 2);
        assert_eq!(rejected, 1);
        assert_eq!(frames[0].cell("M1").unwrap().definition, "No retry");
        assert_eq!(parse(r#"{"apis":[]}"#), (vec![], 0));
    }

    #[test]
    fn class_markers_match_lower_case_substrings_and_absent_matches_all() {
        let (frames, _) = parse(SPECS);
        assert!(frames[0].covers_class("net/HTTP.Client.Do"));
        assert!(!frames[0].covers_class("database/sql.DB.Query"));
        assert!(frames[1].covers_class("anything.At.All"));
    }
}
