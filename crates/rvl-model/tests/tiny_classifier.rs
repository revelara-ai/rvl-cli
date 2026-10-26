//! Inference on the tiny classifier fixture through a real ONNX Runtime.
//!
//! The fixture (`testdata/tiny-classifier/`) is written by
//! `testdata/make_tiny_classifier.py`. The runtime is the pinned library
//! `ci/fetch-onnxruntime.sh` lays out beside the test binaries
//! (`target/<profile>/onnxruntime/`), or the one `RVL_ONNXRUNTIME` names.
//! Without either, each test skips through `rvl-testgate`, which fails it
//! under `RVLSCAN_REQUIRE_ENGINES` (CI).

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use rvl_model::runtime::{self, Source};
use rvl_model::{AbstainReason, Bundle, Classifier, Options, Runtime, Verdict};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/tiny-classifier")
}

/// The runtime for this test process, or `None` after a SKIP line.
fn runtime(test: &str) -> Option<&'static Runtime> {
    let source = match std::env::var_os(runtime::OVERRIDE_ENV).filter(|v| !v.is_empty()) {
        Some(p) => Source::Override(PathBuf::from(p)),
        None => {
            // target/<profile>/deps/<test> -> target/<profile>/onnxruntime/
            let exe = std::env::current_exe().unwrap();
            let lib = exe
                .parent()
                .and_then(|deps| deps.parent())
                .map(|profile| profile.join(runtime::BUNDLE_DIR).join(runtime::LIB_NAME));
            match lib.filter(|l| l.is_file()) {
                Some(lib) => Source::Vendored(lib),
                None => {
                    rvl_testgate::skip(
                        test,
                        format_args!(
                            "no ONNX Runtime: run ci/fetch-onnxruntime.sh <host-triple> \
                             target/debug, or set {}",
                            runtime::OVERRIDE_ENV
                        ),
                    );
                    return None;
                }
            }
        }
    };
    Some(runtime::load(&source).unwrap_or_else(|e| panic!("{test}: {e:#}")))
}

fn classifier(rt: &Runtime, threads: usize, batch_size: usize) -> Classifier {
    let bundle = Bundle::load(&fixture_dir()).unwrap();
    Classifier::new(
        rt,
        bundle,
        Options {
            threads,
            batch_size,
        },
    )
    .unwrap()
}

const TEXTS: &[&str] = &[
    "http get with timeout and deadline",
    "client call will block forever",
    "retry with a budget",
    "wait in a loop no limit",
    "the call",
    "",
    "CANCEL the context",
    "sleep sleep hang infinite",
    "unknown words only here",
    "a mock client in a test fixture",
];

#[test]
fn the_same_inputs_twice_give_byte_identical_records() {
    let Some(rt) = runtime("the_same_inputs_twice_give_byte_identical_records") else {
        return;
    };
    let mut c = classifier(rt, 4, 4);
    let first = serde_json::to_vec(&c.classify(TEXTS, Duration::from_secs(600)).unwrap()).unwrap();
    let again = serde_json::to_vec(&c.classify(TEXTS, Duration::from_secs(600)).unwrap()).unwrap();
    assert_eq!(first, again, "a second run on the same classifier");
    // A fresh session over the same bundle, too.
    let mut fresh = classifier(rt, 4, 4);
    let third =
        serde_json::to_vec(&fresh.classify(TEXTS, Duration::from_secs(600)).unwrap()).unwrap();
    assert_eq!(first, third, "a fresh session");
}

#[test]
fn one_thread_and_four_threads_give_the_same_verdicts() {
    let Some(rt) = runtime("one_thread_and_four_threads_give_the_same_verdicts") else {
        return;
    };
    let one = classifier(rt, 1, 4)
        .classify(TEXTS, Duration::from_secs(600))
        .unwrap();
    let four = classifier(rt, 4, 4)
        .classify(TEXTS, Duration::from_secs(600))
        .unwrap();
    let verdicts = |c: &rvl_model::Classification| -> Vec<Verdict> {
        c.records.iter().map(|r| r.verdict.clone()).collect()
    };
    assert_eq!(verdicts(&one), verdicts(&four));
    assert_eq!(one.coverage.abstained, 0);
}

#[test]
fn a_record_does_not_depend_on_its_batch() {
    let Some(rt) = runtime("a_record_does_not_depend_on_its_batch") else {
        return;
    };
    let alone: Vec<_> = TEXTS
        .iter()
        .map(|t| {
            let mut c = classifier(rt, 4, 1);
            c.classify(&[t], Duration::from_secs(600))
                .unwrap()
                .records
                .remove(0)
        })
        .collect();
    let batched = classifier(rt, 4, 4)
        .classify(TEXTS, Duration::from_secs(600))
        .unwrap();
    assert_eq!(
        serde_json::to_string(&alone).unwrap(),
        serde_json::to_string(&batched.records).unwrap()
    );
}

#[test]
fn records_carry_the_label_the_fixture_was_built_to_give() {
    let Some(rt) = runtime("records_carry_the_label_the_fixture_was_built_to_give") else {
        return;
    };
    let got = classifier(rt, 4, 8)
        .classify(TEXTS, Duration::from_secs(600))
        .unwrap();
    let label = |i: usize| match &got.records[i].verdict {
        Verdict::Label(l) => l.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(label(0), "satisfies");
    assert_eq!(label(1), "violates");
    assert_eq!(label(6), "satisfies", "the tokenizer lowercases");
    assert_eq!(label(7), "violates");
    assert_eq!(label(8), "abstain", "no signal word");
    assert_eq!(label(9), "not_applicable");

    let model = std::fs::read(fixture_dir().join("model.onnx")).unwrap();
    let digest = {
        use sha2::Digest as _;
        format!("sha256:{}", hex::encode(sha2::Sha256::digest(&model)))
    };
    for r in &got.records {
        assert_eq!(r.model_id, "rvl-fixture/tiny-classifier");
        assert_eq!(r.weights_digest, digest);
        assert_eq!(r.logits.len(), 4);
        assert_eq!(r.cell_logits.len(), 4, "the fixture has a cell head");
        let (_, p) = rvl_model::classify::calibrate(&r.logits, 1.5);
        assert_eq!(
            r.confidence,
            Some(p),
            "confidence is calibrated at temperature 1.5"
        );
        assert!((0.25..=1.0).contains(&p), "{p}");
    }
    assert_eq!(got.coverage.line(), None);
}

#[test]
fn the_cell_head_names_the_cell_of_the_verdict() {
    let Some(rt) = runtime("the_cell_head_names_the_cell_of_the_verdict") else {
        return;
    };
    let mut c = classifier(rt, 4, 8);
    let ids = c.cells().expect("the fixture has a cell head").to_vec();
    assert_eq!(ids, ["M1", "M2", "S1", "C1"]);
    let got = c.classify(TEXTS, Duration::from_secs(600)).unwrap();
    let top = |i: usize, allowed: &[&str]| {
        rvl_model::classify::top_cell(&ids, &got.records[i].cell_logits, allowed)
            .map(|at| ids[at].as_str())
    };
    assert_eq!(top(1, &["M1", "M2", "S1", "C1"]), Some("M1"));
    assert_eq!(
        top(1, &["M2", "S1"]),
        Some("M2"),
        "masked to the frame's cells"
    );
    assert_eq!(top(0, &["M1", "M2", "S1", "C1"]), Some("S1"));
    assert_eq!(top(9, &["M1", "M2", "S1", "C1"]), Some("C1"));
}

#[test]
fn the_time_budget_marks_the_remainder_abstain() {
    let Some(rt) = runtime("the_time_budget_marks_the_remainder_abstain") else {
        return;
    };
    let mut c = classifier(rt, 4, 2);
    // The budget allows two batches of two, then runs out.
    let mut asked = 0;
    let got = c
        .classify_until(TEXTS, || {
            asked += 1;
            asked > 2
        })
        .unwrap();
    assert_eq!(got.records.len(), TEXTS.len());
    assert_eq!(
        (got.coverage.inferred, got.coverage.abstained),
        (4, TEXTS.len() - 4)
    );
    for (i, r) in got.records.iter().enumerate() {
        if i < 4 {
            assert!(matches!(r.verdict, Verdict::Label(_)), "{i}: {r:?}");
        } else {
            assert_eq!(
                r.verdict,
                Verdict::Abstain(AbstainReason::TimeBudget),
                "{i}"
            );
            assert_eq!(r.confidence, None);
            assert!(r.logits.is_empty());
            assert_eq!(r.model_id, "rvl-fixture/tiny-classifier");
        }
    }
    assert!(got
        .coverage
        .line()
        .unwrap()
        .starts_with("6 of 10 model input(s) abstain"));

    // A spent budget reaches nothing, and the line names it.
    let none = c.classify(TEXTS, Duration::ZERO).unwrap();
    assert_eq!(none.coverage.abstained, TEXTS.len());
    assert!(
        none.coverage
            .line()
            .unwrap()
            .contains("the 0 ms model time budget"),
        "{:?}",
        none.coverage.line()
    );
}

#[test]
fn the_committed_fixture_is_what_its_script_writes() {
    let test = "the_committed_fixture_is_what_its_script_writes";
    let tmp = tempfile::tempdir().unwrap();
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/make_tiny_classifier.py");
    let ran = Command::new("python3")
        .arg("-I")
        .arg(&script)
        .arg(tmp.path())
        .status();
    match ran {
        Ok(s) => assert!(s.success(), "{} failed: {s}", script.display()),
        Err(e) => {
            rvl_testgate::skip(test, format_args!("python3 did not start: {e}"));
            return;
        }
    }
    for name in ["model.onnx", "tokenizer.json", "bundle.json", "cells.json"] {
        assert_eq!(
            std::fs::read(tmp.path().join(name)).unwrap(),
            std::fs::read(fixture_dir().join(name)).unwrap(),
            "{name} differs from what the script writes; rerun it and commit the output"
        );
    }
}
