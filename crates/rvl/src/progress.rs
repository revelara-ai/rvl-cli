//! The status line `rvl scan` draws on stderr while it runs: a spinner, the
//! step it is on and the seconds since it started, with the decision model's
//! question count while the model runs:
//!
//! ```text
//! ⠋ Running the decision model: 96/312 questions (41s)
//! ```
//!
//! The scan makes one handle and passes it down. Anything the scan prints
//! while the line is drawn goes through [`ProgressBar::suspend`], so it lands
//! on its own line.

use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressFinish, ProgressState, ProgressStyle};

/// The handle for one scan. When stderr is not a terminal (a git hook, CI, a
/// pipe) it is hidden and draws nothing, so stderr is what it would be
/// without it. Dropped, it clears its line, so an error does not print after
/// a stale one.
pub fn scan() -> ProgressBar {
    let style = ProgressStyle::with_template("{spinner} {msg}{questions} ({secs}s)")
        .expect("the status line's template parses")
        .with_key(
            "questions",
            |s: &ProgressState, w: &mut dyn std::fmt::Write| {
                if let Some(len) = s.len() {
                    let _ = write!(w, ": {}/{len} questions", s.pos());
                }
            },
        )
        .with_key("secs", |s: &ProgressState, w: &mut dyn std::fmt::Write| {
            let _ = write!(w, "{}", s.elapsed().as_secs());
        });
    ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr())
        .with_style(style)
        .with_finish(ProgressFinish::AndClear)
}

/// Name the step the scan is on, and keep the line moving while it runs.
pub fn step(progress: &ProgressBar, name: &'static str) {
    progress.set_message(name);
    progress.unset_length();
    if !progress.is_hidden() {
        progress.enable_steady_tick(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::IsTerminal;

    #[test]
    fn the_status_line_is_hidden_when_stderr_is_not_a_terminal() {
        let progress = scan();
        assert_eq!(progress.is_hidden(), !std::io::stderr().is_terminal());
        if !std::io::stderr().is_terminal() {
            // A scan under a test harness, a hook or CI: nothing is drawn.
            step(&progress, "Retrieving call sites");
            assert!(progress.is_hidden());
        }
    }
}
