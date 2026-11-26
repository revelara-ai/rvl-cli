//! What the log retention facts (RC-028) of the Terraform and Loki
//! retrievers share beyond [`crate::non_production`]: the directories that
//! hold evaluation fixtures.
//!
//! A log store under an eval or evals tree is evidence a grader reads, not a
//! store anything ships logs to, so its retention is no fact about a
//! deployment. The shared classifier covers `benchmark` and `benchmarks`
//! already ([`crate::non_production::path_token`]); this list adds only the
//! eval names, and only for the retention facts.

/// Directory tokens of an evaluation fixture tree. A directory segment is
/// split on every non-alphanumeric character and lower-cased; a whole token
/// listed here marks the file. The file stem is not read: a module named
/// `evaluation.tf` deploys like any other.
pub const EVAL_DIR_TOKENS: &[&str] = &["eval", "evals", "evaluation", "evaluations"];

/// The [`EVAL_DIR_TOKENS`] token of `rel_path`'s directory, if any.
pub fn eval_dir_token(rel_path: &str) -> Option<&'static str> {
    let dir = rel_path.rsplit_once('/').map_or("", |(dir, _)| dir);
    dir.split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .find_map(|t| {
            EVAL_DIR_TOKENS
                .iter()
                .copied()
                .find(|w| w.eq_ignore_ascii_case(t))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_eval_directory_token_marks_the_file_and_the_stem_does_not() {
        assert_eq!(
            eval_dir_token("evals/case-3/evidence/main.tf"),
            Some("evals")
        );
        assert_eq!(
            eval_dir_token("ops/Model-Evaluation/loki.yaml"),
            Some("evaluation")
        );
        assert_eq!(eval_dir_token("infra/logging/evaluation.tf"), None);
        assert_eq!(eval_dir_token("infra/medieval/main.tf"), None);
        assert_eq!(eval_dir_token("main.tf"), None);
    }
}
