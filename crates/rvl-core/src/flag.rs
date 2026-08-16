//! Empty flag VALUES, decided per consumer (po-av01j.192).
//!
//! rvl-cli hands every consumer a plain string. `--flag=` and `--flag ''`
//! both produce `""` (`cliutil.FlagValue` returns the same thing for the two
//! spellings), and the consumer then decides what an empty string means:
//!
//! * a filter guards `if v != ""`, so empty means the flag was never given;
//! * a numeric flag runs `strconv.Atoi("")`, which fails, and exits 2;
//! * a few consumers put the empty string on the wire on purpose
//!   (`risk resolve --reason=` POSTs `{"reason":""}`).
//!
//! clap gives us `Some("")` for both spellings too, which is the same
//! starting point — so parity is a per-consumer decision, exactly as in Go.
//! po-av01j.185 tried to make that decision once for everyone by deleting
//! `--x=` tokens from argv before clap parsed them; argv knows a token's
//! SHAPE and nothing about the flag, so it also deleted the numeric usage
//! errors, the misspelled flags, and the values meant for the wire.
//!
//! These two methods are how a call site states which rule it follows. They
//! are deliberately the only way to get at a flag's value in the ported
//! commands: `.as_deref()` says nothing about empty, while
//! `.empty_is_absent()` / `.empty_is_value()` say which rvl-cli consumer this
//! is, and the reviewer can check it against the Go line.

/// Reading a string flag whose empty value has a decided meaning.
pub trait EmptyFlag {
    /// The rvl-cli consumer guards `if v != ""`: an empty value behaves
    /// EXACTLY as if the flag were never given (no query param, no wire
    /// field, the default applies).
    fn empty_is_absent(&self) -> Option<&str>;

    /// The rvl-cli consumer uses the value as-is: the empty string is a real
    /// value and is transmitted/acted on as one. Use this only where the Go
    /// code has NO `!= ""` guard — an empty value that reaches the wire is a
    /// deliberate parity decision, not an oversight.
    fn empty_is_value(&self) -> Option<&str>;
}

impl EmptyFlag for Option<String> {
    fn empty_is_absent(&self) -> Option<&str> {
        self.as_deref().filter(|s| !s.is_empty())
    }
    fn empty_is_value(&self) -> Option<&str> {
        self.as_deref()
    }
}

impl EmptyFlag for Option<&str> {
    fn empty_is_absent(&self) -> Option<&str> {
        self.filter(|s| !s.is_empty())
    }
    fn empty_is_value(&self) -> Option<&str> {
        *self
    }
}

/// The owned form, for the dispatch sites that re-bind a flag before handing
/// it to a validator that takes `&Option<String>`. Same rule as
/// [`EmptyFlag::empty_is_absent`]: normalize FIRST, so a validator sees the
/// flag the way rvl-cli's guarded `if v != ""` check does — `--format=`
/// renders the default instead of failing enum validation.
#[must_use]
pub fn absent_if_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_treats_empty_as_missing_and_keeps_everything_else() {
        assert_eq!(Some(String::new()).empty_is_absent(), None);
        assert_eq!(None::<String>.empty_is_absent(), None);
        assert_eq!(Some("go".to_string()).empty_is_absent(), Some("go"));
        // Whitespace is NOT empty: rvl-cli compares against "" exactly, so
        // `--service " "` is a (useless) filter in both CLIs, not an absent
        // flag. Trimming here would be a new divergence.
        assert_eq!(Some(" ".to_string()).empty_is_absent(), Some(" "));
    }

    #[test]
    fn value_keeps_the_empty_string() {
        assert_eq!(Some(String::new()).empty_is_value(), Some(""));
        assert_eq!(None::<String>.empty_is_value(), None);
    }

    #[test]
    fn absent_if_empty_matches_the_trait() {
        assert_eq!(absent_if_empty(Some(String::new())), None);
        assert_eq!(absent_if_empty(Some("x".into())), Some("x".to_string()));
        assert_eq!(absent_if_empty(None), None);
    }
}
