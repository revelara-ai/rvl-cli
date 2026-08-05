//! Surface-only stub of tracing: macro-based emission, the shape that makes
//! Rust the first language to genuinely populate `macro_expansion`.

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::dispatch("info")
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::dispatch("error")
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::dispatch("warn")
    };
}

pub fn dispatch(_level: &str) {}

pub struct Span;

pub fn info_span(_name: &str) -> Span {
    Span
}
