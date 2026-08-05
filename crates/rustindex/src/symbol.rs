//! SCIP symbol parsing for rust-analyzer monikers.
//!
//! rust-analyzer stamps every occurrence with a symbol of the form
//! `rust-analyzer cargo <crate> <version> <descriptor>`, where the descriptor
//! encodes the path: `pool/impl#[PoolOptions]acquire_timeout().` is the
//! inherent method, `impl#[PgPool][Executor]execute().` is a trait method
//! resolved to its impl (concrete receiver), `Executor#execute().` is the
//! trait method itself (dyn or generic dispatch — the moniker alone cannot
//! tell those apart, see the moniker fixture test), and `info!` is a macro.
//!
//! Names may be backtick-escaped and can then contain spaces
//! (`` result/impl#[`Result<T, E>`][Try]branch(). ``), so the descriptor is
//! everything after the fourth space-separated field, and name reading is
//! quote-aware.

/// What the terminal descriptor of a symbol denotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// `name().` preceded by a type or impl descriptor.
    Method,
    /// `name().` preceded only by namespaces.
    Function,
    /// `name!`.
    Macro,
    /// `name#` as the terminal descriptor.
    Type,
}

/// A parsed rust-analyzer moniker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSymbol {
    pub crate_name: String,
    pub crate_version: String,
    pub kind: SymbolKind,
    /// Leading namespace segments (`pool` in `pool/impl#[PoolOptions]new().`).
    pub module_path: Vec<String>,
    /// Terminal name: the method, function, macro, or type name.
    pub name: String,
    /// `impl#[SelfType]…` — the concrete self type when resolved to an impl.
    pub self_type: Option<String>,
    /// `impl#[SelfType][Trait]…` — the trait the impl implements, when the
    /// method reached the impl through a trait.
    pub via_trait: Option<String>,
    /// `Owner#name().` — the declaring type/trait when NOT resolved to an
    /// impl. For method calls this is trait-level dispatch (dyn or generic).
    pub owner_type: Option<String>,
}

impl ParsedSymbol {
    /// `crate::mod1::mod2` — the crate-qualified module path.
    pub fn crate_module_path(&self) -> String {
        let mut s = self.crate_name.clone();
        for m in &self.module_path {
            s.push_str("::");
            s.push_str(m);
        }
        s
    }

    /// The crate-qualified path of the concrete self type, when present.
    pub fn self_type_path(&self) -> Option<String> {
        self.self_type
            .as_ref()
            .map(|t| format!("{}::{}", self.crate_module_path(), t))
    }

    /// The crate-qualified path of the declaring type/trait, when present.
    pub fn owner_type_path(&self) -> Option<String> {
        self.owner_type
            .as_ref()
            .map(|t| format!("{}::{}", self.crate_module_path(), t))
    }
}

/// One descriptor token.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Namespace(String),
    Type(String),
    Term(String),
    Method(String),
    Macro(String),
    TypeParam(String),
}

/// Read a possibly-backtick-quoted name starting at `chars[i]`; returns
/// (name, next index). A quoted name may contain any character but a backtick.
fn read_name(chars: &[char], mut i: usize) -> (String, usize) {
    let mut name = String::new();
    if i < chars.len() && chars[i] == '`' {
        i += 1;
        while i < chars.len() && chars[i] != '`' {
            name.push(chars[i]);
            i += 1;
        }
        i += 1; // closing backtick
        return (name, i);
    }
    while i < chars.len() && !matches!(chars[i], '/' | '#' | '.' | '!' | '(' | '[' | ']') {
        name.push(chars[i]);
        i += 1;
    }
    (name, i)
}

/// Tokenize a descriptor string. Unknown shapes yield `None` (skip, never
/// guess: a moniker this parser does not understand must not become a site).
fn tokenize(desc: &str) -> Option<Vec<Tok>> {
    let chars: Vec<char> = desc.chars().collect();
    let mut toks = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '[' {
            let (name, ni) = read_name(&chars, i + 1);
            i = ni;
            if i >= chars.len() || chars[i] != ']' {
                return None;
            }
            i += 1;
            toks.push(Tok::TypeParam(name));
            continue;
        }
        let (name, ni) = read_name(&chars, i);
        i = ni;
        if name.is_empty() {
            return None;
        }
        if i >= chars.len() {
            return None; // descriptor must end with a suffix character
        }
        match chars[i] {
            '/' => {
                toks.push(Tok::Namespace(name));
                i += 1;
            }
            '#' => {
                toks.push(Tok::Type(name));
                i += 1;
            }
            '!' => {
                toks.push(Tok::Macro(name));
                i += 1;
            }
            '.' => {
                toks.push(Tok::Term(name));
                i += 1;
            }
            '(' => {
                // method: `name(<optional disambiguator>).`
                while i < chars.len() && chars[i] != ')' {
                    i += 1;
                }
                if i + 1 >= chars.len() || chars[i + 1] != '.' {
                    return None;
                }
                i += 2;
                toks.push(Tok::Method(name));
            }
            _ => return None,
        }
    }
    Some(toks)
}

/// Parse a full rust-analyzer SCIP symbol. Returns `None` for local symbols,
/// non-cargo schemes, and descriptor shapes this consumer does not recognize.
pub fn parse(symbol: &str) -> Option<ParsedSymbol> {
    if symbol.starts_with("local ") {
        return None;
    }
    // scheme manager crate version descriptor — descriptor may contain spaces
    // (backtick-escaped names), so split off exactly four fields.
    let mut parts = symbol.splitn(5, ' ');
    let scheme = parts.next()?;
    let manager = parts.next()?;
    let crate_name = parts.next()?.to_string();
    let crate_version = parts.next()?.to_string();
    let desc = parts.next()?;
    if scheme != "rust-analyzer" || manager != "cargo" {
        return None;
    }
    let toks = tokenize(desc)?;
    let terminal = toks.last()?.clone();

    let mut module_path = Vec::new();
    // Namespaces before any type/impl descriptor form the module path.
    for t in &toks {
        match t {
            Tok::Namespace(n) => module_path.push(n.clone()),
            _ => break,
        }
    }

    match terminal {
        Tok::Macro(name) => Some(ParsedSymbol {
            crate_name,
            crate_version,
            kind: SymbolKind::Macro,
            module_path,
            name,
            self_type: None,
            via_trait: None,
            owner_type: None,
        }),
        Tok::Type(name) => Some(ParsedSymbol {
            crate_name,
            crate_version,
            kind: SymbolKind::Type,
            module_path,
            name,
            self_type: None,
            via_trait: None,
            owner_type: None,
        }),
        Tok::Method(name) => {
            // Walk the tokens before the method: an `impl` type descriptor
            // carries [SelfType] and optionally [Trait]; a plain type
            // descriptor is the declaring type/trait.
            let mut self_type = None;
            let mut via_trait = None;
            let mut owner_type = None;
            let mut after_impl = false;
            for t in &toks[..toks.len() - 1] {
                match t {
                    Tok::Type(n) if n == "impl" => {
                        after_impl = true;
                        self_type = None;
                        via_trait = None;
                    }
                    Tok::Type(n) => {
                        owner_type = Some(n.clone());
                        after_impl = false;
                    }
                    Tok::TypeParam(n) if after_impl => {
                        if self_type.is_none() {
                            self_type = Some(n.clone());
                        } else if via_trait.is_none() {
                            via_trait = Some(n.clone());
                        }
                    }
                    _ => {}
                }
            }
            let kind = if self_type.is_some() || owner_type.is_some() {
                SymbolKind::Method
            } else {
                SymbolKind::Function
            };
            Some(ParsedSymbol {
                crate_name,
                crate_version,
                kind,
                module_path,
                name,
                self_type,
                via_trait,
                owner_type,
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inherent_method_carries_the_self_type() {
        let p = parse("rust-analyzer cargo reqwest 0.11.0 impl#[Client]get().").unwrap();
        assert_eq!(p.crate_name, "reqwest");
        assert_eq!(
            p.crate_version, "0.11.0",
            "the moniker's crate version is provenance a future migration needs"
        );
        assert_eq!(p.kind, SymbolKind::Method);
        assert_eq!(p.name, "get");
        assert_eq!(p.self_type.as_deref(), Some("Client"));
        assert_eq!(p.via_trait, None);
        assert_eq!(p.self_type_path().as_deref(), Some("reqwest::Client"));
    }

    #[test]
    fn trait_impl_method_carries_self_type_and_trait() {
        let p = parse("rust-analyzer cargo sqlx 0.7.0 impl#[PgPool][Executor]execute().").unwrap();
        assert_eq!(p.kind, SymbolKind::Method);
        assert_eq!(p.name, "execute");
        assert_eq!(p.self_type.as_deref(), Some("PgPool"));
        assert_eq!(p.via_trait.as_deref(), Some("Executor"));
    }

    #[test]
    fn trait_method_decl_is_owner_typed_not_self_typed() {
        let p = parse("rust-analyzer cargo sqlx 0.7.0 Executor#execute().").unwrap();
        assert_eq!(p.kind, SymbolKind::Method);
        assert_eq!(p.self_type, None);
        assert_eq!(p.owner_type.as_deref(), Some("Executor"));
        assert_eq!(p.owner_type_path().as_deref(), Some("sqlx::Executor"));
    }

    #[test]
    fn module_scoped_free_function() {
        let p = parse("rust-analyzer cargo tokio 1.0.0 task/spawn_blocking().").unwrap();
        assert_eq!(p.kind, SymbolKind::Function);
        assert_eq!(p.name, "spawn_blocking");
        assert_eq!(p.module_path, vec!["task".to_string()]);
        assert_eq!(p.crate_module_path(), "tokio::task");
    }

    #[test]
    fn crate_root_free_function() {
        let p = parse("rust-analyzer cargo tokio 1.0.0 spawn().").unwrap();
        assert_eq!(p.kind, SymbolKind::Function);
        assert_eq!(p.name, "spawn");
        assert!(p.module_path.is_empty());
    }

    #[test]
    fn macro_symbol() {
        let p = parse("rust-analyzer cargo tracing 0.1.0 info!").unwrap();
        assert_eq!(p.kind, SymbolKind::Macro);
        assert_eq!(p.name, "info");
    }

    #[test]
    fn module_scoped_inherent_method() {
        let p = parse("rust-analyzer cargo sqlx 0.7.0 pool/impl#[PoolOptions]acquire_timeout().")
            .unwrap();
        assert_eq!(p.kind, SymbolKind::Method);
        assert_eq!(p.name, "acquire_timeout");
        assert_eq!(p.module_path, vec!["pool".to_string()]);
        assert_eq!(
            p.self_type_path().as_deref(),
            Some("sqlx::pool::PoolOptions")
        );
    }

    #[test]
    fn backticked_names_with_spaces_parse() {
        // core's Try::branch on Result: the descriptor itself contains a
        // space inside a backticked name. Must parse, not shear at the space.
        let p = parse(
            "rust-analyzer cargo core https://github.com/rust-lang/rust/library/core \
             result/impl#[`Result<T, E>`][Try]branch().",
        )
        .unwrap();
        assert_eq!(p.name, "branch");
        assert_eq!(p.self_type.as_deref(), Some("Result<T, E>"));
        assert_eq!(p.via_trait.as_deref(), Some("Try"));
    }

    #[test]
    fn locals_and_foreign_schemes_are_skipped() {
        assert!(parse("local 3").is_none());
        assert!(parse("scip-typescript npm ts 5.0 x.").is_none());
    }

    #[test]
    fn crate_root_symbol_is_not_a_callable() {
        // `crate/` — a namespace with nothing after it is not a site.
        assert!(parse("rust-analyzer cargo reqwest 0.11.0 crate/").is_none());
    }
}
