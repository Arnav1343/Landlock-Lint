//! syn visitor: collects the raw signals the pattern detectors operate on.
//!
//! High-precision means: we collect concrete, named-call signals only. No
//! type inference, no cross-file reasoning. Each signal includes a span so
//! the reporter can cite file:line:col.
//!
//! Signals collected per file:
//!   - method-call chains terminating in is_ok / create / restrict_self,
//!     with the list of method names appearing in the chain
//!   - every `restrict_self()` site, plus whether the enclosing statement
//!     discards the returned RestrictionStatus
//!   - every `ABI::V<n>` path expression

use proc_macro2::LineColumn;
use syn::visit::{self, Visit};
use syn::{Expr, ExprMethodCall, ExprPath, ExprTry, Stmt};

#[derive(Debug, Clone)]
pub struct Span {
    pub line: usize,
    pub col: usize,
}

impl Span {
    fn from_lc(lc: LineColumn) -> Self {
        Self {
            line: lc.line,
            // proc-macro2 columns are 0-based — bump to 1-based for output
            col: lc.column + 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChainHit {
    /// Method name on the terminal node (the outermost method-call).
    pub terminal: String,
    /// All method names in the chain, terminal first, walking down receivers.
    pub methods: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct RestrictSelfSite {
    /// Span of the `restrict_self` identifier.
    pub span: Span,
    /// True iff this site discards the RestrictionStatus (see classify_restrict_self).
    pub discarded: bool,
}

#[derive(Debug, Clone)]
pub struct AbiLit {
    /// "V5", "V6", ...
    pub version: String,
    pub span: Span,
}

#[derive(Default, Debug)]
pub struct Collected {
    /// Every method-call chain terminating in a method we care about.
    pub chains: Vec<ChainHit>,
    pub restrict_self_sites: Vec<RestrictSelfSite>,
    /// ABI::V<n> literals appearing in landlock-relevant contexts only:
    /// call arguments, let-RHS, and array literals. Match-arm patterns
    /// and string-format helpers are intentionally NOT collected here.
    pub abi_literals: Vec<AbiLit>,
    /// True iff the file contains an array literal with >= 2 distinct
    /// `ABI::V<n>` entries — the canonical "I iterate ABIs for a probe"
    /// shape (nono-rs's `ABI_PROBE_ORDER`, claude-agent-rs's `[V4, V3, V2, V1]`).
    pub has_array_probe: bool,
    /// All `.scope(` call sites — used by the P_SCOPE_GAP rule to clear a file.
    pub scope_call_sites: Vec<Span>,
    /// All `.handle_access(` call sites.
    pub handle_access_sites: Vec<Span>,
    /// All `.restrict_self(` call sites (any chain). Used by P_SCOPE_GAP to
    /// distinguish a real sealing ruleset from a probe ruleset that just
    /// calls handle_access/create without sealing.
    pub restrict_self_call_sites: Vec<Span>,
}

pub fn collect(file: &syn::File) -> Collected {
    let mut v = Collector::default();
    v.visit_file(file);
    v.out
}

#[derive(Default)]
struct Collector {
    out: Collected,
}

/// Walk a method-call expression's receiver chain, collecting method names.
/// The output starts with the terminal node's method name.
fn chain_methods(top: &ExprMethodCall) -> Vec<String> {
    let mut names = vec![top.method.to_string()];
    let mut cur = &*top.receiver;
    loop {
        // Peel ExprTry / parens / references that don't break the chain.
        match cur {
            Expr::MethodCall(m) => {
                names.push(m.method.to_string());
                cur = &*m.receiver;
            }
            Expr::Try(t) => {
                cur = &*t.expr;
            }
            Expr::Paren(p) => {
                cur = &*p.expr;
            }
            Expr::Reference(r) => {
                cur = &*r.expr;
            }
            _ => break,
        }
    }
    names
}

/// True iff the path looks like `ABI::V<digit>+`.
fn abi_version_from_path(p: &ExprPath) -> Option<String> {
    let segs: Vec<_> = p.path.segments.iter().collect();
    if segs.len() < 2 {
        return None;
    }
    let abi_seg = &segs[segs.len() - 2];
    let v_seg = &segs[segs.len() - 1];
    if abi_seg.ident != "ABI" {
        return None;
    }
    let s = v_seg.ident.to_string();
    if let Some(rest) = s.strip_prefix('V') {
        if !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()) {
            return Some(s);
        }
    }
    None
}

/// Classify a restrict_self call site: does the enclosing statement discard
/// the returned `RestrictionStatus`?
///
/// Discarded forms recognised at v1:
///   - `let _ = ruleset.restrict_self()...;`
///   - `ruleset.restrict_self()...;`              (Stmt::Expr with semi, no bind)
///   - `ruleset.restrict_self()?;`                (Stmt::Expr ExprTry, no bind)
///   - `ruleset.restrict_self().map_err(...)?;`   (same shape, just longer chain)
///   - `let s = ruleset.restrict_self()...;` then no `s.ruleset` field access
///     in the rest of the enclosing block
///
/// Inspected (NOT a finding):
///   - `match ruleset.restrict_self() { ... }`
///   - `if let Ok(s) = ruleset.restrict_self() { ... s.ruleset ... }`
///   - any other expression context that lets the caller observe RulesetStatus
///
/// We do statement-level analysis only — same precision contract as the rest
/// of the linter.
fn classify_block(out: &mut Collected, block: &syn::Block) {
    for stmt in &block.stmts {
        match stmt {
            // let _ = ... restrict_self() ...;
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    if let Some(call_span) = find_restrict_self_in_expr(&init.expr) {
                        let discarded = match &local.pat {
                            syn::Pat::Wild(_) => true,
                            syn::Pat::Ident(pi) => {
                                let name = pi.ident.to_string();
                                // Look forward in the same block for a `name.ruleset` field access.
                                !block_has_ruleset_field_access(block, &name)
                            }
                            _ => false, // tuple/struct destructuring is too rare here; treat as inspected.
                        };
                        out.restrict_self_sites.push(RestrictSelfSite {
                            span: call_span,
                            discarded,
                        });
                    }
                }
            }
            // Bare expression statements: `expr;` or `expr` (last).
            Stmt::Expr(expr, semi) => {
                if let Some(call_span) = find_restrict_self_in_expr(expr) {
                    // Bare expression-statement with the value dropped is discarded.
                    // Trailing-tail (no semi) on a function whose return type carries
                    // the RestrictionStatus would technically not discard — but in
                    // practice none of the corpus does this. v1 conservatively
                    // treats `Stmt::Expr` without `;` as inspected (false negative
                    // path acceptable; explicit in README).
                    let discarded = semi.is_some();
                    out.restrict_self_sites.push(RestrictSelfSite {
                        span: call_span,
                        discarded,
                    });
                }
            }
            // Items / Macros: skip.
            _ => {}
        }
    }
}

/// Find a restrict_self method-call inside an expression's outer chain.
/// Returns the span of the `restrict_self` identifier if present.
fn find_restrict_self_in_expr(expr: &Expr) -> Option<Span> {
    // Walk method-call chains looking for restrict_self.
    let mut cur = expr;
    loop {
        match cur {
            Expr::MethodCall(m) => {
                if m.method == "restrict_self" {
                    return Some(Span::from_lc(m.method.span().start()));
                }
                cur = &*m.receiver;
            }
            Expr::Try(t) => {
                cur = &*t.expr;
            }
            Expr::Paren(p) => {
                cur = &*p.expr;
            }
            _ => return None,
        }
    }
}

/// Does any expression in `block` access `<name>.ruleset` as a field?
fn block_has_ruleset_field_access(block: &syn::Block, name: &str) -> bool {
    struct FieldScan<'a> {
        name: &'a str,
        hit: bool,
    }
    impl<'a, 'ast> Visit<'ast> for FieldScan<'a> {
        fn visit_expr_field(&mut self, f: &'ast syn::ExprField) {
            if let Expr::Path(p) = &*f.base {
                if let Some(seg) = p.path.segments.last() {
                    if seg.ident == self.name {
                        if let syn::Member::Named(m) = &f.member {
                            if m == "ruleset" {
                                self.hit = true;
                                return;
                            }
                        }
                    }
                }
            }
            visit::visit_expr_field(self, f);
        }
    }
    let mut scan = FieldScan { name, hit: false };
    scan.visit_block(block);
    scan.hit
}

impl Collector {
    /// Walk an expression tree looking for ABI::V<n> literals, but ONLY
    /// within expression contexts (never into Pat trees). Also notes when
    /// an array literal contains >= 2 distinct ABI versions (probe shape).
    fn collect_abi_in_expr(&mut self, e: &Expr) {
        use std::collections::BTreeSet;
        match e {
            Expr::Path(p) => {
                if let Some(ver) = abi_version_from_path(p) {
                    if let Some(seg) = p.path.segments.last() {
                        self.out.abi_literals.push(AbiLit {
                            version: ver,
                            span: Span::from_lc(seg.ident.span().start()),
                        });
                    }
                }
            }
            Expr::Call(c) => {
                self.collect_abi_in_expr(&c.func);
                for a in &c.args {
                    self.collect_abi_in_expr(a);
                }
            }
            Expr::MethodCall(m) => {
                self.collect_abi_in_expr(&m.receiver);
                for a in &m.args {
                    self.collect_abi_in_expr(a);
                }
            }
            Expr::Reference(r) => self.collect_abi_in_expr(&r.expr),
            Expr::Paren(p) => self.collect_abi_in_expr(&p.expr),
            Expr::Group(g) => self.collect_abi_in_expr(&g.expr),
            Expr::Binary(b) => {
                self.collect_abi_in_expr(&b.left);
                self.collect_abi_in_expr(&b.right);
            }
            Expr::Unary(u) => self.collect_abi_in_expr(&u.expr),
            Expr::Cast(c) => self.collect_abi_in_expr(&c.expr),
            Expr::Try(t) => self.collect_abi_in_expr(&t.expr),
            Expr::Tuple(t) => {
                for el in &t.elems {
                    self.collect_abi_in_expr(el);
                }
            }
            Expr::Array(a) => {
                // Walk for ABI literals AND check for the probe shape
                // (>= 2 distinct ABI::V<n> entries in one array literal).
                let mut local: BTreeSet<String> = BTreeSet::new();
                for el in &a.elems {
                    if let Expr::Path(p) = el {
                        if let Some(v) = abi_version_from_path(p) {
                            local.insert(v);
                        }
                    }
                    self.collect_abi_in_expr(el);
                }
                if local.len() >= 2 {
                    self.out.has_array_probe = true;
                }
            }
            Expr::Struct(s) => {
                for fv in &s.fields {
                    self.collect_abi_in_expr(&fv.expr);
                }
            }
            // Conservative: don't descend into bodies (If, Match, Block, …)
            // here — only contexts we care about (args, let-RHS, arrays)
            // call this function, and we don't want to traverse arbitrary
            // statements via the expression walker.
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        classify_block(&mut self.out, block);
        visit::visit_block(self, block);
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        if let Some(init) = &l.init {
            self.collect_abi_in_expr(&init.expr);
        }
        visit::visit_local(self, l);
    }

    fn visit_expr_call(&mut self, c: &'ast syn::ExprCall) {
        // ABI::V<n> as an arg to e.g. AccessFs::from_all(ABI::V5).
        for a in &c.args {
            self.collect_abi_in_expr(a);
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_expr_method_call(&mut self, m: &'ast ExprMethodCall) {
        let term_name = m.method.to_string();

        // Record specific named call sites (used by P_SCOPE_GAP shortcut).
        match term_name.as_str() {
            "handle_access" => {
                self.out
                    .handle_access_sites
                    .push(Span::from_lc(m.method.span().start()));
            }
            "scope" => {
                self.out
                    .scope_call_sites
                    .push(Span::from_lc(m.method.span().start()));
            }
            "restrict_self" => {
                self.out
                    .restrict_self_call_sites
                    .push(Span::from_lc(m.method.span().start()));
            }
            _ => {}
        }

        // ABI literals in method-call args (e.g. .handle_access(ABI::V5)).
        for a in &m.args {
            self.collect_abi_in_expr(a);
        }

        // Record chains terminating in interesting methods.
        if matches!(term_name.as_str(), "is_ok" | "create" | "restrict_self") {
            let methods = chain_methods(m);
            self.out.chains.push(ChainHit {
                terminal: term_name,
                methods,
                span: Span::from_lc(m.method.span().start()),
            });
        }

        visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_try(&mut self, t: &'ast ExprTry) {
        if let Expr::MethodCall(m) = &*t.expr {
            let term_name = m.method.to_string();
            if matches!(term_name.as_str(), "create" | "restrict_self") {
                let methods = chain_methods(m);
                self.out.chains.push(ChainHit {
                    terminal: term_name,
                    methods,
                    span: Span::from_lc(m.method.span().start()),
                });
            }
        }
        visit::visit_expr_try(self, t);
    }

    fn visit_item_const(&mut self, c: &'ast syn::ItemConst) {
        // Constants like `const ABI_PROBE_ORDER: [ABI; 6] = [ABI::V6, …];`
        self.collect_abi_in_expr(&c.expr);
        visit::visit_item_const(self, c);
    }

    fn visit_item_static(&mut self, s: &'ast syn::ItemStatic) {
        self.collect_abi_in_expr(&s.expr);
        visit::visit_item_static(self, s);
    }

    fn visit_item_mod(&mut self, m: &'ast syn::ItemMod) {
        // Skip #[cfg(test)] modules — test code intentionally pins ABIs / mocks rulesets.
        let is_test = m.attrs.iter().any(|attr| {
            if !attr.path().is_ident("cfg") {
                return false;
            }
            let mut found = false;
            let _ = attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("test") {
                    found = true;
                }
                Ok(())
            });
            found
        });
        if is_test {
            return;
        }
        visit::visit_item_mod(self, m);
    }
}
