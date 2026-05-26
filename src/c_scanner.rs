//! C-language pattern detectors (regex-/line-level; not a full C parser).
//!
//! Mirrors the Rust taxonomy where the pattern has a clean C analogue:
//!
//!   P_SCOPE_GAP — `landlock_create_ruleset` + `landlock_restrict_self` are
//!                 both called, but the file never references `LANDLOCK_SCOPE_*`
//!                 and never assigns the `.scoped` field of
//!                 `landlock_ruleset_attr`. Direct GHSA-27vp-2mmc-vmh3 mapping.
//!
//!   P4          — A `landlock_restrict_self(...)` call whose return value is
//!                 ignored (no `if`, comparison, assignment, or `return` on
//!                 the same statement). On failure the process keeps running
//!                 un-sandboxed.
//!
//!   P_HARDCODED_ABI — The file composes a Landlock access/scope mask but
//!                 never probes the kernel ABI via
//!                 `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
//!                 Hardcoding the mask silently misses newer ABIs.
//!
//!   P11         — Specialisation of the "mask hardcoded" gap: the file sets
//!                 `handled_access_fs` but never references
//!                 `LANDLOCK_ACCESS_FS_TRUNCATE` (V3) and/or
//!                 `LANDLOCK_ACCESS_FS_IOCTL_DEV` (V5).
//!
//! P3 (fake `.is_ok()` ABI probe) has no clean C analogue and is intentionally
//! not detected here. The C-side version-probe idiom is the literal syscall
//! `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`; the
//! corresponding misuse is "no probe at all", which is exactly what
//! P_HARDCODED_ABI catches above.
//!
//! Known limitations (documented; not blocking for v1.2):
//!   - Header-private macros that hide the relevant call shape: not expanded.
//!   - Cross-translation-unit construction (mask built in one .c, applied in
//!     another): the scanner is file-scoped.
//!   - Multi-line C statements split across lines: the P4 statement-context
//!     check looks at the call's line plus the previous physical line, which
//!     is sufficient for every C call shape seen in our corpus.

use crate::patterns::{Finding, PatternId};
use crate::visit::Span;

pub fn scan_c_file(text: &str) -> Vec<Finding> {
    let mut out = vec![];

    // Quick reject: doesn't reference landlock at all.
    let uses_landlock = text.contains("landlock_create_ruleset")
        || text.contains("landlock_restrict_self")
        || text.contains("handled_access_fs")
        || text.contains("LANDLOCK_ACCESS_FS_")
        || text.contains("LANDLOCK_SCOPE_");
    if !uses_landlock {
        return out;
    }

    out.extend(detect_p11(text));
    out.extend(detect_scope_gap_c(text));
    out.extend(detect_discarded_status_c(text));
    out.extend(detect_hardcoded_abi_c(text));

    out
}

// ---------------------------------------------------------------------------
// P11 — V3/V5 access-bit coverage gap
// ---------------------------------------------------------------------------

fn detect_p11(text: &str) -> Vec<Finding> {
    let mut out = vec![];

    // Anchor on the first line that assigns/composes `handled_access_fs`.
    // Without an assignment site, we have no exploitable citation point.
    let mut anchor: Option<Span> = None;
    for (i, line) in text.lines().enumerate() {
        if line_assigns_handled_access_fs(line) {
            let col = line.find("handled_access_fs").map(|c| c + 1).unwrap_or(1);
            anchor = Some(Span { line: i + 1, col });
            break;
        }
    }
    // Fallback: a `_LANDLOCK_*_WRITE`-style macro definition body (Suricata-shape).
    if anchor.is_none() {
        for (i, line) in text.lines().enumerate() {
            if line.contains("LANDLOCK_ACCESS_FS_WRITE_FILE")
                && (line.trim_start().starts_with('#') || line.contains('|'))
            {
                anchor = Some(Span { line: i + 1, col: 1 });
                break;
            }
        }
    }
    let span = match anchor {
        Some(s) => s,
        None => return out,
    };

    let has_truncate = text.contains("LANDLOCK_ACCESS_FS_TRUNCATE");
    let has_ioctl_dev = text.contains("LANDLOCK_ACCESS_FS_IOCTL_DEV");

    if !has_truncate {
        out.push(Finding {
            pattern: PatternId::P11AccessGap,
            span: span.clone(),
            message:
                "handled_access_fs is set but LANDLOCK_ACCESS_FS_TRUNCATE (V3, kernel ≥ 5.19) is never \
                 referenced in this file; ftruncate() on files inside WRITE-granted directories is \
                 not mediated by Landlock."
                    .into(),
        });
    }
    if !has_ioctl_dev {
        out.push(Finding {
            pattern: PatternId::P11AccessGap,
            span,
            message:
                "handled_access_fs is set but LANDLOCK_ACCESS_FS_IOCTL_DEV (V5, kernel ≥ 6.10) is never \
                 referenced in this file; ioctl() on device files inside granted paths is not mediated \
                 by Landlock."
                    .into(),
        });
    }

    out
}

fn line_assigns_handled_access_fs(line: &str) -> bool {
    let idx = match line.find("handled_access_fs") {
        Some(i) => i,
        None => return false,
    };
    let after = &line[idx + "handled_access_fs".len()..];
    let trimmed = after.trim_start();
    trimmed.starts_with('=') || trimmed.starts_with("|=")
}

// ---------------------------------------------------------------------------
// P_SCOPE_GAP (C) — restrict_self is called, but no LANDLOCK_SCOPE_* / .scoped
// ---------------------------------------------------------------------------

fn detect_scope_gap_c(text: &str) -> Vec<Finding> {
    // Must seal a sandbox at a *call* site (skip the syscall-wrapper shim
    // definition that many Linux C files include before the real call).
    let restrict_line = match find_first_call_line(text, "landlock_restrict_self") {
        Some(i) => i,
        None => return vec![],
    };
    // Must actually configure access (otherwise this is e.g. an ABI probe util).
    let configures = text.contains("handled_access_fs")
        || text.contains("LANDLOCK_ACCESS_FS_")
        || text.contains("landlock_add_rule");
    if !configures {
        return vec![];
    }
    // Suppress if the file references the V6 scope feature at all.
    let touches_scope = text.contains("LANDLOCK_SCOPE_")
        || text.contains(".scoped")
        || text.contains("->scoped")
        || text.contains("attr.scoped");
    if touches_scope {
        return vec![];
    }

    let col = text
        .lines()
        .nth(restrict_line - 1)
        .and_then(|l| l.find("landlock_restrict_self"))
        .map(|c| c + 1)
        .unwrap_or(1);

    vec![Finding {
        pattern: PatternId::ScopeGap,
        span: Span { line: restrict_line, col },
        message:
            "landlock_restrict_self() is called but the file never references LANDLOCK_SCOPE_* \
             or sets landlock_ruleset_attr.scoped; GHSA-27vp-2mmc-vmh3 abstract-Unix-socket \
             escape applies."
                .into(),
    }]
}

// ---------------------------------------------------------------------------
// P4 (C) — landlock_restrict_self return value discarded
// ---------------------------------------------------------------------------

fn detect_discarded_status_c(text: &str) -> Vec<Finding> {
    let mut out = vec![];
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(col) = line.find("landlock_restrict_self(") else { continue };
        if looks_like_declaration(line, col) {
            continue;
        }

        // Build the statement context: the call's line preceded by up to one
        // physical line of leading context (covers `int rc =\n  landlock_*` and
        // `if (\n  landlock_*` shapes).
        let prev = if i > 0 { lines[i - 1] } else { "" };
        let context_pre_call = format!("{} {}", prev, &line[..col]);
        if is_return_value_used(&context_pre_call) {
            continue;
        }

        out.push(Finding {
            pattern: PatternId::DiscardedStatus,
            span: Span { line: i + 1, col: col + 1 },
            message:
                "landlock_restrict_self()'s return value is discarded; on failure the process \
                 continues un-sandboxed without any signal to the caller."
                    .into(),
        });
    }
    out
}

/// Heuristic: does the text immediately preceding the call indicate that the
/// return value will be consumed? Looks for assignment, comparison, branch,
/// or return-statement context on the same C statement.
fn is_return_value_used(pre_call: &str) -> bool {
    // Strip an opening `static inline` / function header noise: only the
    // trailing fragment after the last `;`, `{`, or `}` matters.
    let tail_start = pre_call
        .rfind(|c: char| c == ';' || c == '{' || c == '}')
        .map(|i| i + 1)
        .unwrap_or(0);
    let tail = pre_call[tail_start..].trim_start();

    // Empty tail = bare-call statement (`landlock_restrict_self(...)`).
    if tail.is_empty() {
        return false;
    }

    // Common consumption markers, in order of how they appear before the call:
    //   `if (`, `while (`, `return `, `<lhs> = `, `<lhs> == `, `<lhs> != `,
    //   `<lhs> < `, `<lhs> > `, `<lhs> <= `, `<lhs> >= `, `!`, `&&`, `||`, `,`
    //   (the comma covers `f(landlock_restrict_self(...), other)` consumption).
    let markers = [
        "if", "while", "return", "=", "==", "!=", "<", ">", "<=", ">=",
        "!", "&&", "||", ",", "?", ":",
    ];
    markers.iter().any(|m| tail.contains(m))
}

// ---------------------------------------------------------------------------
// P_HARDCODED_ABI (C) — Landlock used but no LANDLOCK_CREATE_RULESET_VERSION probe
// ---------------------------------------------------------------------------

fn detect_hardcoded_abi_c(text: &str) -> Vec<Finding> {
    // Only fires for files that actually build a sandbox: a real
    // `landlock_create_ruleset(&...)` call (i.e. non-probe), and at least one
    // LANDLOCK_ACCESS_FS_* or LANDLOCK_SCOPE_* symbol composed into a mask.
    let composes_mask = text.contains("LANDLOCK_ACCESS_FS_")
        || text.contains("LANDLOCK_SCOPE_");
    if !composes_mask {
        return vec![];
    }

    // Find a non-probe ruleset creation: `landlock_create_ruleset(&...` or
    // `landlock_create_ruleset(  &...`. The probe form is
    // `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.
    let mut creation_span: Option<Span> = None;
    for (i, line) in text.lines().enumerate() {
        let Some(idx) = line.find("landlock_create_ruleset(") else { continue };
        let after = &line[idx + "landlock_create_ruleset(".len()..];
        let after = after.trim_start();
        if after.starts_with('&') {
            creation_span = Some(Span { line: i + 1, col: idx + 1 });
            break;
        }
    }
    let span = match creation_span {
        Some(s) => s,
        None => return vec![],
    };

    if text.contains("LANDLOCK_CREATE_RULESET_VERSION") {
        return vec![];
    }

    vec![Finding {
        pattern: PatternId::HardcodedAbi,
        span,
        message:
            "Landlock mask composed and applied without calling \
             landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) to probe the \
             supported ABI — silently misses newer ABIs on supporting kernels."
                .into(),
    }]
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Find the first line where `symbol(` is a *call site* (not a declaration /
/// shim definition like `static inline int symbol(...)`).
fn find_first_call_line(text: &str, symbol: &str) -> Option<usize> {
    let needle = format!("{}(", symbol);
    for (i, line) in text.lines().enumerate() {
        let Some(col) = line.find(&needle) else { continue };
        if looks_like_declaration(line, col) {
            continue;
        }
        return Some(i + 1);
    }
    None
}

/// Heuristic: does the prefix of `line` before column `col` look like a C
/// function declaration/definition rather than a call? True if it ends in a
/// type/storage-class token (`static`, `inline`, `extern`, `int`, `long`,
/// `void`, `unsigned`, `signed`, `__attribute__(...)`).
fn looks_like_declaration(line: &str, col: usize) -> bool {
    let prefix = line[..col].trim_end();
    let last_tok = prefix.rsplit(|c: char| c.is_whitespace() || c == '*').next().unwrap_or("");
    matches!(
        last_tok,
        "static" | "inline" | "extern" | "int" | "long" | "void" | "unsigned" | "signed"
    ) || prefix.ends_with("inline int")
        || prefix.ends_with("static inline int")
        || prefix.ends_with("static int")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- P11 (preserved from v0.1.1) ----------

    const SURICATA_SHAPE_MIN: &str = r#"
#define _LANDLOCK_ACCESS_FS_WRITE \
    (LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR | \
     LANDLOCK_ACCESS_FS_REFER)

static inline void build(void) {
    ruleset->attr.handled_access_fs =
        _LANDLOCK_ACCESS_FS_READ | _LANDLOCK_ACCESS_FS_WRITE | LANDLOCK_ACCESS_FS_EXECUTE;
    int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 0) return;
    landlock_create_ruleset(&ruleset->attr, sizeof(ruleset->attr), 0);
    if (landlock_restrict_self(ruleset->fd, 0)) { /* ok */ }
}
"#;

    #[test]
    fn p11_fires_for_truncate_and_ioctl_dev_missing() {
        let findings: Vec<_> = scan_c_file(SURICATA_SHAPE_MIN)
            .into_iter()
            .filter(|f| f.pattern == PatternId::P11AccessGap)
            .collect();
        assert_eq!(findings.len(), 2);
        assert!(findings[0].message.contains("TRUNCATE"));
        assert!(findings[1].message.contains("IOCTL_DEV"));
    }

    #[test]
    fn p11_silent_when_mask_is_complete() {
        let src = r#"
ruleset->attr.handled_access_fs =
    LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE
    | LANDLOCK_ACCESS_FS_IOCTL_DEV;
landlock_restrict_self(fd, 0);
"#;
        let p11: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::P11AccessGap)
            .collect();
        assert!(p11.is_empty());
    }

    // ---------- P_SCOPE_GAP (C) ----------

    #[test]
    fn scope_gap_c_fires_when_no_scope_referenced() {
        let scope_findings: Vec<_> = scan_c_file(SURICATA_SHAPE_MIN)
            .into_iter()
            .filter(|f| f.pattern == PatternId::ScopeGap)
            .collect();
        assert_eq!(scope_findings.len(), 1);
        assert!(scope_findings[0].message.contains("LANDLOCK_SCOPE_"));
    }

    #[test]
    fn scope_gap_c_silent_when_scope_referenced() {
        let src = r#"
ruleset.attr.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE;
ruleset.attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;
landlock_create_ruleset(&ruleset.attr, sizeof(ruleset.attr), 0);
if (landlock_restrict_self(fd, 0)) { return -1; }
"#;
        let scope_findings: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::ScopeGap)
            .collect();
        assert!(scope_findings.is_empty());
    }

    #[test]
    fn scope_gap_c_silent_for_probe_only_file() {
        // Calls create_ruleset to probe ABI version but never restrict_self.
        let src = r#"
int probe(void) {
    return landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
}
"#;
        let scope_findings: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::ScopeGap)
            .collect();
        assert!(scope_findings.is_empty());
    }

    // ---------- P4 (C) ----------

    #[test]
    fn p4_c_fires_on_bare_call() {
        let src = r#"
void seal(int fd) {
    landlock_restrict_self(fd, 0);
}
"#;
        let p4: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::DiscardedStatus)
            .collect();
        assert_eq!(p4.len(), 1);
    }

    #[test]
    fn p4_c_silent_when_return_checked_with_if() {
        let src = r#"
void seal(int fd) {
    if (landlock_restrict_self(fd, 0)) { abort(); }
}
"#;
        let p4: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::DiscardedStatus)
            .collect();
        assert!(p4.is_empty());
    }

    #[test]
    fn p4_c_silent_when_return_assigned() {
        let src = r#"
int seal(int fd) {
    int rc = landlock_restrict_self(fd, 0);
    return rc;
}
"#;
        let p4: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::DiscardedStatus)
            .collect();
        assert!(p4.is_empty());
    }

    #[test]
    fn p4_c_silent_when_returned_directly() {
        let src = r#"
int seal(int fd) {
    return landlock_restrict_self(fd, 0);
}
"#;
        let p4: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::DiscardedStatus)
            .collect();
        assert!(p4.is_empty());
    }

    // ---------- P_HARDCODED_ABI (C) ----------

    #[test]
    fn hardcoded_abi_c_fires_when_no_probe() {
        let src = r#"
ruleset.attr.handled_access_fs = LANDLOCK_ACCESS_FS_WRITE_FILE;
landlock_create_ruleset(&ruleset.attr, sizeof(ruleset.attr), 0);
landlock_restrict_self(fd, 0);
"#;
        let abi: Vec<_> = scan_c_file(src)
            .into_iter()
            .filter(|f| f.pattern == PatternId::HardcodedAbi)
            .collect();
        assert_eq!(abi.len(), 1);
    }

    #[test]
    fn hardcoded_abi_c_silent_when_probe_present() {
        // Suricata shape: probes via LANDLOCK_CREATE_RULESET_VERSION.
        let abi: Vec<_> = scan_c_file(SURICATA_SHAPE_MIN)
            .into_iter()
            .filter(|f| f.pattern == PatternId::HardcodedAbi)
            .collect();
        assert!(abi.is_empty());
    }

    // ---------- non-landlock files ----------

    #[test]
    fn non_landlock_c_file_yields_no_findings() {
        let src = "int main(void) { return 0; }\n";
        assert!(scan_c_file(src).is_empty());
    }
}
