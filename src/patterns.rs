//! Four pattern detectors, each a pure function over `visit::Collected`.
//!
//! Naming: stable IDs the report (and the paper) cite verbatim.

use std::collections::BTreeSet;

use crate::visit::{Collected, Span};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PatternId {
    ScopeGap,
    FakeProbe,
    DiscardedStatus,
    HardcodedAbi,
    /// P11 — C-language coverage gap on V3/V5 access bits. Emitted by the
    /// `c_scanner` module against `.c` files that set `handled_access_fs`
    /// without referencing `LANDLOCK_ACCESS_FS_TRUNCATE` (V3) and/or
    /// `LANDLOCK_ACCESS_FS_IOCTL_DEV` (V5).
    P11AccessGap,
}

impl PatternId {
    pub fn as_str(self) -> &'static str {
        match self {
            PatternId::ScopeGap => "P_SCOPE_GAP",
            PatternId::FakeProbe => "P3",
            PatternId::DiscardedStatus => "P4",
            PatternId::HardcodedAbi => "P_HARDCODED_ABI",
            PatternId::P11AccessGap => "P11",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "P_SCOPE_GAP" => Some(Self::ScopeGap),
            "P3" => Some(Self::FakeProbe),
            "P4" => Some(Self::DiscardedStatus),
            "P_HARDCODED_ABI" => Some(Self::HardcodedAbi),
            "P11" => Some(Self::P11AccessGap),
            _ => None,
        }
    }

    pub const ALL: &'static [Self] = &[
        Self::ScopeGap,
        Self::FakeProbe,
        Self::DiscardedStatus,
        Self::HardcodedAbi,
        Self::P11AccessGap,
    ];
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub pattern: PatternId,
    pub span: Span,
    pub message: String,
}

/// P_SCOPE_GAP: file calls `.handle_access(...)` but never `.scope(...)`.
/// We cite the first handle_access span.
pub fn detect_scope_gap(c: &Collected) -> Vec<Finding> {
    if c.handle_access_sites.is_empty() {
        return vec![];
    }
    if !c.scope_call_sites.is_empty() {
        return vec![];
    }
    // Probe-only rulesets (handle_access + create, no restrict_self) don't
    // actually seal a process — they only check kernel capability. Don't flag.
    if c.restrict_self_call_sites.is_empty() {
        return vec![];
    }
    let span = c.handle_access_sites[0].clone();
    vec![Finding {
        pattern: PatternId::ScopeGap,
        span,
        message:
            "ruleset calls handle_access(...) and restrict_self() but never .scope(Scope::AbstractUnixSocket | Scope::Signal); \
             GHSA-27vp-2mmc-vmh3 abstract-Unix-socket escape applies."
                .into(),
    }]
}

/// P3: a method-call chain that contains `handle_access` AND terminates in
/// `is_ok`. Under CompatLevel::BestEffort the call returns Ok regardless of
/// the supplied ABI, so the result is a constant true.
pub fn detect_fake_probe(c: &Collected) -> Vec<Finding> {
    let mut out = vec![];
    for ch in &c.chains {
        if ch.terminal == "is_ok" && ch.methods.iter().any(|m| m == "handle_access") {
            out.push(Finding {
                pattern: PatternId::FakeProbe,
                span: ch.span.clone(),
                message:
                    "Ruleset::default().handle_access(...).is_ok() used as an ABI probe; \
                     handle_access() returns Ok for any value under BestEffort, so this 'probe' \
                     is a no-op and always picks the literal first ABI."
                        .into(),
            });
        }
    }
    out
}

/// P4: `restrict_self()` whose RestrictionStatus is dropped (let _, bare ;,
/// or bound to a name that is never inspected via `.ruleset`).
pub fn detect_discarded_status(c: &Collected) -> Vec<Finding> {
    c.restrict_self_sites
        .iter()
        .filter(|s| s.discarded)
        .map(|s| Finding {
            pattern: PatternId::DiscardedStatus,
            span: s.span.clone(),
            message:
                "restrict_self()'s RestrictionStatus is discarded; \
                 RulesetStatus::NotEnforced / PartiallyEnforced become silent happy paths."
                    .into(),
        })
        .collect()
}

/// P_HARDCODED_ABI: any `ABI::V<n>` literal, where the file does NOT also
/// contain a real probe pattern. v1 definition of a real probe: the same
/// file contains a `handle_access(...).is_ok()` chain (which is itself the
/// P3 hit). Absence of any such chain + presence of one or more ABI literals
/// = the file picks an ABI by fiat.
///
/// We emit one finding per *distinct* ABI literal in the file (deduped) to
/// reduce noise from repeated `from_all(ABI::V5)` uses.
pub fn detect_hardcoded_abi(c: &Collected) -> Vec<Finding> {
    if c.abi_literals.is_empty() {
        return vec![];
    }
    let has_p3_probe = c
        .chains
        .iter()
        .any(|ch| ch.terminal == "is_ok" && ch.methods.iter().any(|m| m == "handle_access"));
    // "real probe" = the P3 fake-probe shape OR a probe-order array literal
    // (e.g., nono's `[ABI::V6, ABI::V5, ABI::V4, ...]`).
    if has_p3_probe || c.has_array_probe {
        return vec![];
    }
    // Dedup by version string; cite first occurrence.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = vec![];
    for lit in &c.abi_literals {
        if seen.insert(lit.version.clone()) {
            let suffix = if lit.version == "V5" {
                "  (V5 adds IoctlDev; scope features land in V6 — hardcoding V5 silently misses them)"
            } else {
                ""
            };
            out.push(Finding {
                pattern: PatternId::HardcodedAbi,
                span: lit.span.clone(),
                message: format!(
                    "ABI::{} hardcoded with no probe — silently misses newer ABIs on supporting kernels.{}",
                    lit.version, suffix
                ),
            });
        }
    }
    out
}

pub fn detect_all(c: &Collected, enabled: &BTreeSet<PatternId>) -> Vec<Finding> {
    let mut out = vec![];
    if enabled.contains(&PatternId::ScopeGap) {
        out.extend(detect_scope_gap(c));
    }
    if enabled.contains(&PatternId::FakeProbe) {
        out.extend(detect_fake_probe(c));
    }
    if enabled.contains(&PatternId::DiscardedStatus) {
        out.extend(detect_discarded_status(c));
    }
    if enabled.contains(&PatternId::HardcodedAbi) {
        out.extend(detect_hardcoded_abi(c));
    }
    out
}
