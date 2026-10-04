//! Reporters: stdout (per-finding terse), `--explain` (developer-friendly),
//! markdown summary (per-project table), and SARIF.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::patterns::{Finding, PatternId};

/// One finding plus its source file, for grouping.
#[derive(Debug, Clone)]
pub struct FileFinding {
    pub path: PathBuf,
    pub finding: Finding,
}

pub fn print_stdout(scan_root: &Path, findings: &[FileFinding]) {
    for f in findings {
        let rel = pathdiff(scan_root, &f.path);
        println!(
            "{}:{}:{}  {}  {}",
            rel.display(),
            f.finding.span.line,
            f.finding.span.col,
            f.finding.pattern.as_str(),
            f.finding.message
        );
    }
    eprintln!("\n{} findings.", findings.len());
}

/// Developer-friendly grouped report: by file, with plain-English headlines,
/// why-it-matters explanations, and concrete fix suggestions per finding.
///
/// Intended for a maintainer running the tool against their own project, not
/// for corpus reproduction or CI ingestion (use the default stdout / SARIF
/// outputs for those).
pub fn print_explain(scan_root: &Path, findings: &[FileFinding]) {
    let bar: String = "─".repeat(72);

    println!("landlock-lint v{}", env!("CARGO_PKG_VERSION"));
    println!("Scanned: {}\n", scan_root.display());

    if findings.is_empty() {
        println!("✓ No Landlock misuse patterns found.");
        println!("  Your Landlock configuration looks correct against the four\n  Rust patterns and four C patterns this tool detects.\n");
        return;
    }

    let mut by_file: BTreeMap<&Path, Vec<&FileFinding>> = BTreeMap::new();
    for f in findings {
        by_file.entry(f.path.as_path()).or_default().push(f);
    }

    println!(
        "Found {} issue(s) in {} file(s).\n",
        findings.len(),
        by_file.len()
    );

    let mut idx = 0;
    for (path, group) in &by_file {
        let rel = pathdiff(scan_root, path);
        println!("{}", bar);
        println!("{}", rel.display());
        println!("{}\n", bar);

        let is_c = matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("c") | Some("h")
        );

        for f in group {
            idx += 1;
            let (headline, why, fix) = explain(f.finding.pattern, is_c);
            println!(
                "  [{}] {}  —  line {}, col {}",
                idx,
                f.finding.pattern.as_str(),
                f.finding.span.line,
                f.finding.span.col
            );
            println!("      {}\n", headline);
            println!("      Why it matters:");
            for line in why.lines() {
                println!("        {}", line);
            }
            println!();
            println!("      How to fix:");
            for line in fix.lines() {
                println!("        {}", line);
            }
            println!();
        }
    }

    // Pattern summary.
    println!("{}", bar);
    println!("Summary");
    println!("{}\n", bar);

    let mut counts: BTreeMap<&str, (usize, &'static str)> = BTreeMap::new();
    for f in findings {
        let id = f.finding.pattern.as_str();
        let short = short_desc(f.finding.pattern);
        let entry = counts.entry(id).or_insert((0, short));
        entry.0 += 1;
    }
    for (id, (count, desc)) in &counts {
        println!("  {} × {:<18}  {}", count, id, desc);
    }
    println!(
        "\n  {} total finding(s) across {} file(s).\n",
        findings.len(),
        by_file.len()
    );

    println!("Next:");
    println!("  • Read each cited line and apply the suggested fix.");
    println!("  • Re-run `landlock-lint <path> --explain` to verify.");
    println!("  • Background: https://docs.kernel.org/userspace-api/landlock.html");
    println!("  • The V6 scope escape (P_SCOPE_GAP): GHSA-27vp-2mmc-vmh3\n");
}

fn short_desc(p: PatternId) -> &'static str {
    match p {
        PatternId::ScopeGap => "V6 scope missing — sandbox escape risk",
        PatternId::FakeProbe => "fake ABI probe — always picks first ABI",
        PatternId::DiscardedStatus => "sandbox status not checked",
        PatternId::HardcodedAbi => "ABI hardcoded — misses newer kernel features",
        PatternId::P11AccessGap => "V3/V5 access bits missing — ftruncate/ioctl unmediated",
    }
}

/// Returns (headline, why-it-matters, how-to-fix) for a pattern, with the
/// Rust or C flavour depending on `is_c`.
fn explain(pattern: PatternId, is_c: bool) -> (&'static str, &'static str, &'static str) {
    match (pattern, is_c) {
        (PatternId::ScopeGap, false) => (
            "Sandbox is missing V6 scope rules — can be escaped via abstract Unix sockets.",
            "A sandboxed process can connect to abstract Unix sockets in the same\n\
             user session — including the systemd user bus at /run/user/$UID/bus —\n\
             and ask the host session to run commands outside the sandbox. The\n\
             same gap also lets signals cross the sandbox boundary.\n\
             This is GHSA-27vp-2mmc-vmh3, fixed in nono-rs v0.55.0.",
            "Chain `.scope(Scope::AbstractUnixSocket | Scope::Signal)` onto your\n\
             ruleset before calling `.restrict_self()`.\n\
             Note: V6 scope only covers *abstract* Unix sockets. Pathname sockets\n\
             like /run/user/$UID/bus must also be addressed explicitly — either\n\
             allow them via path-beneath rules with a tight access mask, or deny\n\
             the systemd user bus directory entirely.",
        ),
        (PatternId::ScopeGap, true) => (
            "Sandbox is missing V6 scope rules — can be escaped via abstract Unix sockets.",
            "A sandboxed process can connect to abstract Unix sockets in the same\n\
             user session — including the systemd user bus at /run/user/$UID/bus —\n\
             and ask the host session to run commands outside the sandbox.\n\
             This is GHSA-27vp-2mmc-vmh3 in the raw-syscall world.",
            "Set `attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL;`\n\
             before calling `landlock_create_ruleset(&attr, sizeof(attr), 0)`.\n\
             Pass the full `sizeof(struct landlock_ruleset_attr)` so the kernel\n\
             sees the `.scoped` field. Gate this on a probed ABI ≥ 6 via\n\
             `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`.\n\
             Pathname sockets (e.g. /run/user/$UID/bus) must still be handled\n\
             explicitly — V6 scope does not cover them.",
        ),

        (PatternId::FakeProbe, _) => (
            "Fake ABI probe — your version-detection is a no-op.",
            "`Ruleset::default().handle_access(...).is_ok()` looks like it asks the\n\
             kernel whether a given ABI is supported, but under `CompatLevel::BestEffort`\n\
             (the default), `handle_access(...)` returns `Ok(_)` for any ABI value.\n\
             So the `.is_ok()` check is always true, and your code always picks\n\
             the first ABI literal in the list — not the highest the kernel supports.\n\
             Result: a kernel that supports V7 still gets sandboxed at the first\n\
             literal you listed (often V4 or V5), silently missing newer features\n\
             including V6 scope (the GHSA-27vp-2mmc-vmh3 fix).",
            "Either:\n\
             (a) Iterate `[ABI::V8, ABI::V7, ABI::V6, ...]` and pick the first\n\
                 whose actual creation succeeds (use `RulesetCreated::handle_access`\n\
                 + match on the error), or\n\
             (b) Use `CompatLevel::HardRequirement` if you have a real minimum\n\
                 ABI requirement and want compile-time-style enforcement.\n\
             See the nono-rs ABI selector for a working reference.",
        ),

        (PatternId::DiscardedStatus, false) => (
            "Sandbox status discarded — silent failures.",
            "`restrict_self()` returns a `RestrictionStatus` whose `.ruleset` field\n\
             can be `NotEnforced` or `PartiallyEnforced` even on a successful call —\n\
             e.g. when the kernel doesn't support the requested ABI. Dropping the\n\
             status (let `_ = …;`, bare `;`, or `?;` without inspection) means your\n\
             code treats those as happy paths and continues running effectively\n\
             un-sandboxed.",
            "Bind the result and inspect `.ruleset`:\n\n\
             ```rust\n\
             let status = ruleset.restrict_self()?;\n\
             if status.ruleset != RulesetStatus::FullyEnforced {\n\
                 // log loudly, refuse to run privileged work, or abort\n\
             }\n\
             ```\n\
             At minimum: log a warning on `NotEnforced` / `PartiallyEnforced`\n\
             so a user can see Landlock didn't actually apply.",
        ),
        (PatternId::DiscardedStatus, true) => (
            "landlock_restrict_self() return value ignored — silent un-sandboxed runs.",
            "On failure, `landlock_restrict_self(fd, 0)` returns -1 with errno set.\n\
             If you don't check the return, the kernel call may have failed (kernel\n\
             too old, ruleset_fd invalid, PR_SET_NO_NEW_PRIVS not set, etc.) and your\n\
             process keeps running with no sandbox at all and no signal to the caller.",
            "Wrap the call in an `if` and handle the error path:\n\n\
             ```c\n\
             if (landlock_restrict_self(fd, 0) != 0) {\n\
                 fprintf(stderr, \"landlock_restrict_self: %s\\n\", strerror(errno));\n\
                 abort();   /* or graceful refusal to run privileged work */\n\
             }\n\
             ```\n\
             Don't forget the matching `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` check.",
        ),

        (PatternId::HardcodedAbi, false) => (
            "Landlock ABI is hardcoded — silently misses newer kernel features.",
            "Pinning `ABI::V<n>` configures your sandbox for that ABI's features\n\
             only. On a kernel that supports a higher ABI you miss everything\n\
             added since — including:\n\
              • V3 (6.2): FS_TRUNCATE — `ftruncate()` mediated\n\
              • V5 (6.10): FS_IOCTL_DEV — `ioctl()` on device files mediated\n\
              • V6 (6.7) : scope rules — abstract-Unix-socket / signal escape\n\
                            closure (the GHSA-27vp-2mmc-vmh3 fix)\n\
              • V7 (6.11): network rules\n\
             Hardcoding `V5` or lower means your sandbox is *structurally* unable\n\
             to defend against the V6 scope escape, regardless of any other config.",
            "Probe at runtime and pick the highest supported ABI. The nono-rs\n\
             pattern is:\n\n\
             ```rust\n\
             const ABIS: &[ABI] = &[ABI::V7, ABI::V6, ABI::V5, ABI::V4];\n\
             let mut ruleset = Ruleset::default();\n\
             for abi in ABIS {\n\
                 match Ruleset::default().set_compatibility(CompatLevel::HardRequirement)\n\
                                          .handle_access(AccessFs::from_all(*abi)) {\n\
                     Ok(_) => { ruleset = ruleset.handle_access(AccessFs::from_all(*abi))?; break }\n\
                     Err(_) => continue,\n\
                 }\n\
             }\n\
             ```",
        ),
        (PatternId::HardcodedAbi, true) => (
            "Landlock mask hardcoded — kernel ABI never probed.",
            "Without `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`\n\
             your file assumes a specific kernel ABI. On older kernels, unknown\n\
             access bits cause -EINVAL on `landlock_create_ruleset`; on newer\n\
             kernels you silently miss features like V3 truncate / V5 ioctl-dev\n\
             control and V6 scope (the GHSA-27vp-2mmc-vmh3 fix).",
            "Probe first, then mask:\n\n\
             ```c\n\
             int abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);\n\
             if (abi < 0) { /* Landlock unavailable */ }\n\
             if (abi < 3) attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;\n\
             if (abi < 5) attr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_IOCTL_DEV;\n\
             if (abi >= 6) attr.scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET\n\
                                       | LANDLOCK_SCOPE_SIGNAL;\n\
             ```\n\
             Reference: kernel sample at samples/landlock/sandboxer.c.",
        ),

        (PatternId::P11AccessGap, _) => (
            "FS access mask is missing V3 / V5 bits — ftruncate() and ioctl() bypass the sandbox.",
            "Even when `handled_access_fs` is set, Landlock only mediates the bits\n\
             you explicitly request. Without:\n\
              • LANDLOCK_ACCESS_FS_TRUNCATE   (V3, kernel ≥ 6.2): `ftruncate()`\n\
                on files inside write-granted directories is NOT mediated — a\n\
                sandboxed process can shrink/extend files arbitrarily.\n\
              • LANDLOCK_ACCESS_FS_IOCTL_DEV  (V5, kernel ≥ 6.10): `ioctl()` on\n\
                device files inside granted paths is NOT mediated — the sandbox\n\
                cannot constrain device-driver interactions.",
            "Add the missing bits to your `handled_access_fs` mask:\n\n\
             ```c\n\
             ruleset.attr.handled_access_fs |=\n\
                 LANDLOCK_ACCESS_FS_TRUNCATE\n\
               | LANDLOCK_ACCESS_FS_IOCTL_DEV;\n\
             ```\n\
             Gate each bit on the probed ABI version (see P_HARDCODED_ABI fix).",
        ),
    }
}

/// Summarise findings into a markdown table keyed by the immediate child
/// directory of `scan_root` (the "project" name in the corpus layout).
pub fn write_markdown_summary(
    out_path: &Path,
    scan_root: &Path,
    findings: &[FileFinding],
) -> std::io::Result<()> {
    use std::io::Write;

    let mut per_project: BTreeMap<String, [usize; 5]> = BTreeMap::new();
    for f in findings {
        let project = project_of(scan_root, &f.path).unwrap_or_else(|| "<root>".to_string());
        let row = per_project.entry(project).or_insert([0; 5]);
        match f.finding.pattern {
            PatternId::ScopeGap => row[0] += 1,
            PatternId::FakeProbe => row[1] += 1,
            PatternId::DiscardedStatus => row[2] += 1,
            PatternId::HardcodedAbi => row[3] += 1,
            PatternId::P11AccessGap => row[4] += 1,
        }
    }

    let mut w = std::fs::File::create(out_path)?;
    writeln!(
        w,
        "# landlock-lint summary\n\nScan root: `{}`\n",
        scan_root.display()
    )?;
    writeln!(
        w,
        "| Project | P_SCOPE_GAP | P3 | P4 | P_HARDCODED_ABI | P11 (C) |"
    )?;
    writeln!(w, "|---|---|---|---|---|---|")?;
    for (proj, counts) in &per_project {
        writeln!(
            w,
            "| {} | {} | {} | {} | {} | {} |",
            proj, counts[0], counts[1], counts[2], counts[3], counts[4]
        )?;
    }
    let totals = per_project.values().fold([0; 5], |mut acc, c| {
        for i in 0..5 {
            acc[i] += c[i];
        }
        acc
    });
    writeln!(
        w,
        "| **Total** | **{}** | **{}** | **{}** | **{}** | **{}** |",
        totals[0], totals[1], totals[2], totals[3], totals[4]
    )?;
    writeln!(
        w,
        "\nProjects with findings: {}. Total findings: {}.",
        per_project.len(),
        findings.len()
    )?;
    Ok(())
}

/// SARIF 2.1.0 emission. One result per finding; ruleId = pattern.as_str();
/// physicalLocation cites file + line + column. URIs are absolute paths under
/// `file://` per SARIF's `uriBaseId` "%SRCROOT%" convention.
pub fn write_sarif(
    out_path: &Path,
    scan_root: &Path,
    findings: &[FileFinding],
) -> std::io::Result<()> {
    use std::io::Write;
    let mut w = std::fs::File::create(out_path)?;
    let abs_root = scan_root.canonicalize().unwrap_or_else(|_| scan_root.to_path_buf());

    writeln!(w, "{{")?;
    writeln!(w, "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",")?;
    writeln!(w, "  \"version\": \"2.1.0\",")?;
    writeln!(w, "  \"runs\": [")?;
    writeln!(w, "    {{")?;
    writeln!(w, "      \"tool\": {{")?;
    writeln!(w, "        \"driver\": {{")?;
    writeln!(w, "          \"name\": \"landlock-lint\",")?;
    writeln!(w, "          \"version\": \"0.1.1\",")?;
    writeln!(w, "          \"informationUri\": \"https://github.com/landlock-misuse-study/landlock-lint\",")?;
    writeln!(w, "          \"rules\": [")?;
    let rules = [
        ("P_SCOPE_GAP", "Landlock V6 scope unused", "warning"),
        ("P3", "Pseudo ABI probe via handle_access().is_ok()", "warning"),
        ("P4", "RulesetStatus discarded after restrict_self()", "warning"),
        ("P_HARDCODED_ABI", "ABI::V<n> literal with no probe", "note"),
        ("P11", "C-language coverage gap on V3 TRUNCATE / V5 IOCTL_DEV", "warning"),
    ];
    for (i, (id, name, level)) in rules.iter().enumerate() {
        writeln!(w, "            {{")?;
        writeln!(w, "              \"id\": \"{}\",", id)?;
        writeln!(w, "              \"name\": \"{}\",", json_escape(name))?;
        writeln!(w, "              \"defaultConfiguration\": {{ \"level\": \"{}\" }}", level)?;
        writeln!(w, "            }}{}", if i + 1 < rules.len() { "," } else { "" })?;
    }
    writeln!(w, "          ]")?;
    writeln!(w, "        }}")?;
    writeln!(w, "      }},")?;
    writeln!(w, "      \"originalUriBaseIds\": {{")?;
    writeln!(w, "        \"SRCROOT\": {{ \"uri\": \"file://{}/\" }}", abs_root.display())?;
    writeln!(w, "      }},")?;
    writeln!(w, "      \"results\": [")?;
    for (i, f) in findings.iter().enumerate() {
        let rel = f
            .path
            .strip_prefix(&abs_root)
            .unwrap_or(&f.path)
            .display()
            .to_string();
        writeln!(w, "        {{")?;
        writeln!(w, "          \"ruleId\": \"{}\",", f.finding.pattern.as_str())?;
        writeln!(
            w,
            "          \"level\": \"{}\",",
            level_for(f.finding.pattern)
        )?;
        writeln!(
            w,
            "          \"message\": {{ \"text\": \"{}\" }},",
            json_escape(&f.finding.message)
        )?;
        writeln!(w, "          \"locations\": [")?;
        writeln!(w, "            {{")?;
        writeln!(w, "              \"physicalLocation\": {{")?;
        writeln!(w, "                \"artifactLocation\": {{")?;
        writeln!(
            w,
            "                  \"uri\": \"{}\",",
            json_escape(&rel)
        )?;
        writeln!(w, "                  \"uriBaseId\": \"SRCROOT\"")?;
        writeln!(w, "                }},")?;
        writeln!(w, "                \"region\": {{")?;
        writeln!(w, "                  \"startLine\": {},", f.finding.span.line)?;
        writeln!(w, "                  \"startColumn\": {}", f.finding.span.col)?;
        writeln!(w, "                }}")?;
        writeln!(w, "              }}")?;
        writeln!(w, "            }}")?;
        writeln!(w, "          ]")?;
        writeln!(
            w,
            "        }}{}",
            if i + 1 < findings.len() { "," } else { "" }
        )?;
    }
    writeln!(w, "      ]")?;
    writeln!(w, "    }}")?;
    writeln!(w, "  ]")?;
    writeln!(w, "}}")?;
    Ok(())
}

fn level_for(p: PatternId) -> &'static str {
    match p {
        PatternId::HardcodedAbi => "note",
        _ => "warning",
    }
}

/// Minimal JSON string escaping for SARIF emission. Handles the subset
/// actually present in our finding messages: backslash, quote, control chars.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn project_of(scan_root: &Path, file: &Path) -> Option<String> {
    let rel = pathdiff(scan_root, file);
    rel.components().next().and_then(|c| match c {
        std::path::Component::Normal(s) => s.to_str().map(|s| s.to_string()),
        _ => None,
    })
}

fn pathdiff(base: &Path, target: &Path) -> PathBuf {
    target
        .strip_prefix(base)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| target.to_path_buf())
}
