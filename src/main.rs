//! landlock-lint — focused detector for four recurring Rust Landlock misuses.
//!
//! Usage:
//!   landlock-lint <path>...
//!   landlock-lint <path>... --summary <out.md>
//!   landlock-lint <path>... --only P_SCOPE_GAP,P4

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use walkdir::WalkDir;

mod c_scanner;
mod patterns;
mod report;
mod visit;

use patterns::PatternId;
use report::FileFinding;

struct Args {
    roots: Vec<PathBuf>,
    summary: Option<PathBuf>,
    sarif: Option<PathBuf>,
    only: BTreeSet<PatternId>,
    explain: bool,
}

fn parse_args() -> Result<Args> {
    let mut roots = Vec::new();
    let mut summary = None;
    let mut sarif = None;
    let mut only: BTreeSet<PatternId> = PatternId::ALL.iter().copied().collect();
    let mut explain = false;

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "--explain" => {
                explain = true;
            }
            "--summary" => {
                let p = it
                    .next()
                    .context("--summary requires a path argument")?;
                summary = Some(PathBuf::from(p));
            }
            "--sarif" => {
                let p = it.next().context("--sarif requires a path argument")?;
                sarif = Some(PathBuf::from(p));
            }
            "--only" => {
                let list = it.next().context("--only requires a comma list")?;
                only.clear();
                for tok in list.split(',') {
                    let t = tok.trim();
                    let p = PatternId::parse(t)
                        .with_context(|| format!("unknown pattern id: {}", t))?;
                    only.insert(p);
                }
            }
            s if s.starts_with('-') => {
                anyhow::bail!("unknown flag: {}", s);
            }
            other => roots.push(PathBuf::from(other)),
        }
    }
    if roots.is_empty() {
        print_help();
        anyhow::bail!("no scan roots provided");
    }
    Ok(Args {
        roots,
        summary,
        sarif,
        only,
        explain,
    })
}

fn print_help() {
    eprintln!(
        "landlock-lint v0.1.3 — detector for recurring Landlock misuses (Rust + C)\n\
         \n\
         USAGE:\n  \
             landlock-lint <path>... [--explain] [--summary <out.md>] \\\n  \
                                     [--sarif <out.json>] [--only PAT1,PAT2,...]\n\
         \n\
         MODES:\n  \
             default     terse one-line-per-finding format (CI / reproduction)\n  \
             --explain   grouped per-file report with why-it-matters and fix\n  \
                          suggestions; recommended when scanning your own project\n\
         \n\
         PATTERNS (Rust .rs):\n  \
             P_SCOPE_GAP       handle_access(...) + restrict_self() but no .scope(...)\n  \
             P3                handle_access(...).is_ok() used as fake ABI probe\n  \
             P4                restrict_self() result discarded\n  \
             P_HARDCODED_ABI   ABI::V<n> literal with no real probe in the same file\n\
         \n\
         PATTERNS (C .c/.h):\n  \
             P_SCOPE_GAP       landlock_restrict_self() with no LANDLOCK_SCOPE_* / .scoped\n  \
             P4                landlock_restrict_self() return value discarded\n  \
             P_HARDCODED_ABI   ruleset built without LANDLOCK_CREATE_RULESET_VERSION probe\n  \
             P11               handled_access_fs set but LANDLOCK_ACCESS_FS_TRUNCATE\n  \
                                and/or LANDLOCK_ACCESS_FS_IOCTL_DEV not referenced\n  \
             (P3 has no clean C analogue and is intentionally not detected.)\n"
    );
}

fn main() -> Result<()> {
    let args = parse_args()?;
    let mut all_findings: Vec<FileFinding> = Vec::new();

    // For grouping in stdout, we anchor at the first root.
    let primary_root = args.roots[0].clone();

    for root in &args.roots {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_excluded(e.path()))
            .filter_map(|e| e.ok())
        {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            match p.extension().and_then(|s| s.to_str()) {
                Some("rs") => {
                    if let Ok(mut f) = analyse_rust_file(p, &args.only) {
                        all_findings.append(&mut f);
                    }
                    // syn parse errors on vendored / generated code: skip silently.
                }
                Some("c") | Some("h") => {
                    if let Ok(mut f) = analyse_c_file(p, &args.only) {
                        all_findings.append(&mut f);
                    }
                }
                _ => {}
            }
        }
    }

    // Stable order: by file, then line, then pattern.
    all_findings.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.finding.span.line.cmp(&b.finding.span.line))
            .then(a.finding.span.col.cmp(&b.finding.span.col))
            .then(a.finding.pattern.as_str().cmp(b.finding.pattern.as_str()))
    });

    if args.explain {
        report::print_explain(&primary_root, &all_findings);
    } else {
        report::print_stdout(&primary_root, &all_findings);
    }

    if let Some(s) = &args.summary {
        report::write_markdown_summary(s, &primary_root, &all_findings)
            .with_context(|| format!("writing summary to {}", s.display()))?;
        eprintln!("Summary written to {}", s.display());
    }

    if let Some(s) = &args.sarif {
        report::write_sarif(s, &primary_root, &all_findings)
            .with_context(|| format!("writing SARIF to {}", s.display()))?;
        eprintln!("SARIF written to {}", s.display());
    }

    Ok(())
}

fn is_excluded(p: &Path) -> bool {
    // Skip vendored / build / cache dirs to keep the scan focused on first-party src.
    let s = p
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    matches!(
        s,
        "target" | "vendor" | "node_modules" | ".git" | ".cache" | "_diffs" | "_failed_clones"
    )
}

fn analyse_rust_file(path: &Path, enabled: &BTreeSet<PatternId>) -> Result<Vec<FileFinding>> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let file = syn::parse_file(&src)
        .with_context(|| format!("parsing {}", path.display()))?;
    let collected = visit::collect(&file);
    let findings = patterns::detect_all(&collected, enabled);
    Ok(findings
        .into_iter()
        .map(|finding| FileFinding {
            path: path.to_path_buf(),
            finding,
        })
        .collect())
}

fn analyse_c_file(path: &Path, enabled: &BTreeSet<PatternId>) -> Result<Vec<FileFinding>> {
    let src = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let findings = c_scanner::scan_c_file(&src);
    Ok(findings
        .into_iter()
        .filter(|f| enabled.contains(&f.pattern))
        .map(|finding| FileFinding {
            path: path.to_path_buf(),
            finding,
        })
        .collect())
}
