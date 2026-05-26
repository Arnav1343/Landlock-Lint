# landlock-lint

A focused static analyser for misuse patterns in [Landlock](https://docs.kernel.org/userspace-api/landlock.html) sandbox code.

Detects eight recurring bugs across Rust (the [`landlock`](https://crates.io/crates/landlock) crate) and C (raw `landlock_*` syscalls). Each finding cites a specific file, line, and column, with a one-line explanation of why it matters — or, with `--explain`, a full why-it-matters paragraph and a concrete code fix.

## Why this exists

Landlock is a Linux LSM that lets userspace processes sandbox themselves. The API is small, but easy to use incorrectly in ways that compile, run, and *look* like a sandbox while leaving real escapes open. The most prominent example is [GHSA-27vp-2mmc-vmh3](https://github.com/advisories/GHSA-27vp-2mmc-vmh3) — a V6-scope gap that lets a sandboxed process escape via abstract Unix sockets to the systemd user bus.

`landlock-lint` mechanically detects that gap and seven related patterns, so reviewers don't have to grep by hand.

## Install

```sh
git clone https://github.com/Arnav1343/Landlock-Lint.git
cd Landlock-Lint
cargo build --release
```

The binary lands at `target/release/landlock-lint`. Rust 1.70+ is sufficient; only four crates (`syn`, `walkdir`, `anyhow`, `proc-macro2`).

## Usage

```sh
landlock-lint <path>... [--explain] [--summary <out.md>] [--sarif <out.json>] [--only PAT1,PAT2,...]
```

- `<path>...` — one or more directories or files. The walker excludes `target/`, `vendor/`, `node_modules/`, `.git/`, and `.cache/`.
- `--explain` — grouped per-file report with why-it-matters paragraphs and concrete fix suggestions. **Recommended when scanning your own project.**
- `--summary <out.md>` — emit a markdown table of findings per top-level subdirectory (useful when scanning multiple projects).
- `--sarif <out.json>` — emit SARIF 2.1.0 for ingestion by GitHub Code Scanning, VS Code SARIF Viewer, etc.
- `--only PAT1,PAT2,...` — restrict to specific pattern IDs (e.g. `--only P_SCOPE_GAP,P11`).

### Modes at a glance

Default (terse — for CI / scripts):

```text
src/sandbox.rs:32:18  P_SCOPE_GAP  ruleset calls handle_access(...) and restrict_self() but never .scope(...); GHSA-27vp-2mmc-vmh3 abstract-Unix-socket escape applies.
src/sandbox.rs:33:18  P3  Ruleset::default().handle_access(...).is_ok() used as an ABI probe; handle_access() returns Ok for any value under BestEffort, so this 'probe' is a no-op.
src/sandbox.rs:88:14  P4  restrict_self()'s RestrictionStatus is discarded; RulesetStatus::NotEnforced / PartiallyEnforced become silent happy paths.
```

`--explain` (grouped, human-readable — for developers):

```text
landlock-lint v0.1.2
Scanned: my-project

Found 3 issue(s) in 1 file(s).

────────────────────────────────────────────────────────────────────────
src/sandbox.rs
────────────────────────────────────────────────────────────────────────

  [1] P_SCOPE_GAP  —  line 32, col 18
      Sandbox is missing V6 scope rules — can be escaped via abstract Unix sockets.

      Why it matters:
        A sandboxed process can connect to abstract Unix sockets in the same
        user session — including the systemd user bus at /run/user/$UID/bus —
        and ask the host session to run commands outside the sandbox.
        This is GHSA-27vp-2mmc-vmh3, fixed in nono-rs v0.55.0.

      How to fix:
        Chain `.scope(Scope::AbstractUnixSocket | Scope::Signal)` onto your
        ruleset before calling `.restrict_self()`.
        ...
```

## Patterns detected

### Rust (`.rs`)

| ID | What it catches | Why it matters |
|---|---|---|
| `P_SCOPE_GAP` | Same-file `handle_access(...)` + `restrict_self()` with no `.scope(...)` call | GHSA-27vp-2mmc-vmh3 abstract-Unix-socket / signal escape applies |
| `P3` | Method chain containing `handle_access(...)` terminating in `.is_ok()` | Under `CompatLevel::BestEffort` (the default) `handle_access` returns `Ok` for any ABI value — the "probe" always picks the literal first ABI |
| `P4` | `restrict_self()` whose returned `RestrictionStatus` is dropped (`let _ = …`, bare `;`, `?;` with no `.ruleset` inspection) | `RulesetStatus::NotEnforced` / `PartiallyEnforced` become silent happy paths |
| `P_HARDCODED_ABI` | An `ABI::V<n>` literal in a landlock-relevant context with no probe in the same file (no `handle_access().is_ok()` chain and no array literal of ≥2 distinct ABIs) | Hardcoding silently misses newer ABIs on supporting kernels — `V5` misses V6 scope (the GHSA fix), V7 net rules, etc. |

### C (`.c` / `.h`)

| ID | What it catches | Why it matters |
|---|---|---|
| `P_SCOPE_GAP` | A real `landlock_restrict_self(...)` *call site* (not the syscall-wrapper shim) without any `LANDLOCK_SCOPE_*` reference or `.scoped` assignment | Same GHSA-27vp-2mmc-vmh3 mapping, raw-syscall edition |
| `P4` | `landlock_restrict_self(...)` return value not consumed by `if`, comparison, assignment, or `return` on the same statement | On failure the process continues un-sandboxed with no signal to the caller |
| `P_HARDCODED_ABI` | `landlock_create_ruleset(&...)` with mask composed from `LANDLOCK_*` symbols but no `LANDLOCK_CREATE_RULESET_VERSION` probe in the same file | Hardcoded masks silently miss newer ABIs |
| `P11` | `handled_access_fs` set but `LANDLOCK_ACCESS_FS_TRUNCATE` (V3) and/or `LANDLOCK_ACCESS_FS_IOCTL_DEV` (V5) never referenced | `ftruncate()` and `ioctl()` on device files bypass the sandbox entirely |

P3 (fake `.is_ok()` ABI probe) has no clean C analogue and is intentionally not detected in C. The C-side version-probe idiom is the syscall `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`; the corresponding misuse — "no probe at all" — is what `P_HARDCODED_ABI` catches.

## Design choices

`landlock-lint` is a focused prototype, not a production-grade linter. The design favours **precision over recall**:

- Rust analysis is `syn`-based AST walking. No type inference, no name resolution, no borrow checker. If a non-Landlock crate exposes a `handle_access` method on a similarly-shaped builder, it could false-positive. Manual confirmation of every finding is the contract.
- C analysis is line-level pattern matching with declaration/call disambiguation (the syscall-wrapper shim `static inline int landlock_restrict_self(...)` is correctly skipped). No full C parser. Multi-line C statements split across many physical lines could fool the P4 statement-context check.
- Both sides are file-scoped. A project that splits ruleset construction across modules (e.g. `handle_access` in one file, `restrict_self` in another) will be under-counted.
- Test code (`#[cfg(test)] mod tests`) is skipped on the Rust side because test code legitimately pins specific ABI literals.
- `target/`, `vendor/`, `node_modules/`, `.git/`, `.cache/` are excluded by the walker.

The false-positive contract: if a finding is reported, the cited file:line should land on a call/literal a maintainer can act on. If a pattern can't be distinguished from a benign use without cross-file or type information, the tool stays silent.

## Output formats

| Mode | Format | Use case |
|---|---|---|
| Default | `path:line:col  PATTERN_ID  message` per finding, total at end | CI, scripts, grep-friendly piping |
| `--explain` | Grouped per-file, headline + why-it-matters + fix snippet | Developer scanning their own project |
| `--summary <out.md>` | Markdown table: project × pattern counts | Surveying multiple projects |
| `--sarif <out.json>` | SARIF 2.1.0 | GitHub Code Scanning, VS Code SARIF Viewer, security dashboards |

## Examples

Scan your project, get a human-readable report:

```sh
landlock-lint ./src --explain
```

Scan, emit SARIF for GitHub Code Scanning:

```sh
landlock-lint ./src --sarif results.sarif
```

Restrict to the GHSA-27vp-2mmc-vmh3 scope-gap pattern only:

```sh
landlock-lint ./src --only P_SCOPE_GAP
```

Scan multiple projects, get a comparison table:

```sh
landlock-lint ./project-a ./project-b ./project-c --summary survey.md
```

## Exit code

The binary exits 0 whether or not findings are reported (this is by design — a linter run is informational, not a CI fail signal). For CI-fail behaviour, count lines: `landlock-lint ./src | wc -l` and fail if non-zero, or parse the SARIF output.

## Limitations and roadmap

Known gaps:

- **Cross-file analysis** — a `restrict_self()` in one file and a `handle_access()` in another will not be linked. Real-world Rust projects sometimes do this; a future version will track Landlock builder symbols across the crate.
- **Macro expansion** — Landlock calls wrapped in macros are invisible to the AST visit. None of the projects in the original test corpus do this.
- **C-side full parser** — currently regex/line-level. A `tree-sitter-c` rewrite is planned.
- **`--fix` mode** — print a suggested patch per finding.

## Patterns reference

For background on each pattern and the threat model:

- **GHSA-27vp-2mmc-vmh3**: https://github.com/advisories/GHSA-27vp-2mmc-vmh3
- **Landlock ABI versions** (V1–V7+ feature list): https://docs.kernel.org/userspace-api/landlock.html#access-rights
- **Kernel sample `samples/landlock/sandboxer.c`**: a reference correct-shape C user.
- **`nono-rs` v0.55.0**: a reference correct-shape Rust user that probes the ABI and sets V6 scope.

## Contributing

Issues and PRs welcome. If you find a false positive, please report it with the file:line and surrounding source context — the rule will be tightened. If you find a false negative on a real project, send the file (or a minimal reproducer) and the rule can be loosened or extended.

## License

MIT — see [LICENSE](LICENSE).
