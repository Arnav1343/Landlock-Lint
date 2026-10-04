# Evidence: corpus scan behind the paper's numbers

This directory pins the corpus scan that produced the "102 findings across 33
project sites" figure cited throughout "Landlock in Practice: An Empirical
Study of Common Deployment Errors and Their Security Impact" (ICISS), Sections
4.4, 6.1, and 7.4.

- **`corpus-manifest.md`** — the 58 scanned repositories, grouped by tier, each
  pinned to the exact commit that was scanned. We do not redistribute the
  third-party source itself; clone each repository at the listed commit to
  reconstruct the corpus.
- **`findings.txt`** — raw `path:line:col  PATTERN_ID  message` output from this
  tag (`v0.1.2`) against the reconstructed corpus. 102 lines of findings plus
  the trailing count.
- **`summary.md`** — the `--summary` markdown table (project × pattern counts
  per tier) from the same run.

## Reproducing

```sh
git clone https://github.com/Arnav1343/Landlock-Lint.git
cd Landlock-Lint
git checkout v0.1.2
cargo build --release

# Clone each project in corpus-manifest.md at its pinned commit into
# tier1/, tier2_go/, tier2_rust/, tier3_ai_agents/, tier3_fork_cluster/,
# tier3_individual/ respectively, then:
target/release/landlock-lint \
    tier1 tier2_go tier2_rust tier3_ai_agents tier3_fork_cluster tier3_individual \
    --summary my-summary.md
```

Expected: 102 findings across 33 project sites, matching `findings.txt` and
`summary.md` in this directory. (`tier3_fork_cluster` contributes zero
findings — it is included for corpus completeness, not because it's expected
to produce output.)

## What's not here

Proof-of-concept evidence (the differential-triad JSON cells referenced in
Section 6.1) is withheld until the coordinated-disclosure windows described in
Section 4.5 of the paper close, to avoid publishing exploit detail for
unpatched projects ahead of maintainer coordination.
