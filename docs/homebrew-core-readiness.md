# Homebrew Core readiness

The supported installation channel today is `Mantaworks/tap`. A `homebrew/core` submission will be opened only when mactriage meets Homebrew's current policies and has enough maintenance history to make Core support responsible.

This is a readiness record, not a growth target. mactriage does not collect telemetry and will not manufacture stars, downloads, forks, or other adoption signals.

## Official eligibility

Homebrew's [Package Acceptance Policy](https://docs.brew.sh/Package-Acceptance-Policy) and [Acceptable Formulae](https://docs.brew.sh/Acceptable-Formulae) are authoritative. As of 2026-07-24:

| Requirement | Status | Evidence |
| --- | --- | --- |
| Public project and homepage | Met | Public GitHub repository and project README |
| Active maintenance and no known unpatched vulnerability | Met today | CI, CodeQL, `govulncheck`, security policy, and maintained releases |
| Repository at least 30 days old | Not yet | Repository created 2026-07-22 |
| Owner-submission notability | Not yet | Policy normally requires 225 stars, 90 forks, or 90 watchers; current counts are 0/0/0 |
| Open-source, compatible license | Met | MIT |
| Stable immutable release | Met | Tagged GitHub releases with checksums, SBOMs, and attestations |
| Builds from source without downstream patches | Met in the tap | Formula builds the tagged Go source |
| Versioned, SHA-256-verified source | Met | Formula pins the tagged source archive and checksum |
| Formula type is appropriate | Met | mactriage is an open-source command-line tool, not a native `.app` bundle |
| Current strict online audit | Met today | `brew audit --strict --new --online Mantaworks/tap/mactriage` |
| Official Core CI matrix | Not tested | Available only as part of an eventual Core proposal |
| macOS-only restriction accepted as useful and maintainable | To be reviewed | Homebrew permits justified platform restrictions, but maintainers decide acceptance |

Meeting a numeric threshold does not guarantee acceptance. Homebrew maintainers retain discretion, and the current policy must be checked again immediately before any proposal.

## Project maturity gates

In addition to Homebrew's policy:

- releases must demonstrate at least 60 days of stable maintenance rather than several same-day tags;
- at least one stable release must be produced after the repository is 30 days old;
- supported release and security questions must receive a substantive response within seven days;
- no unresolved critical correctness, privacy, or security defect may remain;
- the tap formula must continue to build, audit, install, and test without tap-only source patches;
- release automation, checksums, SBOMs, provenance, and both macOS architecture builds must remain green;
- README installation and uninstall instructions must be accurate for a clean Mac.

## Submission procedure

When every gate above is met:

1. Re-read the live Homebrew policies and search open and closed Core pull requests for `mactriage`.
2. Run the validation commands from [Adding Software to Homebrew](https://docs.brew.sh/Adding-Software-to-Homebrew), including a clean source build, `brew test`, strict online audit, and `brew lgtm --online`.
3. Inspect the installed files and command output manually.
4. Open a single-formula Core pull request, disclose AI assistance as required by Homebrew's contribution policy, and remain available to address maintainer feedback.

Until then, keep issue #12 open and update this table only with verifiable public evidence.
