# Changelog

All notable user-facing changes to mactriage are documented here.

## v0.4.0 — The Follow-Through Release

- Added Quick, Full, and Fleet Doctor profiles with explicit verdicts, case IDs, top-three next steps, and unknown-check labels.
- Added battery condition, thermal-limit, Time Machine freshness, aggregate storage-detail, sanitized startup-item, and deeper network evidence.
- Added permission-gated, verified shortcuts to the relevant macOS Settings panes and Activity Monitor; mactriage still changes no setting itself.
- Added `schema`, `--fail-on`, `--total-timeout`, `--offline`, and `--redact strict` for help-desk and fleet automation.
- Expanded baseline health metrics and preserved schema-1 compatibility, private atomic output, and non-mutating JSON behavior.
- Added reproducibility checks, pinned CI actions, CodeQL, OpenSSF Scorecard, Dependabot, release attestations, MDM examples, and community templates.

## v0.3.0 — The Doctor Command

- Added `doctor`, a fast concurrent whole-Mac health check with severity and check filters plus an optional permission-gated action flow.
- Added DNS, routing, proxy, VPN, HTTPS, TLS, and listening-socket diagnosis with `network`.
- Added `relaunch`, which warns about unsaved work, prefers `SIGTERM`, separately confirms `SIGKILL`, and verifies recovery.
- Added private `baseline save`, `list`, `compare`, and `delete` workflows with health-metric and Intel-only-app comparisons.
- Added sanitized Markdown sharing from a report or passive app diagnosis, with previewed permission-gated clipboard copy and no upload.
- Expanded the guided home around everyday symptoms including a slow Mac, network trouble, baselines, relaunching, and support reports.
- Added plain-language finding codes for system health and network problems while preserving schema `1`, existing commands, and safety boundaries.

## v0.2.0

- Added a colorful guided home screen when `mactriage` is run without a subcommand.
- Added private sanitized support bundles with `collect`.
- Added frozen, slow, CPU-heavy, and memory-heavy process diagnosis with `hang`.
- Added privacy-permission denial diagnosis with `permissions` without reading or modifying the TCC database.
- Added bounded installed-application health inventories with `scan`.
- Added report comparison, Markdown summaries, and plain-language finding explanations.
- Extended `watch` with CPU, resident memory, threads, and sockets; exact disk byte counters remain optional and are never estimated from page faults.
- Preserved existing JSON/NDJSON contracts, safety boundaries, accessibility modes, and conventional subcommands.

## v0.1.0

- Initial public release with application launch diagnosis, descriptor-pressure inspection and monitoring, narrowly allowlisted `syspolicyd` recovery, JSON/NDJSON reports, shell completions, and Homebrew installation.
