# Changelog

All notable user-facing changes to mactriage are documented here.

## v0.2.0

- Added a colorful guided home screen when `mactriage` is run without a subcommand.
- Added private sanitized support bundles with `collect`.
- Added frozen, slow, CPU-heavy, and memory-heavy process diagnosis with `hang`.
- Added privacy-permission denial diagnosis with `permissions` without reading or modifying the TCC database.
- Added bounded installed-application health inventories with `scan`.
- Added report comparison, Markdown summaries, and plain-language finding explanations.
- Extended `watch` with CPU, resident memory, threads, sockets, and available cumulative disk-read measurements.
- Preserved existing JSON/NDJSON contracts, safety boundaries, accessibility modes, and conventional subcommands.

## v0.1.0

- Initial public release with application launch diagnosis, descriptor-pressure inspection and monitoring, narrowly allowlisted `syspolicyd` recovery, JSON/NDJSON reports, shell completions, and Homebrew installation.
