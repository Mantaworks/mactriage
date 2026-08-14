# Contributing

`mactriage` supports macOS 13 and newer. Keep evidence collection, diagnosis rules, and presentation/actions as separate modules: collectors report facts, rules interpret them, and renderers never re-diagnose.

Before submitting a change:

```sh
make verify
```

Tests should exercise public package seams with fake command runners or sanitized fixtures. Never make a test restart a real daemon, alter Gatekeeper/SIP, remove quarantine metadata, or depend on private user logs.

Third-party layout fixtures live in [`internal/macos/testdata`](internal/macos/testdata). They must be handwritten and synthetic: do not commit copied unified logs or crash reports, real user paths, SSIDs, IP addresses, or machine identifiers. Add or update a public-seam test whenever a fixture changes.

New repair actions must be narrowly allowlisted, require a clear effect description and confirmation, default to No, support verification, and remain disabled in JSON/noninteractive execution.

Human-facing translation contributions follow [`docs/localization.md`](docs/localization.md). Never translate stable JSON fields, evidence IDs, finding/action codes, commands, or flags.
