# Contributing

`mactriage` supports macOS 13 and newer. Keep evidence collection, diagnosis rules, and presentation/actions as separate modules: collectors report facts, rules interpret them, and renderers never re-diagnose.

Before submitting a change:

```sh
make verify
```

Tests should exercise public package seams with fake command runners or sanitized fixtures. Never make a test restart a real daemon, alter Gatekeeper/SIP, remove quarantine metadata, or depend on private user logs.

New repair actions must be narrowly allowlisted, require a clear effect description and confirmation, default to No, support verification, and remain disabled in JSON/noninteractive execution.

Human-facing translation contributions follow [`docs/localization.md`](docs/localization.md). Never translate stable JSON fields, evidence IDs, finding/action codes, commands, or flags.
