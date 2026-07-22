# Releasing mactriage

Public releases intentionally happen only after the local release candidate passes acceptance.

## Required repositories

- `Mantaworks/mactriage`
- `Mantaworks/homebrew-tap`

## Required GitHub Actions secrets

| Secret | Purpose |
| --- | --- |
| `HOMEBREW_TAP_TOKEN` | Fine-grained GitHub token with Contents read/write access to `Mantaworks/homebrew-tap` |

The release workflow fails before building artifacts when the tap token is absent. The repository-scoped `GITHUB_TOKEN` cannot write to a second repository, so the tap requires its own fine-grained token. No paid Apple signing or notarization credentials are required: Homebrew builds the CLI from tagged source on the user's Mac.

## Local acceptance

```sh
make verify
go run ./cmd/gen-docs docs/generated
goreleaser check
goreleaser release --snapshot --clean
```

Inspect both archives, checksums, SBOMs, generated man pages, completions, plain output, JSON output, and the no-argument guided menu. Exercise `diagnose`, `collect`, `hang`, `permissions`, `scan`, `compare`, `summarize`, and `explain` with disposable fixtures. Confirm that raw samples require `--sample-output`, support bundles contain only their three declared files, and JSON/NDJSON remains free of ANSI and progress output. Do not exercise `repair syspolicyd` on a development machine merely to test a release.

After two clean acceptance passes, configure the tap secret, push `main`, and tag the accepted commit with a semantic version such as `v0.2.0`. The release workflow publishes both architecture archives, `checksums.txt`, and SBOMs; `install.sh` consumes those assets directly. For stable tags, the workflow also hashes GitHub's tagged source archive and publishes the matching source-built Homebrew formula.
