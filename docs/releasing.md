# Releasing mactriage

Public releases intentionally happen only after the local release candidate passes acceptance.

## Required repositories

- `Mantaworks/mactriage`
- `Mantaworks/homebrew-tap`

## Required GitHub Actions secrets

| Secret | Purpose |
| --- | --- |
| `HOMEBREW_TAP_TOKEN` | Fine-grained GitHub token with Contents read/write access to `Mantaworks/homebrew-tap` |
| `MACOS_SIGN_P12` | Base64-encoded Developer ID Application `.p12` certificate |
| `MACOS_SIGN_PASSWORD` | Password for the `.p12` certificate |
| `MACOS_NOTARY_KEY` | Base64-encoded App Store Connect `.p8` API key |
| `MACOS_NOTARY_KEY_ID` | App Store Connect API key ID |
| `MACOS_NOTARY_ISSUER_ID` | App Store Connect issuer UUID |

The release workflow fails before building artifacts when any secret is absent. GoReleaser signs and notarizes both standalone macOS binaries before they are archived, then updates `Casks/mactriage.rb` in the Homebrew tap. The repository-scoped `GITHUB_TOKEN` cannot write to a second repository, so the tap requires its own fine-grained token.

## Local acceptance

```sh
make verify
go run ./cmd/gen-docs docs/generated
goreleaser check
goreleaser release --snapshot --clean
```

Inspect both archives, checksums, SBOMs, generated man pages, completions, plain output, JSON output, and an interactive diagnostic on a disposable test app. Do not exercise `repair syspolicyd` on a development machine merely to test a release.

After two clean acceptance passes, configure the secrets, push `main`, and tag the accepted commit with a semantic version such as `v0.1.0`. The release workflow publishes both architecture archives, `checksums.txt`, and SBOMs; `install.sh` consumes those assets directly and GoReleaser publishes the matching Homebrew cask.
