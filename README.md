<p align="center">
  <img src="docs/assets/mactriage.svg" width="132" alt="MacTriage logo">
</p>

<h1 align="center">MacTriage</h1>

<p align="center">Find out why a macOS app will not launch.</p>

`mactriage` supports macOS 13 Ventura and newer on Apple silicon and Intel Macs.

`mactriage` explains why a macOS application will not launch. It combines bundle, code-signing, Gatekeeper, architecture, dependency, launch, crash, unified-log, and file-descriptor evidence into a single ranked diagnosis.

It is intentionally conservative: it does not disable Gatekeeper or SIP, rewrite signatures, reset security databases, recursively remove quarantine attributes, or delete application data.

## Install

Install the latest signed release on Apple silicon or Intel:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Mantaworks/mactriage/main/install.sh | sh
```

The installer verifies the release archive against its published SHA-256 checksum and installs to `/usr/local/bin` when writable, otherwise `~/.local/bin`. Set `INSTALL_DIR` or `VERSION` to override either choice:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Mantaworks/mactriage/main/install.sh | INSTALL_DIR="$HOME/bin" VERSION=v0.1.0 sh
```

To review the installer before running it, download [install.sh](install.sh) and execute it locally. To build from source, use Go 1.25.8 or newer:

```sh
make build
./bin/mactriage version
```

Release artifacts are built for Apple silicon and Intel Macs, signed with a Developer ID certificate, notarized by Apple, and accompanied by checksums and SBOMs.

## Diagnose an application

Names, `.app` paths, and bundle identifiers are accepted:

```sh
mactriage diagnose Discord
mactriage diagnose /Applications/Discord.app
mactriage diagnose com.hnc.Discord
```

An active diagnosis explains its steps, launches the app, observes it for five seconds, and correlates evidence from the same period. It skips the active launch test if the app is already running.

Useful controls:

```sh
mactriage diagnose Discord --no-launch
mactriage diagnose Discord --observe 10s
mactriage diagnose Discord --new-instance
mactriage diagnose Discord --privileged
mactriage diagnose Discord --json --output report.json
```

`--privileged` can count descriptors owned by protected system processes. In an interactive terminal, mactriage explains why access is needed and offers to rerun itself through `sudo`.

## Inspect descriptor pressure

```sh
mactriage system
mactriage system --top 10
mactriage watch
mactriage watch syspolicyd --interval 5s --window 60s
mactriage watch 497 --duration 2m --json
```

`system --top` retains aggregate PID, process-name, and numeric-descriptor counts; it does not export paths opened by unrelated processes. `watch --include-paths` is explicit and applies only to the selected target.

## Safe recovery

When evidence strongly indicates a wedged `syspolicyd`, an interactive diagnosis offers to restart it. The action is shown in advance, defaults to No, elevates only after permission, verifies that launchd starts a new PID, and reruns the affected diagnosis.

The same action can be requested directly:

```sh
mactriage repair syspolicyd
sudo mactriage repair syspolicyd --yes
```

JSON and other noninteractive modes never prompt or mutate the system.

## Terminal and automation modes

Interactive terminals receive an inline animated checklist and color-coded findings. Every color also has a text label.

```sh
mactriage --plain diagnose Discord
mactriage --accessible diagnose Discord
mactriage --color never --animation never diagnose Discord
NO_COLOR=1 mactriage diagnose Discord
```

`--json` emits schema version `1` and never includes animation or ANSI sequences. `watch --json` emits one NDJSON event per line. `--output` writes sanitized files with permission mode `0600` using an atomic rename.

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Healthy result, successful repair, or normal watch completion |
| 1 | Confident error/critical diagnosis or failed repair |
| 2 | Invalid command or operational failure |
| 3 | Insufficient evidence or inconclusive result |
| 130 | Interrupted |

## Development

```sh
make test
make verify
make docs
make snapshot
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [docs/releasing.md](docs/releasing.md).
