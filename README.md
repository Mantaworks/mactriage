<p align="center">
  <img src="docs/assets/mactriage.svg" width="132" alt="MacTriage logo">
</p>

<h1 align="center">MacTriage</h1>

<p align="center">Understand what is wrong with a Mac app—and what to do next.</p>

`mactriage` supports macOS 13 Ventura and newer on Apple silicon and Intel Macs.

`mactriage` is a guided macOS application troubleshooter. It diagnoses launch failures, frozen or resource-heavy processes, privacy-permission denials, installed-app compatibility, and system resource pressure. Its reports combine bundle, code-signing, Gatekeeper, architecture, dependency, launch, crash, unified-log, process, and file-descriptor evidence into ranked findings written in plain language.

It is intentionally conservative: it does not disable Gatekeeper or SIP, rewrite signatures, reset security databases, recursively remove quarantine attributes, or delete application data.

## Install

Install with Homebrew on Apple silicon or Intel:

```sh
brew install Mantaworks/tap/mactriage
```

Homebrew downloads the tagged source and builds `mactriage` locally. No Apple Developer membership or Gatekeeper bypass is required.

Alternatively, install a prebuilt archive with the checksum-verifying installer:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Mantaworks/mactriage/main/install.sh | sh
```

The installer verifies the release archive against its published SHA-256 checksum and installs to `/usr/local/bin` when writable, otherwise `~/.local/bin`. Set `INSTALL_DIR` or `VERSION` to override either choice:

```sh
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Mantaworks/mactriage/main/install.sh | INSTALL_DIR="$HOME/bin" VERSION=v0.2.0 sh
```

To review the installer before running it, download [install.sh](install.sh) and execute it locally. To build from source, use Go 1.25.8 or newer:

```sh
make build
./bin/mactriage version
```

Prebuilt release archives are available for Apple silicon and Intel Macs with checksums and SBOMs. They are not Apple-notarized; Homebrew is the recommended installation path because its formula builds locally from tagged source.

## Start here

Run `mactriage` with no arguments:

```sh
mactriage
```

In a terminal it opens a colorful guided menu that asks what is wrong, requests only the target it needs, and runs the appropriate diagnostic. Terminal history remains intact. Scripts and experienced users can continue to use the regular subcommands and flags documented below.

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

## Diagnose a frozen or slow application

Inspect a process by name or PID:

```sh
mactriage hang Discord
mactriage hang 497 --cpu-threshold 70 --memory-threshold-mib 2048
```

The command reports state, CPU use, resident memory, thread count, and elapsed runtime. Raw stacks can contain private paths and symbols, so an Apple process sample is collected only when explicitly requested and is written atomically with mode `0600`:

```sh
mactriage hang Discord --sample-output discord.sample.txt
```

## Understand privacy-permission failures

```sh
mactriage permissions Zoom
mactriage permissions com.example.MyApp --lookback 30m
```

This inspects declared entitlements and bounded, correlated `tccd` events for explicit camera, microphone, screen-recording, Accessibility, Full Disk Access, Automation, Bluetooth, location, or contacts denials. It never reads or changes the TCC database. When useful, interactive mode offers to open Privacy & Security and defaults to No.

## Check installed applications

```sh
mactriage scan
mactriage scan /Applications --limit 500 --workers 8
mactriage scan --json --output app-health.json
```

The bounded concurrent scan identifies malformed bundles, missing or non-runnable executables, invalid signatures, unsupported minimum macOS versions, and Intel-only applications on Apple silicon. It scans standard application directories by default or one explicitly supplied directory.

## Create and work with support reports

Create a private sanitized ZIP containing exactly a JSON report, Markdown summary, and checksum manifest:

```sh
mactriage collect Discord --output discord-triage.zip
mactriage collect Discord --no-launch --output discord-passive.zip
```

The bundle never contains raw unified logs, crash reports, process samples, or unrelated paths. Other report tools are intentionally simple:

```sh
mactriage summarize report.json
mactriage compare before.json after.json
mactriage explain gatekeeper.rejected
```

`summarize` produces help-desk/GitHub-ready Markdown. `compare` shows new, resolved, unchanged, and evidence-status changes. `explain` translates a stable finding code into meaning, next steps, and safety boundaries.

## Inspect descriptor pressure

```sh
mactriage system
mactriage system --top 10
mactriage watch
mactriage watch syspolicyd --interval 5s --window 60s
mactriage watch 497 --duration 2m --json
```

`system --top` retains aggregate PID, process-name, and numeric-descriptor counts; it does not export paths opened by unrelated processes. `watch` follows daemon PID changes and reports descriptor growth, CPU, resident memory, threads, sockets, and available cumulative disk-read information. Its warning thresholds are configurable:

```sh
mactriage watch Discord \
  --cpu-threshold 80 \
  --memory-threshold-mib 4096 \
  --memory-free-threshold 10 \
  --threads-threshold 500 \
  --sockets-threshold 1000
```

`watch --include-paths` is explicit and applies only to the selected target.

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

`--json` emits schema version `1` and never includes animation or ANSI sequences. `watch --json` emits one NDJSON event per line. Reports and support artifacts written through `--output` use permission mode `0600` and an atomic rename.

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
