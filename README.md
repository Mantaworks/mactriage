<p align="center">
  <img src="docs/assets/mactriage.svg" width="132" alt="MacTriage logo">
</p>

<h1 align="center">MacTriage</h1>

<p align="center">Understand what is wrong with your Mac—and what to do next.</p>

<p align="center">
  <a href="https://github.com/Mantaworks/mactriage/actions/workflows/ci.yml"><img src="https://github.com/Mantaworks/mactriage/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/Mantaworks/mactriage"><img src="https://api.scorecard.dev/projects/github.com/Mantaworks/mactriage/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://github.com/Mantaworks/mactriage/releases"><img src="https://img.shields.io/github/v/release/Mantaworks/mactriage" alt="Latest release"></a>
</p>

`mactriage` supports macOS 13 Ventura and newer on Apple silicon and Intel Macs.

`mactriage` is a guided, privacy-first macOS troubleshooter for slow Macs, broken apps, network and permission problems, crashes, and safe recovery. **v0.4.0 — The Follow-Through Release** adds fast/full/fleet Doctor profiles, battery/thermal/backup health, storage and startup workflows, deeper network diagnosis, strict redaction, stable schemas, and permission-gated shortcuts to the right macOS surface.

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
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Mantaworks/mactriage/main/install.sh | INSTALL_DIR="$HOME/bin" VERSION=v0.4.0 sh
```

To review the installer before running it, download [install.sh](install.sh) and execute it locally. To build from source, use Go 1.25.8 or newer:

```sh
make build
./bin/mactriage version
```

Prebuilt release archives are available for Apple silicon and Intel Macs with checksums and SBOMs. They are not Apple-notarized; Homebrew is the recommended installation path because its formula builds locally from tagged source.

## 30-second start

Run `mactriage` with no arguments:

```sh
mactriage
```

In a terminal it opens a colorful guided menu that asks what is wrong, requests only the target it needs, and runs the appropriate diagnostic. Terminal history remains intact. Scripts and experienced users can continue to use the regular subcommands and flags documented below.

For the fastest read-only health check:

```sh
mactriage doctor --quick
```

The result starts with `LOOKS GOOD`, `CHECK RECOMMENDED`, `NEEDS ATTENTION`, or `INCOMPLETE`, includes a non-identifying case ID, and lists at most three best next steps.

![Animated mactriage quick Doctor run](docs/assets/mactriage-demo.gif)

The demo is reproducible from [`docs/demo.tape`](docs/demo.tape) with [VHS](https://github.com/charmbracelet/vhs).

## The Doctor Command

Run a bounded, read-only health check across the Mac:

```sh
mactriage doctor
mactriage doctor --quick
mactriage doctor --full
mactriage doctor --profile fleet --json
mactriage doctor --severity warning
mactriage doctor --only storage,memory,cpu,network
mactriage doctor --skip updates,apps
mactriage doctor --json --output doctor.json
```

Quick Doctor checks startup-disk capacity, memory and swap pressure, CPU load, descriptor pressure, core services, and network health. Full Doctor also checks cached updates, crashes, restart loops, startup items, application compatibility, battery condition, thermal limits, and Time Machine freshness. Fleet omits update availability for a more stable automation contract. Doctor's compatibility pass skips deep signature verification; use `mactriage scan` for that slower integrity check.

`doctor --fix` may offer to open Storage, Network, Login Items, Battery, Time Machine, Software Update, Privacy & Security, or Activity Monitor. Every action is explained, separately confirmed, defaults to No, and is verified. It never deletes files, removes login items, installs an update, or changes a system setting.

## Understand storage and startup load

```sh
mactriage storage
mactriage storage --details
mactriage startup
```

Storage details report only aggregate sizes for standard categories; filenames are neither displayed nor exported. Startup reports sanitized registered item names/identifiers, or clearly labels its launch-agent fallback. Neither command removes or disables anything.

## Diagnose network trouble

```sh
mactriage network
mactriage network example.com
mactriage network internal.example --json
mactriage network --detail
```

The default target is `example.com`. The command checks DNS resolution, the default route, configured proxies, active VPN tunnel interfaces, HTTPS/TLS, and aggregate listening-socket count. `--detail` additionally checks interface availability, self-assigned addressing, Wi-Fi power/association, DNS-server presence, plain HTTP, and clock plausibility. It exports no SSID, local IP, DNS address, or response body, and never changes network settings.

## Safely relaunch an application

```sh
mactriage relaunch Discord
```

Interactive mode shows the exact running PIDs and warns about unsaved work. After confirmation, it requests graceful termination with `SIGTERM`, waits, reopens the application, and verifies that it survives the observation window. If the app refuses to quit, `SIGKILL` requires a second default-No confirmation. JSON and noninteractive runs report the available action without performing it.

## Save and compare healthy baselines

```sh
mactriage baseline save healthy-morning
mactriage baseline save healthy-morning --storage-details
mactriage baseline list
mactriage baseline compare healthy-morning
mactriage baseline compare healthy-morning --storage-details
mactriage baseline compare healthy-morning after-update
mactriage baseline delete healthy-morning
```

Baselines are sanitized Doctor reports stored atomically with mode `0600` under `~/Library/Application Support/mactriage/baselines`. Comparisons show new and resolved findings, evidence-status changes, disk/memory/CPU/descriptor/startup/battery/thermal/backup metric changes, and newly Intel-only apps. `--storage-details` explicitly adds aggregate standard-folder changes without retaining filenames. Deletion affects only the named baseline and requires confirmation (`--yes` is mandatory when noninteractive).

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
mactriage share report.json --output issue.md
mactriage share Discord --copy
```

`summarize` produces help-desk/GitHub-ready Markdown. `share` accepts a saved report or performs a passive app diagnosis, previews sanitized Markdown, writes private output, and offers clipboard copy only after permission; it never uploads. `compare` shows finding, evidence, and health-metric changes. `explain` translates a stable finding code into meaning, next steps, and safety boundaries.

## Inspect descriptor pressure

```sh
mactriage system
mactriage system --top 10
mactriage watch
mactriage watch syspolicyd --interval 5s --window 60s
mactriage watch 497 --duration 2m --json
```

`system --top` retains aggregate PID, process-name, and numeric-descriptor counts; it does not export paths opened by unrelated processes. `watch` follows daemon PID changes and reports descriptor growth, CPU, resident memory, threads, and sockets. Disk byte counters are emitted only when macOS supplies an exact process-level source; page faults are never presented as disk I/O. Its warning thresholds are configurable:

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

When evidence strongly indicates a wedged `syspolicyd`, an interactive diagnosis offers to restart it. The action is shown in advance, defaults to No, elevates only after permission, verifies that launchd starts a new PID, and reruns the affected diagnosis. Doctor, relaunch, and share follow the same explain-confirm-verify model.

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

Automation controls are global:

```sh
mactriage --fail-on warning doctor --profile fleet --json
mactriage --total-timeout 45s doctor --quick
mactriage --offline doctor --full
mactriage --redact strict diagnose Discord --no-launch --json
mactriage schema report
mactriage schema watch
```

`--offline` skips Doctor network/update probes and rejects an explicitly requested `network` command. Strict redaction keeps codes, severities, and aggregate measurements while removing app/process identities and user paths. See [schema compatibility](docs/schema-compatibility.md) and [managed-fleet examples](docs/mdm.md).

Exit codes:

| Code | Meaning |
| ---: | --- |
| 0 | Healthy result, successful repair, or normal watch completion |
| 1 | Confident error/critical diagnosis or failed repair |
| 2 | Invalid command or operational failure |
| 3 | Insufficient evidence or inconclusive result |
| 130 | Interrupted |

## Verify release provenance

Releases include SHA-256 checksums, per-archive SBOMs, and GitHub artifact attestations. After downloading an archive:

```sh
shasum -a 256 -c checksums.txt
gh attestation verify mactriage_0.4.0_darwin_arm64.tar.gz --repo Mantaworks/mactriage
```

Homebrew remains the easiest installation route. The project tracks [Homebrew Core readiness](ROADMAP.md) but will not submit prematurely.

## Development

```sh
make test
make verify
make reproducible
make docs
make snapshot
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md), [ROADMAP.md](ROADMAP.md), and [docs/releasing.md](docs/releasing.md). Questions and feature ideas are welcome in [GitHub Discussions](https://github.com/Mantaworks/mactriage/discussions).
