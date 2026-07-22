# Managed Mac and help-desk examples

mactriage has no daemon, telemetry, persistent device identity, or remote-control channel. An MDM or support tool can deploy the Homebrew package or signed-off internal package and invoke the ordinary CLI.

## Fast fleet check

```sh
mactriage --plain --json --fail-on warning --total-timeout 60s doctor --profile fleet >mactriage.json
```

Use a private output location in production. Exit `1` means the configured threshold was met, `2` means the command could not operate, and `3` means evidence was incomplete.

## Offline collection

```sh
mactriage --plain --json --offline --redact strict doctor --full --output /private/var/tmp/mactriage.json
```

The output file is written atomically with mode `0600`. Strict mode removes user paths and app/process identities while retaining aggregate health facts and diagnostic codes.

## Validate the contract

```sh
mactriage schema report >mactriage-report.schema.json
mactriage schema watch >mactriage-watch.schema.json
```

Treat new optional fields and identifiers as forward-compatible. See [schema compatibility](schema-compatibility.md).

## Safety boundary

Noninteractive and JSON runs never prompt or mutate. Managed automation should not pass `repair` or interactive `--fix`; those workflows are intended for an informed person at the Mac.
