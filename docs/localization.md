# Localization

Human-facing mactriage copy is separated from the stable diagnostic contract. Translations may change the guided menu, first-run help, and verdict labels; they must never translate JSON field names, evidence IDs, finding codes, action IDs, command names, flags, or values consumed by automation.

## Add a language

1. Copy `internal/localize/catalog/en.json` to `internal/localize/catalog/<language-tag>.json`. Use a lowercase BCP 47-style tag such as `fr.json` or `pt-br.json`.
2. Translate every value without changing its key. Preserve placeholders, example commands, paths, and product names unless the example is genuinely language-specific.
3. Add `docs/i18n/README.<language-tag>.md` as a translated first-run guide. Keep install commands and safety claims equivalent to the English README.
4. Run:

   ```sh
   go test ./internal/localize ./internal/present ./internal/cli
   make verify
   ```

5. In the pull request, name the translator and reviewer and describe how the safety-sensitive wording was checked.

mactriage selects human copy using `LC_ALL`, then `LC_MESSAGES`, then `LANG`. Region-specific tags fall back to their base language and missing keys fall back to English. JSON and NDJSON output are locale-independent.

## Check localization coverage

The built-in `en-XA` pseudo-locale brackets localized text so hard-coded English is easier to spot:

```sh
LC_ALL=en_XA.UTF-8 mactriage --plain
LC_ALL=en_XA.UTF-8 mactriage --plain doctor --only storage
```

The pseudo-locale is for development and must not be presented as a natural-language translation.

## Translation boundaries

Translate:

- guided-menu questions, options, input labels, and validation messages;
- first-run help labels and hints;
- human verdict labels.

Do not translate:

- report schema fields or enum values;
- evidence IDs and finding/action codes;
- subcommands, flags, shell snippets, bundle IDs, or paths;
- raw macOS command output, which is parsed under a normalized locale.

Keep safety language exact in meaning. In particular, translations must not imply that mactriage automatically deletes files, changes settings, installs updates, bypasses macOS security, or performs an action without confirmation.
