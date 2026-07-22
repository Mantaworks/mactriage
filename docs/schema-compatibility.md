# Report schema compatibility

mactriage currently emits report schema version `1`. Use `mactriage schema report` and `mactriage schema watch` to obtain the bundled JSON Schemas used by the installed binary.

Within a schema version, new optional fields, evidence IDs, finding codes, and action IDs may be added. Consumers must ignore unknown object properties and identifiers. Existing fields will not change type or meaning within the same version. A removal, required-field change, or incompatible meaning change requires a new schema version and a documented migration period.

Human output is intentionally not a machine interface. Automation should use `--json`, stable finding codes, evidence IDs, `completeness`, and exit policy. NDJSON consumers should process each line independently and ignore unknown event types.

Every report has a random `case_id` for matching a report to a help-desk conversation. It is not persistent identity and is not transmitted by mactriage.
