package schema

import "encoding/json"

func Document(kind string) ([]byte, error) {
	properties := map[string]any{}
	required := []string{}
	switch kind {
	case "report":
		properties = map[string]any{
			"schema_version": map[string]any{"type": "string", "const": "1"},
			"case_id":        map[string]any{"type": "string", "pattern": "^MT-[A-F0-9]+$"},
			"command":        map[string]any{"type": "string"},
			"generated_at":   map[string]any{"type": "string", "format": "date-time"},
			"target":         map[string]any{"type": "string"},
			"host":           map[string]any{"type": "object"},
			"completeness":   map[string]any{"enum": []string{"complete", "partial"}},
			"evidence":       map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			"findings":       map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
			"actions":        map[string]any{"type": "array", "items": map[string]any{"type": "object"}},
		}
		required = []string{"schema_version", "command", "generated_at", "host", "completeness", "evidence", "findings", "actions"}
	case "watch":
		properties = map[string]any{
			"schema_version": map[string]any{"type": "string"},
			"timestamp":      map[string]any{"type": "string", "format": "date-time"},
			"type":           map[string]any{"type": "string"},
		}
		required = []string{"schema_version", "timestamp", "type"}
	default:
		return nil, &unknownKind{kind}
	}
	document := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "https://github.com/Mantaworks/mactriage/schema/" + kind + ".json", "title": "mactriage " + kind, "type": "object", "required": required, "properties": properties, "additionalProperties": true}
	return json.MarshalIndent(document, "", "  ")
}

type unknownKind struct{ value string }

func (e *unknownKind) Error() string { return "unknown schema kind " + e.value }
