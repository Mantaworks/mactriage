package schema

import "encoding/json"

func Document(kind string) ([]byte, error) {
	properties := map[string]any{}
	required := []string{}
	switch kind {
	case "report":
		evidence := object([]string{"id", "status", "summary"}, map[string]any{
			"id": map[string]any{"type": "string"}, "status": map[string]any{"enum": []string{"ok", "partial", "failed", "unavailable", "timed_out", "skipped"}},
			"summary": map[string]any{"type": "string"}, "data": map[string]any{"type": "object"}, "error": map[string]any{"type": "string"},
		})
		finding := object([]string{"code", "severity", "title", "explanation", "confidence"}, map[string]any{
			"code": map[string]any{"type": "string"}, "severity": map[string]any{"enum": []string{"info", "warning", "error", "critical"}},
			"title": map[string]any{"type": "string"}, "explanation": map[string]any{"type": "string"}, "confidence": map[string]any{"enum": []string{"low", "medium", "high"}},
			"evidence_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "subjects": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "recommendation": map[string]any{"type": "string"},
		})
		action := object([]string{"id", "title", "description", "requires_root", "available"}, map[string]any{
			"id": map[string]any{"type": "string"}, "title": map[string]any{"type": "string"}, "description": map[string]any{"type": "string"},
			"command": map[string]any{"type": "array", "items": map[string]any{"type": "string"}}, "requires_root": map[string]any{"type": "boolean"}, "available": map[string]any{"type": "boolean"},
		})
		properties = map[string]any{
			"schema_version": map[string]any{"type": "string", "const": "1"},
			"case_id":        map[string]any{"type": "string", "pattern": "^MT-[A-F0-9]+$", "description": "Always emitted by current binaries; optional only for schema-1 backward compatibility."},
			"command":        map[string]any{"type": "string"},
			"generated_at":   map[string]any{"type": "string", "format": "date-time"},
			"target":         map[string]any{"type": "string"},
			"host":           object(nil, map[string]any{"os_version": map[string]any{"type": "string"}, "build": map[string]any{"type": "string"}, "arch": map[string]any{"type": "string"}}),
			"completeness":   map[string]any{"enum": []string{"complete", "partial"}},
			"evidence":       map[string]any{"type": "array", "items": evidence},
			"findings":       map[string]any{"type": "array", "items": finding},
			"actions":        map[string]any{"type": "array", "items": action},
		}
		required = []string{"schema_version", "command", "generated_at", "host", "completeness", "evidence", "findings", "actions"}
	case "watch":
		properties = map[string]any{
			"schema_version": map[string]any{"type": "string", "const": "1"},
			"timestamp":      map[string]any{"type": "string", "format": "date-time"},
			"type":           map[string]any{"type": "string"},
			"target":         map[string]any{"type": "string"}, "pid": map[string]any{"type": "integer", "minimum": 1},
			"descriptor_count": map[string]any{"type": "integer", "minimum": 0}, "growth": map[string]any{"type": "integer"}, "growth_per_second": map[string]any{"type": "number"}, "window_seconds": map[string]any{"type": "integer", "minimum": 0},
			"severity": map[string]any{"enum": []string{"info", "warning", "error", "critical"}}, "message": map[string]any{"type": "string"},
			"by_type": counts(), "by_path": counts(), "cpu_percent": map[string]any{"type": "number"}, "rss_bytes": map[string]any{"type": "integer", "minimum": 0},
			"threads": map[string]any{"type": "integer", "minimum": 0}, "socket_count": map[string]any{"type": "integer", "minimum": 0}, "disk_read_bytes": map[string]any{"type": "integer", "minimum": 0}, "disk_write_bytes": map[string]any{"type": "integer", "minimum": 0}, "memory_free_percent": map[string]any{"type": "number"}, "restart_count": map[string]any{"type": "integer", "minimum": 0},
		}
		required = []string{"schema_version", "timestamp", "type", "target", "severity", "message"}
	default:
		return nil, &unknownKind{kind}
	}
	document := map[string]any{"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "https://github.com/Mantaworks/mactriage/schema/" + kind + ".json", "title": "mactriage " + kind, "type": "object", "required": required, "properties": properties, "additionalProperties": true}
	return json.MarshalIndent(document, "", "  ")
}

func object(required []string, properties map[string]any) map[string]any {
	value := map[string]any{"type": "object", "properties": properties, "additionalProperties": true}
	if len(required) > 0 {
		value["required"] = required
	}
	return value
}

func counts() map[string]any {
	return map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "integer", "minimum": 0}}
}

type unknownKind struct{ value string }

func (e *unknownKind) Error() string { return "unknown schema kind " + e.value }
