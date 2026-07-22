package knowledge_test

import (
	"testing"

	"github.com/Mantaworks/mactriage/internal/knowledge"
)

func TestLookupExplainsStableFindingCodeForLayperson(t *testing.T) {
	entry, ok := knowledge.Lookup("gatekeeper.rejected")
	if !ok {
		t.Fatal("known finding code was not found")
	}
	if entry.Meaning == "" || entry.Next == "" || entry.Safety == "" {
		t.Fatalf("incomplete explanation: %#v", entry)
	}
}
