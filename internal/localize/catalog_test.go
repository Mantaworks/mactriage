package localize_test

import (
	"testing"

	"github.com/Mantaworks/mactriage/internal/localize"
)

func TestCatalogSelectsLocaleAndFallsBackToEnglish(t *testing.T) {
	english := localize.For("en-US")
	if english.Locale() != "en" {
		t.Fatalf("locale=%q want=en", english.Locale())
	}
	if got := english.Text("home.prompt"); got != "What would you like to troubleshoot?" {
		t.Fatalf("home.prompt=%q", got)
	}

	fallback := localize.For("zz-ZZ")
	if fallback.Locale() != "en" || fallback.Text("verdict.looks_good") != "LOOKS GOOD" {
		t.Fatalf("unexpected fallback: locale=%q verdict=%q", fallback.Locale(), fallback.Text("verdict.looks_good"))
	}
}

func TestCatalogUsesStandardLocaleEnvironmentPrecedence(t *testing.T) {
	values := map[string]string{
		"LANG":        "en_US.UTF-8",
		"LC_MESSAGES": "en_GB.UTF-8",
		"LC_ALL":      "en_CA.UTF-8",
	}
	messages := localize.FromEnvironment(func(name string) string { return values[name] })
	if messages.Locale() != "en" {
		t.Fatalf("locale=%q want=en", messages.Locale())
	}
}

func TestCatalogMakesMissingKeysVisible(t *testing.T) {
	if got := localize.For("en").Text("missing.example"); got != "[missing.example]" {
		t.Fatalf("missing key=%q", got)
	}
}
