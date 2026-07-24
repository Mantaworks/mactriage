package localize

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

//go:embed catalog/*.json
var catalogFiles embed.FS

type Messages struct {
	locale string
	values map[string]string
}

type MessageID string

const (
	AppName                   MessageID = "app.name"
	HomeTagline               MessageID = "home.tagline"
	HomePrompt                MessageID = "home.prompt"
	HomeOptionDoctor          MessageID = "home.option.doctor"
	HomeOptionStorage         MessageID = "home.option.storage"
	HomeOptionStartup         MessageID = "home.option.startup"
	HomeOptionDoctorHealth    MessageID = "home.option.doctor_health"
	HomeOptionDiagnose        MessageID = "home.option.diagnose"
	HomeOptionHang            MessageID = "home.option.hang"
	HomeOptionNetwork         MessageID = "home.option.network"
	HomeOptionPermissions     MessageID = "home.option.permissions"
	HomeOptionRelaunch        MessageID = "home.option.relaunch"
	HomeOptionBaselineCompare MessageID = "home.option.baseline_compare"
	HomeOptionShare           MessageID = "home.option.share"
	HomeOptionScan            MessageID = "home.option.scan"
	HomeOptionSystem          MessageID = "home.option.system"
	HomeOptionWatch           MessageID = "home.option.watch"
	HomeOptionCollect         MessageID = "home.option.collect"
	HomeOptionExplain         MessageID = "home.option.explain"
	HomeInputApplicationTitle MessageID = "home.input.application.title"
	HomeInputApplicationHint  MessageID = "home.input.application.placeholder"
	HomeInputProcessTitle     MessageID = "home.input.process.title"
	HomeInputProcessHint      MessageID = "home.input.process.placeholder"
	HomeInputCodeTitle        MessageID = "home.input.code.title"
	HomeInputCodeHint         MessageID = "home.input.code.placeholder"
	HomeInputNetworkTitle     MessageID = "home.input.network.title"
	HomeInputNetworkHint      MessageID = "home.input.network.placeholder"
	HomeInputBaselineTitle    MessageID = "home.input.baseline.title"
	HomeInputBaselineHint     MessageID = "home.input.baseline.placeholder"
	HomeInputShareTitle       MessageID = "home.input.share.title"
	HomeInputShareHint        MessageID = "home.input.share.placeholder"
	HomeInputRequired         MessageID = "home.input.required"
	GettingStartedQuick       MessageID = "getting_started.quick"
	GettingStartedStorage     MessageID = "getting_started.storage"
	GettingStartedDiagnose    MessageID = "getting_started.diagnose"
	GettingStartedHang        MessageID = "getting_started.hang"
	GettingStartedNetwork     MessageID = "getting_started.network"
	GettingStartedPermissions MessageID = "getting_started.permissions"
	GettingStartedScan        MessageID = "getting_started.scan"
	GettingStartedShare       MessageID = "getting_started.share"
	GettingStartedHint        MessageID = "getting_started.hint"
	VerdictNeedsAttention     MessageID = "verdict.needs_attention"
	VerdictCheckRecommended   MessageID = "verdict.check_recommended"
	VerdictIncomplete         MessageID = "verdict.incomplete"
	VerdictLooksGood          MessageID = "verdict.looks_good"
)

var messageIDs = []MessageID{
	AppName,
	HomeTagline,
	HomePrompt,
	HomeOptionDoctor,
	HomeOptionStorage,
	HomeOptionStartup,
	HomeOptionDoctorHealth,
	HomeOptionDiagnose,
	HomeOptionHang,
	HomeOptionNetwork,
	HomeOptionPermissions,
	HomeOptionRelaunch,
	HomeOptionBaselineCompare,
	HomeOptionShare,
	HomeOptionScan,
	HomeOptionSystem,
	HomeOptionWatch,
	HomeOptionCollect,
	HomeOptionExplain,
	HomeInputApplicationTitle,
	HomeInputApplicationHint,
	HomeInputProcessTitle,
	HomeInputProcessHint,
	HomeInputCodeTitle,
	HomeInputCodeHint,
	HomeInputNetworkTitle,
	HomeInputNetworkHint,
	HomeInputBaselineTitle,
	HomeInputBaselineHint,
	HomeInputShareTitle,
	HomeInputShareHint,
	HomeInputRequired,
	GettingStartedQuick,
	GettingStartedStorage,
	GettingStartedDiagnose,
	GettingStartedHang,
	GettingStartedNetwork,
	GettingStartedPermissions,
	GettingStartedScan,
	GettingStartedShare,
	GettingStartedHint,
	VerdictNeedsAttention,
	VerdictCheckRecommended,
	VerdictIncomplete,
	VerdictLooksGood,
}

var catalogs = loadCatalogs()

func For(locale string) Messages {
	normalized := normalizeLocale(locale)
	if values, ok := catalogs[normalized]; ok {
		return Messages{locale: normalized, values: values}
	}
	if language, _, ok := strings.Cut(normalized, "-"); ok {
		if values, found := catalogs[language]; found {
			return Messages{locale: language, values: values}
		}
	}
	return Messages{locale: "en", values: catalogs["en"]}
}

func Default() Messages {
	return FromEnvironment(os.Getenv)
}

func FromEnvironment(getenv func(string) string) Messages {
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if value := strings.TrimSpace(getenv(name)); value != "" {
			return For(value)
		}
	}
	return For("en")
}

func (m Messages) Locale() string {
	if m.locale == "" {
		return "en"
	}
	return m.locale
}

func (m Messages) Text(id MessageID) string {
	key := string(id)
	if value := m.values[key]; value != "" {
		return value
	}
	if value := catalogs["en"][key]; value != "" {
		return value
	}
	return "[" + key + "]"
}

func loadCatalogs() map[string]map[string]string {
	paths, err := fs.Glob(catalogFiles, "catalog/*.json")
	if err != nil {
		panic(fmt.Sprintf("load message catalogs: %v", err))
	}
	loaded := make(map[string]map[string]string, len(paths))
	for _, path := range paths {
		data, readErr := catalogFiles.ReadFile(path)
		if readErr != nil {
			panic(fmt.Sprintf("read message catalog %s: %v", path, readErr))
		}
		values := map[string]string{}
		if decodeErr := json.Unmarshal(data, &values); decodeErr != nil {
			panic(fmt.Sprintf("decode message catalog %s: %v", path, decodeErr))
		}
		locale := normalizeLocale(strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)))
		loaded[locale] = values
	}
	if len(loaded["en"]) == 0 {
		panic("English message catalog is required")
	}
	known := make(map[string]bool, len(messageIDs))
	for _, id := range messageIDs {
		known[string(id)] = true
	}
	for locale, values := range loaded {
		for _, id := range messageIDs {
			if values[string(id)] == "" {
				panic(fmt.Sprintf("message catalog %s is missing %s", locale, id))
			}
		}
		for key := range values {
			if !known[key] {
				panic(fmt.Sprintf("message catalog %s contains unknown key %s", locale, key))
			}
		}
	}
	return loaded
}

func normalizeLocale(locale string) string {
	locale = strings.TrimSpace(locale)
	if index := strings.IndexAny(locale, ".@"); index >= 0 {
		locale = locale[:index]
	}
	return strings.ToLower(strings.ReplaceAll(locale, "_", "-"))
}
