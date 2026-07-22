package baseline_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mantaworks/mactriage/internal/baseline"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestStoreSavesListsLoadsAndDeletesPrivateReports(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "baselines")
	store := baseline.Store{Dir: dir}
	r := report.New("doctor", "this Mac")
	r.Findings = append(r.Findings, report.Finding{Code: "doctor.storage_low", Severity: report.Warning, Title: "Low disk"})
	r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceStorage, Status: report.StatusOK, Data: report.StorageData{AvailablePercent: 12.5}})
	path, err := store.Save("healthy-morning", r)
	if err != nil {
		t.Fatalf("Save returned error: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("saved mode/error=%v %v", info.Mode().Perm(), err)
	}
	entries, err := store.List()
	if err != nil || len(entries) != 1 || entries[0].Name != "healthy-morning" {
		t.Fatalf("List=%#v error=%v", entries, err)
	}
	loaded, err := store.Load("healthy-morning")
	if err != nil || len(loaded.Findings) != 1 || loaded.Findings[0].Code != "doctor.storage_low" {
		t.Fatalf("Load=%#v error=%v", loaded, err)
	}
	if storage, ok := loaded.Evidence[0].Data.(report.StorageData); !ok || storage.AvailablePercent != 12.5 {
		t.Fatalf("typed storage evidence was not preserved: %#v", loaded.Evidence)
	}
	if err := store.Delete("healthy-morning"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("baseline still exists: %v", err)
	}
}

func TestStoreRejectsTraversalNames(t *testing.T) {
	store := baseline.Store{Dir: t.TempDir()}
	if _, err := store.Save("../outside", report.New("doctor", "this Mac")); err == nil {
		t.Fatal("Save accepted a traversal name")
	}
}
