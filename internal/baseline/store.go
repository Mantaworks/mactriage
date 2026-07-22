package baseline

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/Mantaworks/mactriage/internal/reportutil"
)

type Store struct {
	Dir string
}

type Entry struct {
	Name        string    `json:"name"`
	GeneratedAt time.Time `json:"generated_at"`
}

func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "mactriage", "baselines"), nil
}

func (s Store) Save(name string, r report.Report) (string, error) {
	path, err := s.path(name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".mactriage-baseline-*")
	if err != nil {
		return "", err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return "", err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(r); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temp, path); err != nil {
		return "", err
	}
	return path, nil
}

func (s Store) Load(name string) (report.Report, error) {
	path, err := s.path(name)
	if err != nil {
		return report.Report{}, err
	}
	return reportutil.Load(path)
}

func (s Store) List() ([]Entry, error) {
	dir, err := s.directory()
	if err != nil {
		return nil, err
	}
	items, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Entry{}, nil
	}
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		if item.IsDir() || !strings.HasSuffix(item.Name(), ".json") {
			continue
		}
		name := strings.TrimSuffix(item.Name(), ".json")
		r, loadErr := s.Load(name)
		if loadErr != nil {
			continue
		}
		entries = append(entries, Entry{Name: name, GeneratedAt: r.GeneratedAt})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].GeneratedAt.Equal(entries[j].GeneratedAt) {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].GeneratedAt.After(entries[j].GeneratedAt)
	})
	return entries, nil
}

func (s Store) Delete(name string) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

func (s Store) path(name string) (string, error) {
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(name) {
		return "", fmt.Errorf("invalid baseline name %q; use letters, numbers, dots, dashes, or underscores", name)
	}
	dir, err := s.directory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name+".json"), nil
}

func (s Store) directory() (string, error) {
	if s.Dir != "" {
		return filepath.Clean(s.Dir), nil
	}
	return DefaultDir()
}
