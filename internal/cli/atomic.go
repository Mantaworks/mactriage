package cli

import (
	"os"
	"path/filepath"
)

type atomicStream struct {
	path, temp string
	file       *os.File
}

func newAtomicStream(path string) (*atomicStream, error) {
	file, err := os.CreateTemp(filepath.Dir(path), ".mactriage-watch-*")
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	return &atomicStream{path: path, temp: file.Name(), file: file}, nil
}

func (s *atomicStream) Commit() error {
	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	return os.Rename(s.temp, s.path)
}

func (s *atomicStream) Abort() {
	if s.file != nil {
		s.file.Close()
	}
	if s.temp != "" {
		os.Remove(s.temp)
	}
}
