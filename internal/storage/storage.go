// Package storage persiste los artefactos del proceso en un directorio de salida.
package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrInvalidName indica un nombre de artefacto que intenta salirse del directorio.
var ErrInvalidName = errors.New("storage: nombre de artefacto inválido")

const (
	// PermPublic es el permiso de artefactos no secretos (log, hashes).
	PermPublic os.FileMode = 0o644
	// PermSecret es el permiso de artefactos sensibles (llave).
	PermSecret os.FileMode = 0o600
)

// Store lee y escribe archivos planos dentro de un único directorio.
type Store struct {
	dir string
}

// New crea (si hace falta) el directorio y devuelve el Store.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("crear directorio %q: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir devuelve el directorio de salida.
func (s *Store) Dir() string { return s.dir }

// Write guarda data en name con el permiso indicado, aun si el archivo ya existía.
func (s *Store) Write(name string, data []byte, perm os.FileMode) error {
	path, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("escribir %s: %w", name, err)
	}
	return os.Chmod(path, perm)
}

// Read devuelve el contenido de name.
func (s *Store) Read(name string) ([]byte, error) {
	path, err := s.path(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("leer %s: %w", name, err)
	}
	return data, nil
}

func (s *Store) path(name string) (string, error) {
	if name == "" || name == "." || name == ".." || name != filepath.Base(name) {
		return "", fmt.Errorf("%w: %q", ErrInvalidName, name)
	}
	return filepath.Join(s.dir, name), nil
}
