package almacenamiento

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNewCreatesNestedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")

	s, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(s.Dir()); err != nil || !info.IsDir() {
		t.Errorf("el directorio no se creó: %v", err)
	}
}

func TestWriteReadRoundTripAndOverwrite(t *testing.T) {
	s, _ := New(t.TempDir())

	if err := s.Write("a.txt", []byte("uno"), PermPublic); err != nil {
		t.Fatal(err)
	}
	if err := s.Write("a.txt", []byte("dos"), PermPublic); err != nil {
		t.Fatal(err)
	}
	got, err := s.Read("a.txt")
	if err != nil || !bytes.Equal(got, []byte("dos")) {
		t.Errorf("Read = %q, %v", got, err)
	}
}

func TestSecretFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("los bits de permiso POSIX no aplican en Windows")
	}
	s, _ := New(t.TempDir())
	_ = s.Write("llave_aes256.hex", []byte("secreto"), PermSecret)

	info, err := os.Stat(filepath.Join(s.Dir(), "llave_aes256.hex"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != PermSecret {
		t.Errorf("permisos = %o, quiero %o", perm, PermSecret)
	}
}

func TestRejectsPathTraversal(t *testing.T) {
	s, _ := New(t.TempDir())
	for _, name := range []string{"", ".", "..", "../x", "a/b", "a/c"} {
		if err := s.Write(name, []byte("x"), PermPublic); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Write(%q) err = %v, quiero ErrInvalidName", name, err)
		}
		if _, err := s.Read(name); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Read(%q) err = %v, quiero ErrInvalidName", name, err)
		}
	}
}

func TestReadMissingFile(t *testing.T) {
	s, _ := New(t.TempDir())
	if _, err := s.Read("no-existe"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, quiero os.ErrNotExist", err)
	}
}
