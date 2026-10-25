package flujo

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/equipo/proteccion-logs/internal/almacenamiento"
	"github.com/equipo/proteccion-logs/internal/cifrado"
	"github.com/equipo/proteccion-logs/internal/generador"
	"github.com/equipo/proteccion-logs/internal/integridad"
	"github.com/equipo/proteccion-logs/internal/modelo"
)

var fixedNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func newPipeline(t *testing.T) (*Pipeline, *almacenamiento.Store) {
	t.Helper()
	store, err := almacenamiento.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	gen := generador.New(11, 22, fixedNow.Add(-24*time.Hour))
	return New(gen, store, func() time.Time { return fixedNow }), store
}

func mustRun(t *testing.T, p *Pipeline, n int) Result {
	t.Helper()
	res, err := p.Run(n)
	if err != nil {
		t.Fatalf("Run(%d): %v", n, err)
	}
	return res
}

func TestRunPreservesInformation(t *testing.T) {
	p, _ := newPipeline(t)

	res := mustRun(t, p, 200)

	if res.EventCount != 200 {
		t.Errorf("EventCount = %d", res.EventCount)
	}
	if res.CountsByType[modelo.GradeRegistered]+res.CountsByType[modelo.GradeModified] != 200 {
		t.Errorf("CountsByType no suma 200: %v", res.CountsByType)
	}
	if !res.Preserved || res.PlainHash != res.DecryptedHash {
		t.Error("el hash del log descifrado debe coincidir con el original")
	}
	if !res.CipherHashVerified || !res.EventHashesValid {
		t.Errorf("verificaciones fallidas: %+v", res)
	}
	if res.PlainHash == res.CipherHash {
		t.Error("el hash del cifrado debe diferir del hash del claro")
	}
}

func TestRunWritesAllArtifactsWithConsistentChecksums(t *testing.T) {
	p, store := newPipeline(t)
	res := mustRun(t, p, 30)

	for name, wantHash := range map[string]string{
		FilePlainLog:     res.PlainHash,
		FileCipherLog:    res.CipherHash,
		FileDecryptedLog: res.DecryptedHash,
	} {
		data, err := store.Read(name)
		if err != nil {
			t.Fatalf("falta %s: %v", name, err)
		}
		if got := integridad.SHA256Hex(data); got != wantHash {
			t.Errorf("%s: hash en disco %s != reportado %s", name, got, wantHash)
		}
	}
	for _, name := range []string{FilePlainHash, FileCipherHash, FileDecryptedHash, FileKey, FileNonce} {
		if _, err := store.Read(name); err != nil {
			t.Errorf("falta %s: %v", name, err)
		}
	}
	plain, _ := store.Read(FilePlainLog)
	decrypted, _ := store.Read(FileDecryptedLog)
	if !bytes.Equal(plain, decrypted) {
		t.Error("log.json y log.decrypted.json deben ser idénticos byte a byte")
	}
}

func TestCiphertextDoesNotLeakPlaintext(t *testing.T) {
	p, store := newPipeline(t)
	mustRun(t, p, 50)

	ct, _ := store.Read(FileCipherLog)
	for _, marker := range [][]byte{[]byte("EVT-"), []byte("STU-"), []byte("new_value")} {
		if bytes.Contains(ct, marker) {
			t.Errorf("el cifrado contiene texto plano %q", marker)
		}
	}
}

func TestRunRejectsInvalidCount(t *testing.T) {
	p, _ := newPipeline(t)
	if _, err := p.Run(0); !errors.Is(err, generador.ErrInvalidCount) {
		t.Errorf("err = %v, quiero ErrInvalidCount", err)
	}
}

func TestEachRunUsesFreshKeyMaterial(t *testing.T) {
	p, store := newPipeline(t)
	mustRun(t, p, 5)
	key1, _ := store.Read(FileKey)
	mustRun(t, p, 5)
	key2, _ := store.Read(FileKey)

	if bytes.Equal(key1, key2) {
		t.Error("cada ejecución debe generar una llave nueva")
	}
}

func TestVerifyStoredOK(t *testing.T) {
	p, _ := newPipeline(t)
	mustRun(t, p, 40)

	if err := p.VerifyStored(); err != nil {
		t.Errorf("VerifyStored = %v", err)
	}
}

func TestVerifyStoredDetectsTamperedFileOnDisk(t *testing.T) {
	p, store := newPipeline(t)
	mustRun(t, p, 40)
	flipByteOnDisk(t, store, FileCipherLog)

	if err := p.VerifyStored(); !errors.Is(err, ErrCiphertextHashMismatch) {
		t.Errorf("err = %v, quiero ErrCiphertextHashMismatch", err)
	}
}

// Un atacante que además recalcula log_cifrado.sha256 sigue siendo detectado por GCM.
func TestVerifyStoredDetectsTamperEvenIfHashIsForged(t *testing.T) {
	p, store := newPipeline(t)
	mustRun(t, p, 40)
	flipByteOnDisk(t, store, FileCipherLog)
	forged, _ := store.Read(FileCipherLog)
	forgedHash := integridad.SHA256Hex(forged)
	_ = store.Write(FileCipherHash, integridad.FormatChecksum(forgedHash, FileCipherLog), almacenamiento.PermPublic)

	if err := p.VerifyStored(); !errors.Is(err, cifrado.ErrAuthentication) {
		t.Errorf("err = %v, quiero ErrAuthentication", err)
	}
}

func TestVerifyStoredFailsWithoutArtifacts(t *testing.T) {
	p, _ := newPipeline(t)
	if err := p.VerifyStored(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, quiero os.ErrNotExist", err)
	}
}

func TestSimulateTamperingIsDetectedAndLeavesFilesUntouched(t *testing.T) {
	p, store := newPipeline(t)
	res := mustRun(t, p, 40)

	report, err := p.SimulateTampering()
	if err != nil {
		t.Fatal(err)
	}
	if !report.Detected() || !report.HashMismatchDetected || !report.AuthenticationFailed {
		t.Errorf("report = %+v, ambas defensas debían reaccionar", report)
	}
	ct, _ := store.Read(FileCipherLog)
	if integridad.SHA256Hex(ct) != res.CipherHash {
		t.Error("la simulación no debe modificar log_cifrado.bin en disco")
	}
	if err := p.VerifyStored(); err != nil {
		t.Errorf("tras la simulación, VerifyStored = %v", err)
	}
}

func TestSimulateTamperingWithoutRun(t *testing.T) {
	p, _ := newPipeline(t)
	if _, err := p.SimulateTampering(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, quiero os.ErrNotExist", err)
	}
}

func TestRecoveredLogHasValidEventHashes(t *testing.T) {
	p, store := newPipeline(t)
	mustRun(t, p, 25)

	data, _ := store.Read(FileDecryptedLog)
	l, err := unmarshalLog(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := integridad.VerifyLog(l); err != nil {
		t.Errorf("VerifyLog = %v", err)
	}
	if l.EventCount != 25 || len(l.Events) != 25 {
		t.Errorf("event_count=%d len=%d", l.EventCount, len(l.Events))
	}
}

func TestUnmarshalLogRejectsUnknownFields(t *testing.T) {
	if _, err := unmarshalLog([]byte(`{"schema_version":"1.0","extra":1}`)); err == nil {
		t.Error("se esperaba error por campo desconocido")
	}
}

func flipByteOnDisk(t *testing.T, store *almacenamiento.Store, name string) {
	t.Helper()
	data, err := store.Read(name)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)/2] ^= 0xFF
	if err := os.WriteFile(filepath.Join(store.Dir(), name), data, 0o644); err != nil {
		t.Fatal(err)
	}
}
