// Package integridad concentra el hashing SHA-256: hash de payload por evento,
// hash de artefactos completos y verificación en tiempo constante.
package integridad

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/equipo/proteccion-logs/internal/modelo"
)

var (
	// ErrPayloadHashMismatch indica que el payload de un evento fue alterado.
	ErrPayloadHashMismatch = errors.New("integridad: el hash del payload no coincide")
	// ErrEventCountMismatch indica que event_count no coincide con los eventos presentes.
	ErrEventCountMismatch = errors.New("integridad: event_count no coincide con el número de eventos")
	// ErrInvalidChecksum indica un archivo de checksum mal formado.
	ErrInvalidChecksum = errors.New("integridad: checksum mal formado")
)

// SHA256Hex devuelve el SHA-256 de data en hexadecimal minúscula.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Equal compara dos hashes hexadecimales en tiempo constante.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// PayloadHash calcula el SHA-256 de la serialización JSON del payload.
//
// La serialización es determinista: Go emite los campos de un struct en el
// orden de declaración, y el payload no contiene mapas.
func PayloadHash(p modelo.Payload) (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("serializar payload %s: %w", p.EventID, err)
	}
	return SHA256Hex(raw), nil
}

// NewEvent sella un payload con su hash.
func NewEvent(p modelo.Payload) (modelo.Event, error) {
	h, err := PayloadHash(p)
	if err != nil {
		return modelo.Event{}, err
	}
	return modelo.Event{Payload: p, PayloadHash: h}, nil
}

// VerifyEvent recalcula el hash del payload y lo compara con el almacenado.
func VerifyEvent(e modelo.Event) error {
	h, err := PayloadHash(e.Payload)
	if err != nil {
		return err
	}
	if !Equal(h, e.PayloadHash) {
		return fmt.Errorf("%w (evento %s)", ErrPayloadHashMismatch, e.EventID)
	}
	return nil
}

// VerifyLog valida event_count y el hash de cada evento. Devuelve todos los
// problemas encontrados, unidos con errors.Join, o nil si el log es íntegro.
func VerifyLog(l modelo.Log) error {
	var errs []error
	if l.EventCount != len(l.Events) {
		errs = append(errs, fmt.Errorf("%w: declara %d, hay %d",
			ErrEventCountMismatch, l.EventCount, len(l.Events)))
	}
	for _, e := range l.Events {
		if err := VerifyEvent(e); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// FormatChecksum genera el contenido de un archivo .sha256 compatible con
// `sha256sum -c`: "<hash>  <archivo>\n".
func FormatChecksum(hash, filename string) []byte {
	return []byte(hash + "  " + filename + "\n")
}

// ParseChecksum extrae el hash de un archivo generado por FormatChecksum.
func ParseChecksum(data []byte) (string, error) {
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return "", ErrInvalidChecksum
	}
	h := fields[0]
	if len(h) != sha256.Size*2 {
		return "", fmt.Errorf("%w: longitud %d", ErrInvalidChecksum, len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidChecksum, err)
	}
	return h, nil
}
