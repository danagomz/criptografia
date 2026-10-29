// Package flujo orquesta los 10 pasos del taller: generar, hashear,
// cifrar, descifrar y comparar el log de eventos académicos.
package flujo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/equipo/criptografia/internal/almacenamiento"
	"github.com/equipo/criptografia/internal/cifrado"
	"github.com/equipo/criptografia/internal/integridad"
	"github.com/equipo/criptografia/internal/modelo"
)

// Nombres de los artefactos producidos en el directorio de salida.
const (
	FilePlainLog      = "log_original.json"
	FilePlainHash     = "log_original.sha256"
	FileCipherLog     = "log_cifrado.bin"
	FileCipherHash    = "log_cifrado.sha256"
	FileKey           = "llave_aes256.hex"
	FileNonce         = "nonce_aes_gcm.hex"
	FileDecryptedLog  = "log_descifrado.json"
	FileDecryptedHash = "log_descifrado.sha256"
)

// aad liga el ciphertext a este formato: GCM rechaza el descifrado si cambia.
var aad = []byte("criptografia/v1")

var (
	// ErrCiphertextHashMismatch indica que log_cifrado.bin no coincide con su hash almacenado.
	ErrCiphertextHashMismatch = errors.New("flujo: el hash del log cifrado no coincide con el almacenado")
	// ErrPlainHashMismatch indica que el log recuperado difiere del hash del original.
	ErrPlainHashMismatch = errors.New("flujo: el hash del log descifrado no coincide con el del original")
)

// PayloadGenerator produce los payloads de los eventos.
type PayloadGenerator interface {
	Generate(count int) ([]modelo.Payload, error)
}

// Pipeline ejecuta el flujo completo sobre un Store.
type Pipeline struct {
	gen   PayloadGenerator
	store *almacenamiento.Store
	now   func() time.Time
}

// New crea un Pipeline. now permite inyectar el reloj en las pruebas.
func New(gen PayloadGenerator, store *almacenamiento.Store, now func() time.Time) *Pipeline {
	return &Pipeline{gen: gen, store: store, now: now}
}

// Result resume una ejecución para presentarla al usuario (paso 10).
type Result struct {
	OutputDir          string                   `json:"output_dir"`
	EventCount         int                      `json:"event_count"`
	CountsByType       map[modelo.EventType]int `json:"counts_by_type"`
	PlainHash          string                   `json:"plain_hash"`
	CipherHash         string                   `json:"cipher_hash"`
	DecryptedHash      string                   `json:"decrypted_hash"`
	CipherHashVerified bool                     `json:"cipher_hash_verified"` // log_cifrado.bin coincidía con su hash antes de descifrar
	EventHashesValid   bool                     `json:"event_hashes_valid"`   // todos los payload_hash del log recuperado son válidos
	Preserved          bool                     `json:"preserved"`            // PlainHash == DecryptedHash
}

// TamperReport describe cómo reaccionan las defensas ante un log cifrado alterado.
type TamperReport struct {
	HashMismatchDetected bool `json:"hash_mismatch_detected"` // el hash SHA-256 almacenado ya no coincide
	AuthenticationFailed bool `json:"authentication_failed"`  // la etiqueta de GCM rechazó el descifrado
}

// Detected indica si al menos una defensa detectó la alteración.
func (r TamperReport) Detected() bool {
	return r.HashMismatchDetected || r.AuthenticationFailed
}

// Run ejecuta los pasos 1 a 10 con count eventos.
func (p *Pipeline) Run(count int) (Result, error) {
	// Pasos 1 y 2: volumen y generación aleatoria de payloads.
	payloads, err := p.gen.Generate(count)
	if err != nil {
		return Result{}, err
	}

	// Paso 3: hash del payload de cada evento.
	events, err := sealEvents(payloads)
	if err != nil {
		return Result{}, err
	}

	// Paso 4: log estructurado completo.
	logDoc := modelo.NewLog(events, p.now())
	plain, err := marshalLog(logDoc)
	if err != nil {
		return Result{}, err
	}

	// Paso 5: hash del log en claro, calculado sobre los bytes exactos que se guardan.
	plainHash := integridad.SHA256Hex(plain)
	if err := p.writeWithChecksum(FilePlainLog, plain, FilePlainHash, plainHash); err != nil {
		return Result{}, err
	}

	// Paso 6: cifrado AES-256-GCM; llave y nonce se guardan como insumos separados.
	material, err := cifrado.NewMaterial()
	if err != nil {
		return Result{}, err
	}
	ciphertext, err := cifrado.Encrypt(material, plain, aad)
	if err != nil {
		return Result{}, err
	}
	if err := p.store.Write(FileKey, []byte(material.KeyHex()+"\n"), almacenamiento.PermSecret); err != nil {
		return Result{}, err
	}
	if err := p.store.Write(FileNonce, []byte(material.NonceHex()+"\n"), almacenamiento.PermPublic); err != nil {
		return Result{}, err
	}

	// Paso 7: hash del log cifrado.
	cipherHash := integridad.SHA256Hex(ciphertext)
	if err := p.writeWithChecksum(FileCipherLog, ciphertext, FileCipherHash, cipherHash); err != nil {
		return Result{}, err
	}

	// Paso 8: descifrado a partir de lo que realmente quedó en disco.
	storedCipher, err := p.store.Read(FileCipherLog)
	if err != nil {
		return Result{}, err
	}
	recovered, err := p.decryptStored(storedCipher)
	if err != nil {
		return Result{}, err
	}

	// Paso 9: hash del log descifrado y comparación con el original.
	decryptedHash := integridad.SHA256Hex(recovered)
	if err := p.writeWithChecksum(FileDecryptedLog, recovered, FileDecryptedHash, decryptedHash); err != nil {
		return Result{}, err
	}
	recoveredLog, err := unmarshalLog(recovered)
	if err != nil {
		return Result{}, err
	}

	// Paso 10: datos para la presentación de resultados.
	return Result{
		OutputDir:          p.store.Dir(),
		EventCount:         logDoc.EventCount,
		CountsByType:       logDoc.CountByType(),
		PlainHash:          plainHash,
		CipherHash:         cipherHash,
		DecryptedHash:      decryptedHash,
		CipherHashVerified: true, // decryptStored habría fallado en caso contrario
		EventHashesValid:   integridad.VerifyLog(recoveredLog) == nil,
		Preserved:          integridad.Equal(plainHash, decryptedHash),
	}, nil
}

// VerifyStored revalida los artefactos guardados: hash del cifrado, descifrado,
// hash del log original y hash de cada evento.
func (p *Pipeline) VerifyStored() error {
	ciphertext, err := p.store.Read(FileCipherLog)
	if err != nil {
		return err
	}
	recovered, err := p.decryptStored(ciphertext)
	if err != nil {
		return err
	}
	expected, err := p.readChecksum(FilePlainHash)
	if err != nil {
		return err
	}
	if !integridad.Equal(integridad.SHA256Hex(recovered), expected) {
		return ErrPlainHashMismatch
	}
	logDoc, err := unmarshalLog(recovered)
	if err != nil {
		return err
	}
	return integridad.VerifyLog(logDoc)
}

// SimulateTampering altera un byte del log cifrado EN MEMORIA (los archivos no
// se tocan) y comprueba cuáles defensas lo detectan.
func (p *Pipeline) SimulateTampering() (TamperReport, error) {
	ciphertext, err := p.store.Read(FileCipherLog)
	if err != nil {
		return TamperReport{}, err
	}
	if len(ciphertext) == 0 {
		return TamperReport{}, errors.New("flujo: el log cifrado está vacío")
	}
	tampered := bytes.Clone(ciphertext)
	tampered[len(tampered)/2] ^= 0xFF

	storedHash, err := p.readChecksum(FileCipherHash)
	if err != nil {
		return TamperReport{}, err
	}
	material, err := p.readMaterial()
	if err != nil {
		return TamperReport{}, err
	}
	_, decErr := cifrado.Decrypt(material, tampered, aad)

	return TamperReport{
		HashMismatchDetected: !integridad.Equal(integridad.SHA256Hex(tampered), storedHash),
		AuthenticationFailed: errors.Is(decErr, cifrado.ErrAuthentication),
	}, nil
}

// decryptStored verifica el hash del cifrado y luego descifra.
func (p *Pipeline) decryptStored(ciphertext []byte) ([]byte, error) {
	expected, err := p.readChecksum(FileCipherHash)
	if err != nil {
		return nil, err
	}
	if !integridad.Equal(integridad.SHA256Hex(ciphertext), expected) {
		return nil, ErrCiphertextHashMismatch
	}
	material, err := p.readMaterial()
	if err != nil {
		return nil, err
	}
	return cifrado.Decrypt(material, ciphertext, aad)
}

func (p *Pipeline) readMaterial() (cifrado.Material, error) {
	key, err := p.store.Read(FileKey)
	if err != nil {
		return cifrado.Material{}, err
	}
	nonce, err := p.store.Read(FileNonce)
	if err != nil {
		return cifrado.Material{}, err
	}
	return cifrado.DecodeMaterial(strings.TrimSpace(string(key)), strings.TrimSpace(string(nonce)))
}

func (p *Pipeline) readChecksum(name string) (string, error) {
	data, err := p.store.Read(name)
	if err != nil {
		return "", err
	}
	return integridad.ParseChecksum(data)
}

func (p *Pipeline) writeWithChecksum(name string, data []byte, checksumName, hash string) error {
	if err := p.store.Write(name, data, almacenamiento.PermPublic); err != nil {
		return err
	}
	return p.store.Write(checksumName, integridad.FormatChecksum(hash, name), almacenamiento.PermPublic)
}

func sealEvents(payloads []modelo.Payload) ([]modelo.Event, error) {
	events := make([]modelo.Event, 0, len(payloads))
	for _, pl := range payloads {
		e, err := integridad.NewEvent(pl)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

func marshalLog(l modelo.Log) ([]byte, error) {
	raw, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("serializar log: %w", err)
	}
	return append(raw, '\n'), nil
}

func unmarshalLog(data []byte) (modelo.Log, error) {
	var l modelo.Log
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return modelo.Log{}, fmt.Errorf("interpretar log: %w", err)
	}
	return l, nil
}
