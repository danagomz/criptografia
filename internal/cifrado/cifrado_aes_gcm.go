// Package cifrado implementa cifrado autenticado AES-256-GCM con la
// biblioteca estándar de Go (crypto/aes, crypto/cipher, crypto/rand).
package cifrado

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

const (
	// KeySize es el tamaño de la llave AES-256 en bytes.
	KeySize = 32
	// NonceSize es el tamaño estándar del nonce de GCM (96 bits).
	NonceSize = 12
)

var (
	// ErrInvalidKeySize indica una llave que no mide KeySize bytes.
	ErrInvalidKeySize = errors.New("cifrado: la llave debe medir 32 bytes")
	// ErrInvalidNonceSize indica un nonce que no mide NonceSize bytes.
	ErrInvalidNonceSize = errors.New("cifrado: el nonce debe medir 12 bytes")
	// ErrAuthentication indica que el etiquetado GCM falló: datos, llave,
	// nonce o AAD incorrectos, o ciphertext manipulado.
	ErrAuthentication = errors.New("cifrado: autenticación fallida (¿datos alterados o llave incorrecta?)")
)

// Material agrupa los insumos criptográficos de una operación de cifrado.
//
// Regla de GCM: nunca reutilizar un nonce con la misma llave. Aquí se genera
// una llave nueva por ejecución, por lo que el par (llave, nonce) es único.
type Material struct {
	Key   []byte
	Nonce []byte
}

// NewMaterial genera llave y nonce con crypto/rand (CSPRNG del sistema).
func NewMaterial() (Material, error) {
	m := Material{Key: make([]byte, KeySize), Nonce: make([]byte, NonceSize)}
	if _, err := rand.Read(m.Key); err != nil {
		return Material{}, fmt.Errorf("generar llave: %w", err)
	}
	if _, err := rand.Read(m.Nonce); err != nil {
		return Material{}, fmt.Errorf("generar nonce: %w", err)
	}
	return m, nil
}

// DecodeMaterial reconstruye el material desde su representación hexadecimal.
func DecodeMaterial(keyHex, nonceHex string) (Material, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return Material{}, fmt.Errorf("decodificar llave: %w", err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		return Material{}, fmt.Errorf("decodificar nonce: %w", err)
	}
	m := Material{Key: key, Nonce: nonce}
	return m, m.validate()
}

// KeyHex devuelve la llave en hexadecimal.
func (m Material) KeyHex() string { return hex.EncodeToString(m.Key) }

// NonceHex devuelve el nonce en hexadecimal.
func (m Material) NonceHex() string { return hex.EncodeToString(m.Nonce) }

func (m Material) validate() error {
	if len(m.Key) != KeySize {
		return ErrInvalidKeySize
	}
	if len(m.Nonce) != NonceSize {
		return ErrInvalidNonceSize
	}
	return nil
}

func (m Material) aead() (cipher.AEAD, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(m.Key)
	if err != nil {
		return nil, fmt.Errorf("crear AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crear GCM: %w", err)
	}
	return gcm, nil
}

// Encrypt cifra y autentica plaintext. aad (datos adicionales autenticados)
// no se cifra pero queda ligado al ciphertext. El resultado incluye la
// etiqueta de autenticación de 16 bytes al final; el nonce NO se antepone.
func Encrypt(m Material, plaintext, aad []byte) ([]byte, error) {
	gcm, err := m.aead()
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, m.Nonce, plaintext, aad), nil
}

// Decrypt verifica la etiqueta y descifra. Devuelve ErrAuthentication si
// cualquier byte del ciphertext, la llave, el nonce o el aad no coincide.
func Decrypt(m Material, ciphertext, aad []byte) ([]byte, error) {
	gcm, err := m.aead()
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, m.Nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthentication, err)
	}
	return plaintext, nil
}
