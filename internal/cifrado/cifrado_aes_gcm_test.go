package cifrado

import (
	"bytes"
	"errors"
	"testing"
)

var testAAD = []byte("criptografia/test")

func mustMaterial(t *testing.T) Material {
	t.Helper()
	m, err := NewMaterial()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNewMaterialSizesAndRandomness(t *testing.T) {
	a, b := mustMaterial(t), mustMaterial(t)

	if len(a.Key) != KeySize || len(a.Nonce) != NonceSize {
		t.Fatalf("tamaños: key=%d nonce=%d", len(a.Key), len(a.Nonce))
	}
	if bytes.Equal(a.Key, b.Key) || bytes.Equal(a.Nonce, b.Nonce) {
		t.Error("dos materiales no deben coincidir")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	m := mustMaterial(t)
	plain := []byte(`{"event_id":"EVT-00000001","new_value":4.5}`)

	ct, err := Encrypt(m, plain, testAAD)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("EVT-00000001")) {
		t.Error("el ciphertext no debe revelar el texto plano")
	}
	if len(ct) != len(plain)+16 {
		t.Errorf("len(ct) = %d, esperado plaintext + 16 de etiqueta GCM", len(ct))
	}

	got, err := Decrypt(m, ct, testAAD)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("round trip = %q", got)
	}
}

func TestDecryptFailsOnAnyTampering(t *testing.T) {
	m := mustMaterial(t)
	ct, _ := Encrypt(m, []byte("nota: 4.5"), testAAD)

	flipped := bytes.Clone(ct)
	flipped[0] ^= 0x01
	wrongKey := mustMaterial(t)
	wrongNonce := Material{Key: m.Key, Nonce: bytes.Repeat([]byte{9}, NonceSize)}

	cases := map[string]func() ([]byte, error){
		"ciphertext alterado": func() ([]byte, error) { return Decrypt(m, flipped, testAAD) },
		"ciphertext truncado": func() ([]byte, error) { return Decrypt(m, ct[:len(ct)-1], testAAD) },
		"llave incorrecta":    func() ([]byte, error) { return Decrypt(wrongKey, ct, testAAD) },
		"nonce incorrecto":    func() ([]byte, error) { return Decrypt(wrongNonce, ct, testAAD) },
		"aad incorrecto":      func() ([]byte, error) { return Decrypt(m, ct, []byte("otro")) },
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := run(); !errors.Is(err, ErrAuthentication) {
				t.Errorf("err = %v, quiero ErrAuthentication", err)
			}
		})
	}
}

func TestInvalidMaterial(t *testing.T) {
	good := mustMaterial(t)

	if _, err := Encrypt(Material{Key: []byte("corta"), Nonce: good.Nonce}, nil, nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("llave corta: err = %v", err)
	}
	if _, err := Encrypt(Material{Key: good.Key, Nonce: []byte{1}}, nil, nil); !errors.Is(err, ErrInvalidNonceSize) {
		t.Errorf("nonce corto: err = %v", err)
	}
}

func TestMaterialHexRoundTrip(t *testing.T) {
	m := mustMaterial(t)

	got, err := DecodeMaterial(m.KeyHex(), m.NonceHex())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Key, m.Key) || !bytes.Equal(got.Nonce, m.Nonce) {
		t.Error("el material decodificado difiere del original")
	}
}

func TestDecodeMaterialRejectsBadInput(t *testing.T) {
	m := mustMaterial(t)
	cases := map[string][2]string{
		"llave no hex": {"zz", m.NonceHex()},
		"nonce no hex": {m.KeyHex(), "zz"},
		"llave tamaño": {"abcd", m.NonceHex()},
		"nonce tamaño": {m.KeyHex(), "abcd"},
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeMaterial(in[0], in[1]); err == nil {
				t.Error("se esperaba error")
			}
		})
	}
}
