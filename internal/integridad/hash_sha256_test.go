package integridad

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/equipo/criptografia/internal/modelo"
)

func samplePayload() modelo.Payload {
	prev := 2.5
	return modelo.Payload{
		EventID:       "EVT-00000001",
		EventType:     modelo.GradeModified,
		Timestamp:     time.Date(2026, 10, 1, 8, 0, 5, 0, time.UTC),
		ActorUID:      "PRF-001",
		StudentUID:    "STU-00042",
		CourseUID:     "CRS-007",
		PreviousValue: &prev,
		NewValue:      4.1,
	}
}

func TestSHA256HexKnownVector(t *testing.T) {
	// Vector de prueba oficial de FIPS 180-2 para "abc".
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := SHA256Hex([]byte("abc")); got != want {
		t.Errorf("SHA256Hex(abc) = %s", got)
	}
}

func TestPayloadHashIsDeterministic(t *testing.T) {
	a, _ := PayloadHash(samplePayload())
	b, _ := PayloadHash(samplePayload())
	if a != b {
		t.Error("el hash del mismo payload debe ser estable")
	}
}

func TestPayloadHashChangesWhenAnyFieldChanges(t *testing.T) {
	base, _ := PayloadHash(samplePayload())
	otherPrev := 1.0

	mutations := map[string]func(*modelo.Payload){
		"event_id":       func(p *modelo.Payload) { p.EventID = "EVT-00000002" },
		"event_type":     func(p *modelo.Payload) { p.EventType = modelo.GradeRegistered },
		"timestamp":      func(p *modelo.Payload) { p.Timestamp = p.Timestamp.Add(time.Second) },
		"actor_uid":      func(p *modelo.Payload) { p.ActorUID = "PRF-002" },
		"student_uid":    func(p *modelo.Payload) { p.StudentUID = "STU-00043" },
		"course_uid":     func(p *modelo.Payload) { p.CourseUID = "CRS-008" },
		"previous_value": func(p *modelo.Payload) { p.PreviousValue = &otherPrev },
		"new_value":      func(p *modelo.Payload) { p.NewValue = 4.2 },
	}
	for field, mutate := range mutations {
		t.Run(field, func(t *testing.T) {
			p := samplePayload()
			mutate(&p)
			got, _ := PayloadHash(p)
			if got == base {
				t.Errorf("cambiar %s no alteró el hash", field)
			}
		})
	}
}

func TestEventJSONIsFlatAndHashIsNotPartOfPayload(t *testing.T) {
	e, err := NewEvent(samplePayload())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(e)

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"event_id", "event_type", "timestamp", "actor_uid",
		"student_uid", "course_uid", "previous_value", "new_value", "payload_hash"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("falta el campo %q en el JSON del evento", k)
		}
	}
	// El hash almacenado no influye en el hash recalculado (sin circularidad).
	e.PayloadHash = "cualquier-cosa"
	h, _ := PayloadHash(e.Payload)
	if !Equal(h, mustHash(t, samplePayload())) {
		t.Error("el hash del payload no debe depender de payload_hash")
	}
}

func mustHash(t *testing.T, p modelo.Payload) string {
	t.Helper()
	h, err := PayloadHash(p)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestVerifyEvent(t *testing.T) {
	e, _ := NewEvent(samplePayload())
	if err := VerifyEvent(e); err != nil {
		t.Fatalf("evento íntegro rechazado: %v", err)
	}
	e.NewValue = 5.0 // manipulación de la nota
	if err := VerifyEvent(e); !errors.Is(err, ErrPayloadHashMismatch) {
		t.Errorf("err = %v, quiero ErrPayloadHashMismatch", err)
	}
}

func TestVerifyLog(t *testing.T) {
	e1, _ := NewEvent(samplePayload())
	p2 := samplePayload()
	p2.EventID = "EVT-00000002"
	e2, _ := NewEvent(p2)

	t.Run("íntegro", func(t *testing.T) {
		l := modelo.NewLog([]modelo.Event{e1, e2}, time.Now())
		if err := VerifyLog(l); err != nil {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("evento alterado", func(t *testing.T) {
		l := modelo.NewLog([]modelo.Event{e1, e2}, time.Now())
		l.Events[1].NewValue = 0.0
		if err := VerifyLog(l); !errors.Is(err, ErrPayloadHashMismatch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("evento eliminado", func(t *testing.T) {
		l := modelo.NewLog([]modelo.Event{e1, e2}, time.Now())
		l.Events = l.Events[:1]
		if err := VerifyLog(l); !errors.Is(err, ErrEventCountMismatch) {
			t.Errorf("err = %v", err)
		}
	})
}

func TestChecksumRoundTrip(t *testing.T) {
	hash := SHA256Hex([]byte("abc"))
	data := FormatChecksum(hash, "log_original.json")

	if want := hash + "  log_original.json\n"; string(data) != want {
		t.Errorf("formato = %q", data)
	}
	got, err := ParseChecksum(data)
	if err != nil || got != hash {
		t.Errorf("ParseChecksum = %q, %v", got, err)
	}
}

func TestParseChecksumRejectsGarbage(t *testing.T) {
	for name, in := range map[string]string{
		"vacío":      "",
		"corto":      "abc123  file",
		"no hex":     strings.Repeat("z", 64) + "  file",
		"solo ruido": "   \n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseChecksum([]byte(in)); !errors.Is(err, ErrInvalidChecksum) {
				t.Errorf("err = %v, quiero ErrInvalidChecksum", err)
			}
		})
	}
}
