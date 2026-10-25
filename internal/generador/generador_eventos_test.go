package generador

import (
	"errors"
	"math"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/equipo/proteccion-logs/internal/modelo"
)

var start = time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)

func newGen() *Generator { return New(1, 2, start) }

func TestGenerateCount(t *testing.T) {
	got, err := newGen().Generate(250)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 250 {
		t.Errorf("len = %d, quiero 250", len(got))
	}
}

func TestGenerateInvalidCount(t *testing.T) {
	for _, n := range []int{-5, 0, MaxEvents + 1} {
		if _, err := newGen().Generate(n); !errors.Is(err, ErrInvalidCount) {
			t.Errorf("Generate(%d) err = %v, quiero ErrInvalidCount", n, err)
		}
	}
}

func TestValidateCountBounds(t *testing.T) {
	for _, n := range []int{1, MaxEvents} {
		if err := ValidateCount(n); err != nil {
			t.Errorf("ValidateCount(%d) = %v, quiero nil", n, err)
		}
	}
}

func TestGenerateIsDeterministicPerSeed(t *testing.T) {
	a, _ := New(7, 9, start).Generate(50)
	b, _ := New(7, 9, start).Generate(50)
	c, _ := New(8, 9, start).Generate(50)

	if !reflect.DeepEqual(a, b) {
		t.Error("misma semilla debe producir los mismos eventos")
	}
	if reflect.DeepEqual(a, c) {
		t.Error("semillas distintas deben producir eventos distintos")
	}
}

func TestGradesAreUniformInRange(t *testing.T) {
	const n = 20_000
	payloads, _ := newGen().Generate(n)

	var sum float64
	for _, p := range payloads {
		if p.NewValue < 0 || p.NewValue > 5 {
			t.Fatalf("nota fuera de rango: %v", p.NewValue)
		}
		sum += p.NewValue
	}
	// Media teórica de U(0,5) = 2.5; desviación estándar de la media ≈ 0.01.
	if mean := sum / n; math.Abs(mean-2.5) > 0.1 {
		t.Errorf("media = %.3f, esperada ≈ 2.5", mean)
	}
}

func TestBothEventTypesAppearWithConsistentFields(t *testing.T) {
	payloads, _ := newGen().Generate(2000)

	counts := map[modelo.EventType]int{}
	for _, p := range payloads {
		counts[p.EventType]++
		switch p.EventType {
		case modelo.GradeRegistered:
			if p.PreviousValue != nil {
				t.Fatalf("%s: un registro no debe tener previous_value", p.EventID)
			}
		case modelo.GradeModified:
			if p.PreviousValue == nil {
				t.Fatalf("%s: una modificación debe tener previous_value", p.EventID)
			}
			if *p.PreviousValue == p.NewValue {
				t.Fatalf("%s: new_value debe diferir de previous_value", p.EventID)
			}
			if *p.PreviousValue < 0 || *p.PreviousValue > 5 {
				t.Fatalf("%s: previous_value fuera de rango", p.EventID)
			}
		default:
			t.Fatalf("tipo inesperado %q", p.EventType)
		}
	}
	if counts[modelo.GradeRegistered] == 0 || counts[modelo.GradeModified] == 0 {
		t.Errorf("deben aparecer ambos tipos, got %v", counts)
	}
}

func TestIdentifiersArePseudonyms(t *testing.T) {
	payloads, _ := newGen().Generate(500)
	patterns := map[string]*regexp.Regexp{
		"event":   regexp.MustCompile(`^EVT-\d{8}$`),
		"actor":   regexp.MustCompile(`^PRF-\d{3}$`),
		"student": regexp.MustCompile(`^STU-\d{5}$`),
		"course":  regexp.MustCompile(`^CRS-\d{3}$`),
	}
	for _, p := range payloads {
		checks := map[string]string{
			"event": p.EventID, "actor": p.ActorUID,
			"student": p.StudentUID, "course": p.CourseUID,
		}
		for k, v := range checks {
			if !patterns[k].MatchString(v) {
				t.Fatalf("%s UID %q no cumple el formato", k, v)
			}
		}
	}
}

func TestEventIDsAreUniqueAndTimestampsIncrease(t *testing.T) {
	payloads, _ := newGen().Generate(300)
	seen := map[string]bool{}
	prev := start
	for _, p := range payloads {
		if seen[p.EventID] {
			t.Fatalf("event_id repetido: %s", p.EventID)
		}
		seen[p.EventID] = true
		if !p.Timestamp.After(prev) {
			t.Fatalf("%s: timestamp no creciente", p.EventID)
		}
		prev = p.Timestamp
	}
}

func TestGenerateRestartsSequencePerCall(t *testing.T) {
	g := newGen()
	first, _ := g.Generate(3)
	second, _ := g.Generate(3)
	if first[0].EventID != "EVT-00000001" || second[0].EventID != "EVT-00000001" {
		t.Error("cada llamada debe reiniciar la secuencia de event_id")
	}
}
