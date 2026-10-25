// Package generator produce eventos aleatorios de registro y modificación de notas.
package generator

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/equipo/logvault/internal/domain"
)

const (
	// MaxEvents limita el volumen para mantener la demo en memoria y tiempo razonables.
	MaxEvents = 100_000

	// Las notas se generan en centésimas (0..500) y se dividen entre 100: así la
	// distribución es uniforme sobre [0.0, 5.0] con dos decimales exactos.
	maxGradeCents = 500

	studentPool    = 200
	professorPool  = 20
	coursePool     = 30
	maxStepSeconds = 300
)

// ErrInvalidCount indica una cantidad de eventos fuera del rango permitido.
var ErrInvalidCount = errors.New("generator: cantidad de eventos inválida")

// ValidateCount verifica que count esté en [1, MaxEvents].
func ValidateCount(count int) error {
	if count < 1 || count > MaxEvents {
		return fmt.Errorf("%w: %d (rango permitido 1-%d)", ErrInvalidCount, count, MaxEvents)
	}
	return nil
}

// Generator crea payloads con identificadores pseudónimos (UID).
type Generator struct {
	rng   *rand.Rand
	start time.Time
}

// New crea un generador reproducible a partir de dos semillas. Los eventos
// parten de start y avanzan en el tiempo.
func New(seed1, seed2 uint64, start time.Time) *Generator {
	return &Generator{
		rng:   rand.New(rand.NewPCG(seed1, seed2)),
		start: start.UTC().Truncate(time.Second),
	}
}

// Generate devuelve count payloads (aún sin hash) ordenados cronológicamente.
func (g *Generator) Generate(count int) ([]domain.Payload, error) {
	if err := ValidateCount(count); err != nil {
		return nil, err
	}
	payloads := make([]domain.Payload, 0, count)
	clock := g.start
	for seq := 1; seq <= count; seq++ {
		clock = clock.Add(time.Duration(1+g.rng.IntN(maxStepSeconds)) * time.Second)
		payloads = append(payloads, g.nextPayload(seq, clock))
	}
	return payloads, nil
}

func (g *Generator) nextPayload(seq int, ts time.Time) domain.Payload {
	p := domain.Payload{
		EventID:    fmt.Sprintf("EVT-%08d", seq),
		Timestamp:  ts,
		ActorUID:   g.uid("PRF", 3, professorPool),
		StudentUID: g.uid("STU", 5, studentPool),
		CourseUID:  g.uid("CRS", 3, coursePool),
	}

	if g.rng.IntN(2) == 0 {
		p.EventType = domain.GradeRegistered
		p.NewValue = cents(g.rng.IntN(maxGradeCents + 1))
		return p
	}

	// Modificación: el nuevo valor se sortea sobre los 500 valores restantes,
	// lo que garantiza new != previous sin sesgar la distribución.
	prev := g.rng.IntN(maxGradeCents + 1)
	next := g.rng.IntN(maxGradeCents)
	if next >= prev {
		next++
	}
	previous := cents(prev)
	p.EventType = domain.GradeModified
	p.PreviousValue = &previous
	p.NewValue = cents(next)
	return p
}

func (g *Generator) uid(prefix string, width, pool int) string {
	return fmt.Sprintf("%s-%0*d", prefix, width, 1+g.rng.IntN(pool))
}

func cents(n int) float64 { return float64(n) / 100 }
