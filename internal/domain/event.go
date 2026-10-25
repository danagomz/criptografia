// Package domain define el modelo de datos del log de eventos académicos.
package domain

import "time"

// SchemaVersion identifica la versión del esquema JSON del log.
const SchemaVersion = "1.0"

// EventType distingue las dos operaciones sensibles del dominio.
type EventType string

const (
	// GradeRegistered es el registro inicial de una nota.
	GradeRegistered EventType = "GRADE_REGISTERED"
	// GradeModified es la modificación de una nota ya registrada.
	GradeModified EventType = "GRADE_MODIFIED"
)

// Payload contiene exactamente los campos cubiertos por el hash del evento.
//
// El hash NO forma parte del payload: se mantiene en Event. Así se evita por
// construcción la circularidad (el hash no puede depender de sí mismo).
type Payload struct {
	EventID       string    `json:"event_id"`
	EventType     EventType `json:"event_type"`
	Timestamp     time.Time `json:"timestamp"`
	ActorUID      string    `json:"actor_uid"`
	StudentUID    string    `json:"student_uid"`
	CourseUID     string    `json:"course_uid"`
	PreviousValue *float64  `json:"previous_value,omitempty"`
	NewValue      float64   `json:"new_value"`
}

// Event es el payload más su hash de integridad. Al serializarse a JSON,
// los campos del payload quedan en el mismo nivel que payload_hash.
type Event struct {
	Payload
	PayloadHash string `json:"payload_hash"`
}

// Log es el documento completo que se hashea, cifra y recupera.
type Log struct {
	SchemaVersion string    `json:"schema_version"`
	LogID         string    `json:"log_id"`
	GeneratedAt   time.Time `json:"generated_at"`
	EventCount    int       `json:"event_count"`
	Events        []Event   `json:"events"`
}

// NewLog consolida los eventos en un log con metadatos coherentes.
func NewLog(events []Event, generatedAt time.Time) Log {
	generatedAt = generatedAt.UTC().Truncate(time.Second)
	return Log{
		SchemaVersion: SchemaVersion,
		LogID:         "LOG-" + generatedAt.Format("20060102T150405Z"),
		GeneratedAt:   generatedAt,
		EventCount:    len(events),
		Events:        events,
	}
}

// CountByType devuelve cuántos eventos hay de cada tipo.
func (l Log) CountByType() map[EventType]int {
	counts := make(map[EventType]int, 2)
	for _, e := range l.Events {
		counts[e.EventType]++
	}
	return counts
}
