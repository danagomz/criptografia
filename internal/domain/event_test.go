package domain

import (
	"testing"
	"time"
)

func TestNewLog(t *testing.T) {
	at := time.Date(2026, 10, 25, 14, 30, 5, 999, time.FixedZone("COT", -5*3600))
	events := []Event{
		{Payload: Payload{EventType: GradeRegistered}},
		{Payload: Payload{EventType: GradeModified}},
		{Payload: Payload{EventType: GradeModified}},
	}

	l := NewLog(events, at)

	if l.SchemaVersion != SchemaVersion {
		t.Errorf("SchemaVersion = %q, quiero %q", l.SchemaVersion, SchemaVersion)
	}
	if l.EventCount != 3 {
		t.Errorf("EventCount = %d, quiero 3", l.EventCount)
	}
	if want := "LOG-20261025T193005Z"; l.LogID != want {
		t.Errorf("LogID = %q, quiero %q", l.LogID, want)
	}
	if l.GeneratedAt.Location() != time.UTC {
		t.Error("GeneratedAt debe estar en UTC")
	}
}

func TestCountByType(t *testing.T) {
	l := NewLog([]Event{
		{Payload: Payload{EventType: GradeRegistered}},
		{Payload: Payload{EventType: GradeModified}},
		{Payload: Payload{EventType: GradeModified}},
	}, time.Now())

	got := l.CountByType()

	if got[GradeRegistered] != 1 || got[GradeModified] != 2 {
		t.Errorf("CountByType = %v", got)
	}
}
