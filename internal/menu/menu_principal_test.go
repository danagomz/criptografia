package menu

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/equipo/criptografia/internal/flujo"
	"github.com/equipo/criptografia/internal/generador"
	"github.com/equipo/criptografia/internal/modelo"
)

// fakePrompter reproduce un guion de selecciones y respuestas.
type fakePrompter struct {
	selects []int
	answers []string
}

func (f *fakePrompter) Select(string, []string) (int, error) {
	if len(f.selects) == 0 {
		return 0, ErrAborted
	}
	v := f.selects[0]
	f.selects = f.selects[1:]
	return v, nil
}

func (f *fakePrompter) Ask(_ string, validate func(string) error) (string, error) {
	if len(f.answers) == 0 {
		return "", ErrAborted
	}
	v := f.answers[0]
	f.answers = f.answers[1:]
	return v, validate(v)
}

type fakeRunner struct {
	result       flujo.Result
	runErr       error
	verifyErr    error
	tamper       flujo.TamperReport
	runCounts    []int
	verifyCalled int
}

func (f *fakeRunner) Run(count int) (flujo.Result, error) {
	f.runCounts = append(f.runCounts, count)
	return f.result, f.runErr
}
func (f *fakeRunner) VerifyStored() error { f.verifyCalled++; return f.verifyErr }
func (f *fakeRunner) SimulateTampering() (flujo.TamperReport, error) {
	return f.tamper, nil
}

func goodResult() flujo.Result {
	return flujo.Result{
		OutputDir:  "output",
		EventCount: 5,
		CountsByType: map[modelo.EventType]int{
			modelo.GradeRegistered: 2, modelo.GradeModified: 3,
		},
		PlainHash: "aaaa", CipherHash: "bbbb", DecryptedHash: "aaaa",
		CipherHashVerified: true, EventHashesValid: true, Preserved: true,
	}
}

func runApp(t *testing.T, p *fakePrompter, r *fakeRunner) string {
	t.Helper()
	var out bytes.Buffer
	if err := NewApp(p, r, &out).Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out.String()
}

func TestParseCount(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"10", 10, false},
		{"  25 ", 25, false},
		{"1", 1, false},
		{"100000", 100000, false},
		{"0", 0, true},
		{"-3", 0, true},
		{"100001", 0, true},
		{"abc", 0, true},
		{"", 0, true},
		{"2.5", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseCount(tt.in)
		if (err != nil) != tt.wantErr || got != tt.want {
			t.Errorf("ParseCount(%q) = %d, %v", tt.in, got, err)
		}
	}
}

func TestParseCountRangeErrorWrapsSentinel(t *testing.T) {
	if _, err := ParseCount("0"); !errors.Is(err, generador.ErrInvalidCount) {
		t.Errorf("err = %v", err)
	}
}

func TestRunFlowShowsFullReport(t *testing.T) {
	r := &fakeRunner{result: goodResult()}
	out := runApp(t, &fakePrompter{selects: []int{menuRun, menuExit}, answers: []string{"5"}}, r)

	if len(r.runCounts) != 1 || r.runCounts[0] != 5 {
		t.Errorf("runCounts = %v", r.runCounts)
	}
	for _, want := range []string{"aaaa", "bbbb", "GRADE_REGISTERED", "GRADE_MODIFIED",
		"PRESERVÓ la información original", "Hasta pronto"} {
		if !strings.Contains(out, want) {
			t.Errorf("la salida no contiene %q:\n%s", want, out)
		}
	}
}

func TestInvalidCountDoesNotRunPipeline(t *testing.T) {
	r := &fakeRunner{result: goodResult()}
	out := runApp(t, &fakePrompter{selects: []int{menuRun, menuExit}, answers: []string{"0"}}, r)

	if len(r.runCounts) != 0 {
		t.Error("no debe ejecutarse el pipeline con una cantidad inválida")
	}
	if !strings.Contains(out, "Error:") {
		t.Errorf("debe informar el error:\n%s", out)
	}
}

func TestRunErrorIsReportedAndMenuContinues(t *testing.T) {
	r := &fakeRunner{runErr: errors.New("disco lleno")}
	out := runApp(t, &fakePrompter{selects: []int{menuRun, menuExit}, answers: []string{"3"}}, r)

	if !strings.Contains(out, "disco lleno") || !strings.Contains(out, "Hasta pronto") {
		t.Errorf("salida inesperada:\n%s", out)
	}
}

func TestShowLastBeforeAndAfterRun(t *testing.T) {
	r := &fakeRunner{result: goodResult()}
	out := runApp(t, &fakePrompter{
		selects: []int{menuShowLast, menuRun, menuShowLast, menuExit},
		answers: []string{"5"},
	}, r)

	if !strings.Contains(out, "Aún no hay ejecuciones") {
		t.Error("debe avisar que no hay ejecuciones previas")
	}
	if strings.Count(out, "RESULTADOS") != 2 {
		t.Errorf("el reporte debe mostrarse dos veces:\n%s", out)
	}
}

func TestVerifyOKAndFailure(t *testing.T) {
	ok := runApp(t, &fakePrompter{selects: []int{menuVerify, menuExit}}, &fakeRunner{})
	if !strings.Contains(ok, "Verificación OK") {
		t.Errorf("salida: %s", ok)
	}

	bad := runApp(t, &fakePrompter{selects: []int{menuVerify, menuExit}},
		&fakeRunner{verifyErr: errors.New("hash distinto")})
	if !strings.Contains(bad, "verificación FALLIDA") || !strings.Contains(bad, "hash distinto") {
		t.Errorf("salida: %s", bad)
	}
}

func TestTamperReport(t *testing.T) {
	detected := runApp(t, &fakePrompter{selects: []int{menuTamper, menuExit}},
		&fakeRunner{tamper: flujo.TamperReport{HashMismatchDetected: true, AuthenticationFailed: true}})
	if !strings.Contains(detected, "ALTERACIÓN DETECTADA") {
		t.Errorf("salida: %s", detected)
	}

	missed := runApp(t, &fakePrompter{selects: []int{menuTamper, menuExit}}, &fakeRunner{})
	if !strings.Contains(missed, "NO fue detectada") {
		t.Errorf("salida: %s", missed)
	}
}

func TestAbortEndsGracefully(t *testing.T) {
	// Sin selecciones, el fake devuelve ErrAborted (Ctrl+C del usuario).
	out := runApp(t, &fakePrompter{}, &fakeRunner{})
	if strings.Contains(out, "Error:") {
		t.Errorf("cancelar no debe mostrar error:\n%s", out)
	}
}

func TestFormatResultNotPreserved(t *testing.T) {
	res := goodResult()
	res.DecryptedHash, res.Preserved = "cccc", false

	out := FormatResult(res)

	if !strings.Contains(out, "NO se preservó") {
		t.Errorf("salida: %s", out)
	}
}
