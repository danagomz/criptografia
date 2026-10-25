// Package cli implementa el menú interactivo. La interacción con la terminal
// vive detrás de la interfaz Prompter para poder probar el flujo sin TTY.
package cli

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/equipo/logvault/internal/domain"
	"github.com/equipo/logvault/internal/generator"
	"github.com/equipo/logvault/internal/pipeline"
)

// ErrAborted indica que el usuario canceló (Ctrl+C / Ctrl+D) en un prompt.
var ErrAborted = errors.New("cli: operación cancelada por el usuario")

// Prompter abstrae la interacción con la terminal (implementada con promptui).
type Prompter interface {
	// Select muestra un menú y devuelve el índice elegido.
	Select(label string, items []string) (int, error)
	// Ask pide un texto validándolo mientras se escribe.
	Ask(label string, validate func(string) error) (string, error)
}

// Runner es la parte del pipeline que consume la interfaz.
type Runner interface {
	Run(count int) (pipeline.Result, error)
	VerifyStored() error
	SimulateTampering() (pipeline.TamperReport, error)
}

const (
	menuRun = iota
	menuShowLast
	menuVerify
	menuTamper
	menuExit
)

var menuItems = []string{
	menuRun:      "Ejecutar flujo completo (pasos 1-10)",
	menuShowLast: "Ver resultados de la última ejecución",
	menuVerify:   "Verificar artefactos almacenados",
	menuTamper:   "Simular manipulación del log cifrado",
	menuExit:     "Salir",
}

// App es la aplicación interactiva.
type App struct {
	prompter Prompter
	runner   Runner
	out      io.Writer
	last     *pipeline.Result
}

// NewApp construye la aplicación.
func NewApp(p Prompter, r Runner, out io.Writer) *App {
	return &App{prompter: p, runner: r, out: out}
}

// Run muestra el menú hasta que el usuario sale o cancela. Los errores de cada
// acción se informan sin terminar el programa.
func (a *App) Run() error {
	fmt.Fprintln(a.out, "LogVault — protección de logs académicos en reposo")
	for {
		idx, err := a.prompter.Select("Menú principal", menuItems)
		if errors.Is(err, ErrAborted) {
			return nil
		}
		if err != nil {
			return err
		}
		switch idx {
		case menuRun:
			err = a.runFlow()
		case menuShowLast:
			a.showLast()
		case menuVerify:
			err = a.verify()
		case menuTamper:
			err = a.tamper()
		case menuExit:
			fmt.Fprintln(a.out, "Hasta pronto.")
			return nil
		}
		if errors.Is(err, ErrAborted) {
			return nil
		}
		if err != nil {
			fmt.Fprintf(a.out, "\nError: %v\n\n", err)
		}
	}
}

func (a *App) runFlow() error {
	label := fmt.Sprintf("Cantidad de eventos a generar (1-%d)", generator.MaxEvents)
	answer, err := a.prompter.Ask(label, func(s string) error {
		_, err := ParseCount(s)
		return err
	})
	if err != nil {
		return err
	}
	count, err := ParseCount(answer)
	if err != nil {
		return err
	}
	res, err := a.runner.Run(count)
	if err != nil {
		return err
	}
	a.last = &res
	fmt.Fprintln(a.out, FormatResult(res))
	return nil
}

func (a *App) showLast() {
	if a.last == nil {
		fmt.Fprint(a.out, "\nAún no hay ejecuciones en esta sesión.\n\n")
		return
	}
	fmt.Fprintln(a.out, FormatResult(*a.last))
}

func (a *App) verify() error {
	if err := a.runner.VerifyStored(); err != nil {
		return fmt.Errorf("verificación FALLIDA: %w", err)
	}
	fmt.Fprint(a.out, "\nVerificación OK: hash del cifrado, descifrado, hash del original y hash de cada evento coinciden.\n\n")
	return nil
}

func (a *App) tamper() error {
	report, err := a.runner.SimulateTampering()
	if err != nil {
		return err
	}
	fmt.Fprintln(a.out, "\nSe alteró 1 byte del log cifrado (solo en memoria):")
	fmt.Fprintf(a.out, "  - Hash SHA-256 almacenado ya no coincide: %s\n", yesNo(report.HashMismatchDetected))
	fmt.Fprintf(a.out, "  - Etiqueta de autenticación GCM rechazó el descifrado: %s\n", yesNo(report.AuthenticationFailed))
	if report.Detected() {
		fmt.Fprint(a.out, "Resultado: ALTERACIÓN DETECTADA.\n\n")
	} else {
		fmt.Fprint(a.out, "Resultado: ¡la alteración NO fue detectada!\n\n")
	}
	return nil
}

// ParseCount convierte y valida la cantidad de eventos ingresada.
func ParseCount(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("ingrese un número entero")
	}
	if err := generator.ValidateCount(n); err != nil {
		return 0, err
	}
	return n, nil
}

// FormatResult arma el reporte del paso 10.
func FormatResult(r pipeline.Result) string {
	var b strings.Builder
	line := func(label, value string) { fmt.Fprintf(&b, "  %-44s %s\n", label, value) }

	b.WriteString("\n══════════ RESULTADOS ══════════\n")
	line("Eventos generados:", strconv.Itoa(r.EventCount))
	line("  Registros de nota (GRADE_REGISTERED):", strconv.Itoa(r.CountsByType[domain.GradeRegistered]))
	line("  Modificaciones de nota (GRADE_MODIFIED):", strconv.Itoa(r.CountsByType[domain.GradeModified]))
	line("Artefactos guardados en:", r.OutputDir)
	b.WriteString("\n  SHA-256 por etapa\n")
	line("  1. Log original (texto plano):", r.PlainHash)
	line("  2. Log cifrado (AES-256-GCM):", r.CipherHash)
	line("  3. Log descifrado:", r.DecryptedHash)
	b.WriteString("\n  Verificaciones\n")
	line("  Hash del cifrado verificado antes de descifrar:", yesNo(r.CipherHashVerified))
	line("  Hash de payload válido en todos los eventos:", yesNo(r.EventHashesValid))
	line("  Original == descifrado (comparación de hashes):", yesNo(r.Preserved))
	b.WriteString("\n")
	if r.Preserved && r.EventHashesValid {
		b.WriteString("  CONCLUSIÓN: el proceso PRESERVÓ la información original.\n")
	} else {
		b.WriteString("  CONCLUSIÓN: la información original NO se preservó.\n")
	}
	return b.String()
}

func yesNo(v bool) string {
	if v {
		return "SÍ"
	}
	return "NO"
}
