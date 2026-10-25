// Programa proteccion-logs: CLI interactiva que genera, hashea, cifra y verifica un
// log estructurado de eventos de notas.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/equipo/proteccion-logs/internal/almacenamiento"
	"github.com/equipo/proteccion-logs/internal/flujo"
	"github.com/equipo/proteccion-logs/internal/generador"
	"github.com/equipo/proteccion-logs/internal/menu"
)

func main() {
	outDir := flag.String("out", "output", "directorio donde se guardan los artefactos")
	flag.Parse()

	if err := run(*outDir); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(outDir string) error {
	store, err := almacenamiento.New(outDir)
	if err != nil {
		return err
	}
	now := time.Now
	seed := uint64(now().UnixNano())
	gen := generador.New(seed, seed^0x9E3779B97F4A7C15, now().Add(-24*time.Hour))

	app := menu.NewApp(menu.PromptUI{}, flujo.New(gen, store, now), os.Stdout)
	return app.Run()
}
