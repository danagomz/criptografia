// Comando logvault: CLI interactiva que genera, hashea, cifra y verifica un
// log estructurado de eventos de notas.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/equipo/logvault/internal/cli"
	"github.com/equipo/logvault/internal/generator"
	"github.com/equipo/logvault/internal/pipeline"
	"github.com/equipo/logvault/internal/storage"
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
	store, err := storage.New(outDir)
	if err != nil {
		return err
	}
	now := time.Now
	seed := uint64(now().UnixNano())
	gen := generator.New(seed, seed^0x9E3779B97F4A7C15, now().Add(-24*time.Hour))

	app := cli.NewApp(cli.PromptUI{}, pipeline.New(gen, store, now), os.Stdout)
	return app.Run()
}
