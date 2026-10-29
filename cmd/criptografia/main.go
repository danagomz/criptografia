// Programa criptografia: CLI interactiva que genera, hashea, cifra y verifica un
// log estructurado de eventos de notas.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/equipo/criptografia/internal/almacenamiento"
	"github.com/equipo/criptografia/internal/flujo"
	"github.com/equipo/criptografia/internal/generador"
	"github.com/equipo/criptografia/internal/menu"
	"github.com/equipo/criptografia/internal/webui"
)

func main() {
	outDir := flag.String("out", "output", "directorio donde se guardan los artefactos")
	web := flag.Bool("web", false, "iniciar interfaz web local")
	addr := flag.String("addr", "127.0.0.1:8080", "dirección de la interfaz web")
	flag.Parse()

	var err error
	if *web {
		err = runWeb(*outDir, *addr)
	} else {
		err = run(*outDir)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func runWeb(outDir, addr string) error {
	store, err := almacenamiento.New(outDir)
	if err != nil {
		return err
	}
	now := time.Now
	seed := uint64(now().UnixNano())
	pipeline := flujo.New(generador.New(seed, seed^0x9E3779B97F4A7C15, now().Add(-24*time.Hour)), store, now)
	fmt.Printf("Interfaz lista en http://%s (artefactos: %s)\n", addr, filepath.Clean(outDir))
	return http.ListenAndServe(addr, webui.New(pipeline, store))
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
