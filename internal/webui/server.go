// Package webui sirve la interfaz local y conecta sus acciones con flujo.Pipeline.
package webui

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"
	"sync"

	"github.com/equipo/criptografia/internal/almacenamiento"
	"github.com/equipo/criptografia/internal/flujo"
	"github.com/equipo/criptografia/internal/generador"
	"github.com/equipo/criptografia/internal/modelo"
)

// Runner reúne las operaciones usadas por la página.
type Runner interface {
	Run(int) (flujo.Result, error)
	VerifyStored() error
	SimulateTampering() (flujo.TamperReport, error)
}

type server struct {
	runner Runner
	store  *almacenamiento.Store
	mu     sync.Mutex
}

type runResponse struct {
	flujo.Result
	Events []modelo.Event `json:"events"`
}

// New construye un handler para la UI y su API JSON.
func New(runner Runner, store *almacenamiento.Store) http.Handler {
	s := &server{runner: runner, store: store}
	assets, _ := fs.Sub(staticFiles, "static")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/api/run", s.run)
	mux.HandleFunc("/api/verify", s.verify)
	mux.HandleFunc("/api/tamper", s.tamper)
	return mux
}

func (s *server) run(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&input); err != nil || input.Count < 1 || input.Count > generador.MaxEvents {
		writeError(w, "Indica una cantidad entre 1 y "+strconv.Itoa(generador.MaxEvents)+".", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.runner.Run(input.Count)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := s.store.Read(flujo.FilePlainLog)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var log modelo.Log
	if err = json.Unmarshal(data, &log); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, runResponse{Result: result, Events: log.Events})
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.runner.VerifyStored()
	if err != nil {
		writeJSON(w, map[string]any{"valid": false, "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"valid": true, "message": "Artefactos verificados correctamente."})
}

func (s *server) tamper(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report, err := s.runner.SimulateTampering()
	if err != nil {
		writeError(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]any{"report": report, "detected": report.Detected()})
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
