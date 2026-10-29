// Package webui sirve una interfaz HTML local que conecta con flujo.Pipeline.
package webui

import (
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"sync"

	"github.com/equipo/criptografia/internal/almacenamiento"
	"github.com/equipo/criptografia/internal/flujo"
	"github.com/equipo/criptografia/internal/generador"
	"github.com/equipo/criptografia/internal/modelo"
)

type Runner interface {
	Run(int) (flujo.Result, error)
	VerifyStored() error
	SimulateTampering() (flujo.TamperReport, error)
}

type server struct {
	runner Runner
	store  *almacenamiento.Store
	mu     sync.Mutex
	page   pageData
}

type displayEvent struct {
	EventID     string
	TypeLabel   string
	Modified    bool
	StudentUID  string
	CourseUID   string
	Previous    float64
	NewValue    float64
	PayloadHash string
}

type pageData struct {
	Count          int
	HasResult      bool
	EventCount     int
	Registered     int
	Modified       int
	PlainHash      string
	CipherHash     string
	DecryptedHash  string
	Preserved      bool
	StatusKind     string
	StatusTitle    string
	StatusMessage  string
	BadgeText      string
	BadgeKind      string
	ComparisonText string
	ComparisonKind string
	Events         []displayEvent
}

var pageTemplate = template.Must(template.ParseFS(staticFiles, "static/index.html"))

// New construye el handler para la interfaz y sus formularios.
func New(runner Runner, store *almacenamiento.Store) http.Handler {
	assets, _ := fs.Sub(staticFiles, "static")
	s := &server{
		runner: runner,
		store:  store,
		page: pageData{
			Count:          12,
			StatusTitle:    "Listo",
			StatusMessage:  "Ejecuta el flujo para ver los resultados.",
			BadgeText:      "Sin ejecución",
			ComparisonText: "Aún no hay resultados.",
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.Handle("/styles.css", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/run", s.run)
	mux.HandleFunc("/verify", s.verify)
	mux.HandleFunc("/tamper", s.tamper)
	return mux
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.render(w)
}

func (s *server) run(w http.ResponseWriter, r *http.Request) {
	if !s.postOnly(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "formulario inválido", http.StatusBadRequest)
		return
	}
	count, err := strconv.Atoi(r.FormValue("count"))
	if err != nil || generador.ValidateCount(count) != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.page.StatusKind = "failure"
		s.page.StatusTitle = "Cantidad inválida"
		s.page.StatusMessage = "Ingresa un número entero entre 1 y 100 000."
		s.render(w)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.page.Count = count
	result, err := s.runner.Run(count)
	if err != nil {
		s.setStatus("failure", "No se pudo ejecutar", err.Error())
		s.render(w)
		return
	}
	data, err := s.store.Read(flujo.FilePlainLog)
	if err != nil {
		s.setStatus("failure", "No se pudo leer el log", err.Error())
		s.render(w)
		return
	}
	var log modelo.Log
	if err := json.Unmarshal(data, &log); err != nil {
		s.setStatus("failure", "No se pudo interpretar el log", err.Error())
		s.render(w)
		return
	}

	s.page.HasResult = true
	s.page.EventCount = result.EventCount
	s.page.Registered = result.CountsByType[modelo.GradeRegistered]
	s.page.Modified = result.CountsByType[modelo.GradeModified]
	s.page.PlainHash = result.PlainHash
	s.page.CipherHash = result.CipherHash
	s.page.DecryptedHash = result.DecryptedHash
	s.page.Preserved = result.Preserved && result.EventHashesValid && result.CipherHashVerified
	s.page.Events = make([]displayEvent, 0, len(log.Events))
	for _, event := range log.Events {
		row := displayEvent{
			EventID:     event.EventID,
			TypeLabel:   "Registro",
			StudentUID:  event.StudentUID,
			CourseUID:   event.CourseUID,
			NewValue:    event.NewValue,
			PayloadHash: event.PayloadHash,
		}
		if event.EventType == modelo.GradeModified {
			row.TypeLabel = "Modificación"
			row.Modified = true
			if event.PreviousValue != nil {
				row.Previous = *event.PreviousValue
			}
		}
		s.page.Events = append(s.page.Events, row)
	}
	if s.page.Preserved {
		s.page.BadgeText = "Información preservada"
		s.page.BadgeKind = "ok"
		s.page.ComparisonKind = "ok"
		s.page.ComparisonText = "Los hashes coinciden. El descifrado recuperó el log original y los hashes de eventos son válidos."
		s.setStatus("success", "Flujo completado", "Los hashes coinciden; el log se recuperó correctamente.")
	} else {
		s.page.BadgeText = "Verificación fallida"
		s.page.BadgeKind = "bad"
		s.page.ComparisonKind = "bad"
		s.page.ComparisonText = "Hay una diferencia o un evento cuyo hash no es válido."
		s.setStatus("failure", "Flujo completado con errores", "Revisa la comparación y los hashes de los eventos.")
	}
	s.render(w)
}

func (s *server) verify(w http.ResponseWriter, r *http.Request) {
	if !s.postOnly(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.runner.VerifyStored(); err != nil {
		s.setStatus("failure", "Verificación fallida", err.Error())
	} else {
		s.setStatus("success", "Verificación correcta", "Los artefactos y hashes almacenados son válidos.")
	}
	s.render(w)
}

func (s *server) tamper(w http.ResponseWriter, r *http.Request) {
	if !s.postOnly(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	report, err := s.runner.SimulateTampering()
	if err != nil {
		s.setStatus("failure", "No se pudo simular", err.Error())
	} else if report.Detected() {
		s.setStatus("success", "Alteración detectada", "SHA-256 detectó el cambio y AES-GCM rechazó el descifrado. El archivo guardado sigue intacto.")
	} else {
		s.setStatus("failure", "Alteración no detectada", "Las defensas no detectaron el cambio simulado.")
	}
	s.render(w)
}

func (s *server) postOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "método no permitido", http.StatusMethodNotAllowed)
		return false
	}
	return true
}

func (s *server) setStatus(kind, title, message string) {
	s.page.StatusKind = kind
	s.page.StatusTitle = title
	s.page.StatusMessage = message
}

func (s *server) render(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := pageTemplate.Execute(w, s.page); err != nil {
		http.Error(w, "no se pudo mostrar la página", http.StatusInternalServerError)
	}
}
