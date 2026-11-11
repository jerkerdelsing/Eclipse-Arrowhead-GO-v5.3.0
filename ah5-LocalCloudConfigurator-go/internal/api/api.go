// Package api is the HTTP API and operator UI of LocalCloudConfigurator.
package api

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/colony"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/planner"
)

//go:embed web
var web embed.FS

// Backend is the ColonyOS side of the API.
type Backend interface {
	Status(ctx context.Context, executorType string) ([]string, error)
	SubmitPlan(p *planner.Plan, executorType string) (string, error)
	Deployment(id string) (*colony.Deployment, error)
}

// Server serves the API for one cloud catalog.
type Server struct {
	Catalog *catalog.Catalog
	Backend Backend
	Token   string
	// StatusTimeout bounds the wait for the cloud executor's status answer.
	StatusTimeout time.Duration
}

// SystemState is the observed state of one catalogued system.
type SystemState struct {
	ID    string `json:"id"`
	State string `json:"state"` // running, alternate, partial, stopped
	Via   string `json:"via,omitempty"`
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(web, "web")
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/catalog", s.auth(func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Catalog) }))
	mux.HandleFunc("GET /api/status", s.auth(s.status))
	mux.HandleFunc("POST /api/plan", s.auth(s.plan))
	mux.HandleFunc("POST /api/deployments", s.auth(s.deploy))
	mux.HandleFunc("GET /api/deployments/{id}", s.auth(s.deployment))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if s.Token == "" || !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "operator token required"})
			return
		}
		h(w, r)
	}
}

func (s *Server) running(ctx context.Context) ([]string, error) {
	t := s.StatusTimeout
	if t == 0 {
		t = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t)
	defer cancel()
	return s.Backend.Status(ctx, s.Catalog.ExecutorType)
}

// States derives the state of each catalogued system from the running services.
func States(c *catalog.Catalog, running []string) []SystemState {
	on := map[string]bool{}
	for _, r := range running {
		on[r] = true
	}
	var out []SystemState
	for _, sys := range c.Systems {
		st := SystemState{ID: sys.ID, State: "stopped"}
		n := 0
		for _, svc := range sys.Services {
			if on[svc] {
				n++
			}
		}
		switch {
		case n == len(sys.Services):
			st.State = "running"
		case n > 0:
			st.State = "partial"
		}
		for _, a := range sys.Alternates {
			if on[a] && st.State != "running" {
				st.State, st.Via = "alternate", a
			}
		}
		out = append(out, st)
	}
	return out
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	run, err := s.running(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"cloud": s.Catalog.Cloud, "running": run, "systems": States(s.Catalog, run)})
}

func (s *Server) buildPlan(w http.ResponseWriter, r *http.Request) (*planner.Plan, bool) {
	var req planner.Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
		return nil, false
	}
	run, err := s.running(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return nil, false
	}
	p, err := planner.Build(s.Catalog, req, run)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
		return nil, false
	}
	return p, true
}

func (s *Server) plan(w http.ResponseWriter, r *http.Request) {
	if p, ok := s.buildPlan(w, r); ok {
		writeJSON(w, 200, p)
	}
}

func (s *Server) deploy(w http.ResponseWriter, r *http.Request) {
	p, ok := s.buildPlan(w, r)
	if !ok {
		return
	}
	if len(p.Steps) == 0 {
		writeJSON(w, 200, map[string]any{"plan": p, "id": ""})
		return
	}
	id, err := s.Backend.SubmitPlan(p, s.Catalog.ExecutorType)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"plan": p, "id": id})
}

func (s *Server) deployment(w http.ResponseWriter, r *http.Request) {
	d, err := s.Backend.Deployment(r.PathValue("id"))
	if err != nil {
		code := http.StatusBadGateway
		if errors.Is(err, ErrNotFound) {
			code = http.StatusNotFound
		}
		writeJSON(w, code, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, d)
}

// ErrNotFound may be returned by a Backend for an unknown deployment.
var ErrNotFound = errors.New("deployment not found")

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
