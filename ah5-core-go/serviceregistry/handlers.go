package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

const basePath = "/serviceregistry"

// Server wires the HTTP API to the Registry.
type Server struct {
	cfg  *Config
	rg   *Registry
	log  *Logger
	auth *Authenticator
	mux  *http.ServeMux
}

func NewServer(cfg *Config, rg *Registry, log *Logger, auth *Authenticator) *Server {
	s := &Server{cfg: cfg, rg: rg, log: log, auth: auth, mux: http.NewServeMux()}
	s.routes()
	return s
}

// Handler returns the complete handler chain (logging -> authentication -> routes).
func (s *Server) Handler() http.Handler {
	var h http.Handler = s.mux
	if s.auth != nil {
		h = s.auth.Middleware(h)
	}
	return s.logging(h)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }

func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.LogAllReqResp {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		s.log.Infof("http", "%s %s -> %d", r.Method, r.URL.RequestURI(), rec.status)
	})
}

type handlerFn func(r *http.Request) (int, any, error)

func (s *Server) route(pattern string, fn handlerFn) {
	// pattern is "METHOD /path"
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		origin := r.Method + " " + r.URL.Path
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		r.Body = io.NopCloser(bytes.NewReader(raw))
		status, body, err := fn(r)
		if err != nil {
			who, _ := identity(r)
			code := 500
			if ae, ok := err.(*AHError); ok {
				code = ae.Type.status()
			}
			snippet := string(raw)
			if len(snippet) > 1500 {
				snippet = snippet[:1500] + "..."
			}
			s.log.Warnf("http", "%s %s by %s -> %d: %v | request: %s", r.Method, r.URL.RequestURI(), who, code, err, snippet)
			writeError(w, err, origin)
			return
		}
		if status == http.StatusNoContent || body == nil {
			w.WriteHeader(status)
			return
		}
		writeJSON(w, status, body)
	})
}

// decode reads the JSON body into a new T. An empty body yields nil (so that the service layer
// reports "Request payload is missing"); malformed JSON is an invalid-parameter error.
func decode[T any](r *http.Request) (*T, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		return nil, errInvalid("Request payload cannot be read")
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	v := new(T)
	if err := json.Unmarshal(data, v); err != nil {
		return nil, errInvalid("Invalid request payload: " + err.Error())
	}
	return v, nil
}

// qList returns repeated and/or comma separated values of a query parameter (nil if absent).
func qList(r *http.Request, key string) []string {
	vals, ok := r.URL.Query()[key]
	if !ok {
		return nil
	}
	out := []string{}
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}

func qBool(r *http.Request, key string) bool {
	b, _ := strconv.ParseBool(strings.TrimSpace(r.URL.Query().Get(key)))
	return b
}

func createdStatus(created bool) int {
	if created {
		return http.StatusCreated
	}
	return http.StatusOK
}

func revokedStatus(found bool) int {
	if found {
		return http.StatusOK
	}
	return http.StatusNoContent
}

func (s *Server) isDirectAccess(name string, sysop bool) bool {
	return sysop || containsStr(s.cfg.ServiceDiscoveryDirectAccess, name)
}

func (s *Server) routes() {
	rg := s.rg
	b := basePath

	s.mux.HandleFunc("GET "+b+"/monitor/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		_, _ = w.Write([]byte("Got it!"))
	})
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, &AHError{Type: ExDataNotFound, Msg: "Not found"}, r.Method+" "+r.URL.Path)
	})

	// ---- device discovery
	s.route("POST "+b+"/device-discovery/register", func(r *http.Request) (int, any, error) {
		req, err := decode[DeviceReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, created, err := rg.RegisterDevice(req)
		return createdStatus(created), resp, err
	})
	s.route("POST "+b+"/device-discovery/lookup", func(r *http.Request) (int, any, error) {
		req, err := decode[DeviceLookupReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.LookupDevice(req)
		return 200, resp, err
	})
	s.route("DELETE "+b+"/device-discovery/revoke/{name}", func(r *http.Request) (int, any, error) {
		found, err := rg.RevokeDevice(r.PathValue("name"))
		return revokedStatus(found), nil, err
	})

	// ---- system discovery
	s.route("POST "+b+"/system-discovery/register", func(r *http.Request) (int, any, error) {
		req, err := decode[SystemRegisterReq](r)
		if err != nil {
			return 0, nil, err
		}
		name, _ := identity(r)
		resp, created, err := rg.RegisterSystem(name, req)
		return createdStatus(created), resp, err
	})
	s.route("POST "+b+"/system-discovery/lookup", func(r *http.Request) (int, any, error) {
		req, err := decode[SystemLookupReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.LookupSystem(req, qBool(r, "verbose"))
		return 200, resp, err
	})
	s.route("DELETE "+b+"/system-discovery/revoke", func(r *http.Request) (int, any, error) {
		name, _ := identity(r)
		found, err := rg.RevokeSystem(name)
		return revokedStatus(found), nil, err
	})

	// ---- service discovery
	s.route("POST "+b+"/service-discovery/register", func(r *http.Request) (int, any, error) {
		req, err := decode[InstanceReq](r)
		if err != nil {
			return 0, nil, err
		}
		name, sysop := identity(r)
		if req != nil && (!sysop || isBlank(req.SystemName)) {
			req.SystemName = name
		}
		resp, err := rg.RegisterService(req)
		return http.StatusCreated, resp, err
	})
	s.route("POST "+b+"/service-discovery/lookup", func(r *http.Request) (int, any, error) {
		// Every system must be able to discover Authentication before it can
		// obtain the identity token used by restricted discovery. The auth
		// middleware already permits this exact bootstrap lookup; applying the
		// authorization filter again here produced an empty result and broke
		// Java support systems after a drop-in registry swap.
		identityBootstrap := isIdentityLookup(r)
		req, err := decode[InstanceLookupReq](r)
		if err != nil {
			return 0, nil, err
		}
		name, sysop := identity(r)
		restricted := s.cfg.ServiceDiscoveryPolicy == "restricted" && !identityBootstrap && !s.isDirectAccess(name, sysop)
		resp, err := rg.LookupService(req, qBool(r, "verbose"), restricted)
		return 200, resp, err
	})
	s.route("DELETE "+b+"/service-discovery/revoke/{instanceId}", func(r *http.Request) (int, any, error) {
		name, _ := identity(r)
		found, err := rg.RevokeService(name, r.PathValue("instanceId"))
		return revokedStatus(found), nil, err
	})

	// ---- management: devices
	s.route("POST "+b+"/mgmt/devices/query", func(r *http.Request) (int, any, error) {
		req, err := decode[DeviceQueryReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.QueryDevices(req)
		return 200, resp, err
	})
	s.route("POST "+b+"/mgmt/devices", func(r *http.Request) (int, any, error) {
		req, err := decode[DeviceListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.CreateDevices(req)
		return http.StatusCreated, resp, err
	})
	s.route("PUT "+b+"/mgmt/devices", func(r *http.Request) (int, any, error) {
		req, err := decode[DeviceListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.UpdateDevices(req)
		return 200, resp, err
	})
	s.route("DELETE "+b+"/mgmt/devices", func(r *http.Request) (int, any, error) {
		return 200, nil, rg.RemoveDevices(qList(r, "names"))
	})

	// ---- management: systems
	s.route("POST "+b+"/mgmt/systems/query", func(r *http.Request) (int, any, error) {
		req, err := decode[SystemQueryReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.QuerySystems(req, qBool(r, "verbose"))
		return 200, resp, err
	})
	s.route("POST "+b+"/mgmt/systems", func(r *http.Request) (int, any, error) {
		req, err := decode[SystemListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.CreateSystems(req)
		return http.StatusCreated, resp, err
	})
	s.route("PUT "+b+"/mgmt/systems", func(r *http.Request) (int, any, error) {
		req, err := decode[SystemListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.UpdateSystems(req)
		return 200, resp, err
	})
	s.route("DELETE "+b+"/mgmt/systems", func(r *http.Request) (int, any, error) {
		return 200, nil, rg.RemoveSystems(qList(r, "names"))
	})

	// ---- management: service definitions
	s.route("POST "+b+"/mgmt/service-definitions/query", func(r *http.Request) (int, any, error) {
		req, err := decode[PageDTO](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.QueryServiceDefinitions(req)
		return 200, resp, err
	})
	s.route("POST "+b+"/mgmt/service-definitions", func(r *http.Request) (int, any, error) {
		req, err := decode[ServiceDefListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.CreateServiceDefinitions(req)
		return http.StatusCreated, resp, err
	})
	s.route("DELETE "+b+"/mgmt/service-definitions", func(r *http.Request) (int, any, error) {
		return 200, nil, rg.RemoveServiceDefinitions(qList(r, "names"))
	})

	// ---- management: service instances
	s.route("POST "+b+"/mgmt/service-instances/query", func(r *http.Request) (int, any, error) {
		req, err := decode[InstanceQueryReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.QueryServiceInstances(req, qBool(r, "verbose"))
		return 200, resp, err
	})
	s.route("POST "+b+"/mgmt/service-instances", func(r *http.Request) (int, any, error) {
		req, err := decode[InstanceCreateListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.CreateServiceInstances(req)
		return http.StatusCreated, resp, err
	})
	s.route("PUT "+b+"/mgmt/service-instances", func(r *http.Request) (int, any, error) {
		req, err := decode[InstanceUpdateListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.UpdateServiceInstances(req)
		return 200, resp, err
	})
	s.route("DELETE "+b+"/mgmt/service-instances", func(r *http.Request) (int, any, error) {
		return 200, nil, rg.RemoveServiceInstances(qList(r, "serviceInstances"))
	})

	// ---- management: interface templates
	s.route("POST "+b+"/mgmt/interface-templates/query", func(r *http.Request) (int, any, error) {
		req, err := decode[TemplateQueryReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.QueryInterfaceTemplates(req)
		return 200, resp, err
	})
	s.route("POST "+b+"/mgmt/interface-templates", func(r *http.Request) (int, any, error) {
		req, err := decode[TemplateListReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.CreateInterfaceTemplates(req)
		return http.StatusCreated, resp, err
	})
	s.route("DELETE "+b+"/mgmt/interface-templates", func(r *http.Request) (int, any, error) {
		return 200, nil, rg.RemoveInterfaceTemplates(qList(r, "names"))
	})

	// ---- general management
	s.route("POST "+b+"/general/mgmt/logs", func(r *http.Request) (int, any, error) {
		req, err := decode[LogReq](r)
		if err != nil {
			return 0, nil, err
		}
		resp, err := rg.GetLogs(req)
		return 200, resp, err
	})
	s.route("GET "+b+"/general/mgmt/get-config", func(r *http.Request) (int, any, error) {
		resp, err := rg.GetConfig(qList(r, "keys"))
		return 200, resp, err
	})
}
