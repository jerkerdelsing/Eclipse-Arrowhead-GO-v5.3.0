// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string       { return e.Message }
func bad(s string) error                { return &APIError{400, s} }
func forbidden() error                  { return &APIError{403, "Access denied"} }
func unsupported(s string) error        { return &APIError{501, s} }
func str(d Document, k string) string   { s, _ := d[k].(string); return s }
func obj(d Document, k string) Document { m, _ := d[k].(map[string]any); return m }
func flag(d Document, k string) bool    { b, _ := d[k].(bool); return b }
func number(d Document, k string, def int) int {
	if n, ok := d[k].(int); ok {
		return n
	}
	v, ok := d[k].(float64)
	if !ok {
		return def
	}
	return int(v)
}
func list(d Document, k string) []any { a, _ := d[k].([]any); return a }
func contains(a []any, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
func selected(d Document, k, s string) bool { return len(list(d, k)) == 0 || contains(list(d, k), s) }
func now() string                           { return time.Now().UTC().Format(time.RFC3339Nano) }
func expired(s string) bool {
	t, e := time.Parse(time.RFC3339Nano, s)
	return e != nil || !t.After(time.Now())
}
func uuid() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

var nameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)

func validName(s string) bool { return nameRE.MatchString(s) }
func require(d Document, keys ...string) error {
	for _, k := range keys {
		if strings.TrimSpace(str(d, k)) == "" {
			return bad(k + " is required")
		}
	}
	return nil
}
func decode(w http.ResponseWriter, r *http.Request) (Document, error) {
	return decodeBody(w, r, false)
}
func decodeOptional(w http.ResponseWriter, r *http.Request) (Document, error) {
	return decodeBody(w, r, true)
}
func decodeBody(w http.ResponseWriter, r *http.Request, optional bool) (Document, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	var d Document
	e := dec.Decode(&d)
	if optional && e == io.EOF {
		return Document{}, nil
	}
	if optional && e == nil && d == nil {
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return nil, bad("Expected exactly one JSON object")
		}
		return Document{}, nil
	}
	if e != nil || d == nil {
		return nil, bad("Expected a JSON object")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, bad("Expected exactly one JSON object")
	}
	return d, nil
}
func respond(w http.ResponseWriter, status int, v any) {
	if raw, ok := v.(rawResponse); ok {
		w.Header().Set("Content-Type", raw.contentType)
		w.WriteHeader(raw.status)
		_, _ = w.Write(raw.body)
		return
	}
	if b, ok := v.(binaryResponse); ok {
		w.Header().Set("Content-Type", b.ContentType)
		w.WriteHeader(status)
		_, _ = w.Write(b.Data)
		return
	}
	if text, ok := v.(textResponse); ok {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, string(text))
		return
	}
	if v == nil {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func queryNames(r *http.Request, key string) ([]string, error) {
	var out []string
	for _, v := range r.URL.Query()[key] {
		for _, s := range strings.Split(v, ",") {
			if strings.TrimSpace(s) == "" {
				return nil, bad(key + " contains an empty value")
			}
			out = append(out, strings.TrimSpace(s))
		}
	}
	if len(out) == 0 {
		return nil, bad(key + " is required")
	}
	return out, nil
}
func page(entries []Document, d Document, key string) (Document, error) {
	p := obj(d, "pagination")
	sortField := str(p, "sortField")
	if sortField == "" {
		sortField = "createdAt"
	}
	direction := str(p, "direction")
	if direction != "" && direction != "ASC" && direction != "DESC" {
		return nil, bad("Invalid sort direction")
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if a, ok := entries[i][sortField].(float64); ok {
			if b, ok := entries[j][sortField].(float64); ok && a != b {
				if direction == "DESC" {
					return a > b
				}
				return a < b
			}
		}
		a, b := fmt.Sprint(entries[i][sortField]), fmt.Sprint(entries[j][sortField])
		if a == b {
			a, b = fmt.Sprint(entries[i]["id"], entries[i]["systemName"], entries[i]["instanceId"], entries[i]["logId"]), fmt.Sprint(entries[j]["id"], entries[j]["systemName"], entries[j]["instanceId"], entries[j]["logId"])
		}
		if direction == "DESC" {
			return a > b
		}
		return a < b
	})
	n := len(entries)
	for _, k := range []string{"page", "size"} {
		if value, exists := p[k]; exists {
			v, ok := value.(float64)
			if !ok || math.Trunc(v) != v || math.IsInf(v, 0) || math.IsNaN(v) {
				return nil, bad("Pagination values must be integers")
			}
		}
	}
	pg, size := number(p, "page", 0), number(p, "size", 100)
	if pg < 0 || pg > 1000000000 || size < 1 || size > 10000 {
		return nil, bad("Invalid pagination")
	}
	start := int64(pg) * int64(size)
	if start > int64(n) {
		start = int64(n)
	}
	end := start + int64(size)
	if end > int64(n) {
		end = int64(n)
	}
	return Document{key: entries[start:end], "count": n}, nil
}

type principal struct {
	Name  string
	Sysop bool
}
type principalKey struct{}

func caller(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey{}).(principal)
	return p
}
func profile(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.String() == "2.5.4.46" {
			return fmt.Sprint(n.Value)
		}
	}
	return ""
}
func certificateIdentity(r *http.Request, suffix string) (principal, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return principal{}, &APIError{401, "Verified client certificate required"}
	}
	c := r.TLS.PeerCertificates[0]
	parts := strings.SplitN(c.Subject.CommonName, ".", 2)
	if len(parts) != 2 || parts[1] != suffix || !validName(parts[0]) || (profile(c) != "sy" && profile(c) != "op") {
		return principal{}, &APIError{401, "Invalid local-cloud certificate identity"}
	}
	return principal{parts[0], profile(c) == "op"}, nil
}

type endpoint func(http.ResponseWriter, *http.Request) (any, int, error)
type Route struct {
	Method    string `json:"method"`
	Path      string `json:"path"`
	Access    string `json:"access"`
	Service   string `json:"service,omitempty"`
	Operation string `json:"operation,omitempty"`
}
type App struct {
	Config       Config
	Store        *Store
	mux          *http.ServeMux
	Routes       []Route
	Remote       *Remote
	TLS          *tls.Config
	background   sync.WaitGroup
	relayHandler http.Handler
	broker       *brokerState
}

func (a *App) WaitBackground() { a.background.Wait() }

func New(cfg Config, s *Store, tc *tls.Config) (*App, error) {
	if _, ok := Systems[cfg.Role]; !ok {
		return nil, errors.New("unknown role")
	}
	a := &App{Config: cfg, Store: s, TLS: tc, mux: http.NewServeMux(), broker: &brokerState{}}
	a.Remote = NewRemote(cfg, tc)
	switch cfg.Role {
	case "Blacklist":
		a.blacklistRoutes()
	case "Configuration":
		a.configurationRoutes()
	case "DataManager":
		a.dataRoutes()
	case "TimeManager":
		a.timeRoutes()
	case "EventHandler":
		a.eventRoutes()
	case "DeviceQoSEvaluator":
		a.qosRoutes()
	case "AIGym":
		a.aiRoutes()
	case "PlantDescriptionEngine":
		a.plantRoutes()
	case "Choreographer":
		a.choreographyRoutes()
	case "CertificateAuthority":
		a.caRoutes()
	case "SysMonitor":
		a.monitorRoutes()
	case "Onboarding":
		a.onboardingRoutes()
	case "TranslationManager":
		a.translationRoutes()
	case "TestTranslation":
		a.testTranslationRoutes()
	case "Gatekeeper", "GateTunnel":
		a.federationRoutes()
	}
	a.commonRoutes()
	return a, nil
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	a.mux.ServeHTTP(w, r)
}
func (a *App) route(method, path, access string, fn endpoint) {
	a.Routes = append(a.Routes, Route{Method: method, Path: path, Access: access})
	a.mux.HandleFunc(method+" "+path, func(w http.ResponseWriter, r *http.Request) {
		p, e := certificateIdentity(r, a.Config.CloudSuffix)
		if access == "enrollment" {
			p, e = a.enrollmentIdentity(r)
		}
		if e == nil && access != "certificate" && access != "enrollment" && access != "bridge" {
			h := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer IDENTITY-TOKEN//")
			if h == r.Header.Get("Authorization") || h == "" || len(h) > 4096 || strings.ContainsAny(h, "/?#\r\n") {
				e = &APIError{401, "Identity token required"}
			} else {
				var v Document
				e = a.Remote.Call(r.Context(), "authentication", "GET", "/authentication/identity/verify/"+h, nil, &v)
				if e == nil {
					if !flag(v, "verified") || str(v, "systemName") != p.Name {
						e = &APIError{401, "Token and certificate identity mismatch"}
					} else {
						p.Sysop = flag(v, "sysop")
					}
				}
			}
		}
		// also certificate-only operations (e.g. monitor/echo), by the verified client certificate name, as the Java filter
		if e == nil && access != "enrollment" && !p.Sysop {
			e = a.checkBlacklist(r.Context(), p.Name)
		}
		if e == nil && access == "management" && !p.Sysop {
			allowed := false
			for _, name := range a.Config.ManagementWhitelist {
				if name == p.Name {
					allowed = true
				}
			}
			if !allowed && a.Config.ManagementPolicy == "authorization" && p.Name != "" {
				// per-operation management authorization by ConsumerAuthorization (MGMT policies)
				def, op := a.contractOf(Route{Method: method, Path: path, Access: access})
				var granted bool
				if ce := a.Remote.Call(r.Context(), "authorization", "POST", "/consumerauthorization/authorization/verify", Document{"provider": a.Config.Name, "consumer": p.Name, "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": def, "scope": op}, &granted); ce != nil {
					e = ce
				}
				allowed = granted
			}
			if e == nil && !allowed {
				e = forbidden()
			}
		}
		if e == nil {
			r = r.WithContext(context.WithValue(r.Context(), principalKey{}, p))
			var v any
			var status int
			v, status, e = fn(w, r)
			if e == nil {
				a.recordLog("INFO", method+" "+path+" by "+p.Name)
				if status == 0 {
					return
				}
				respond(w, status, v)
				return
			}
		}
		status := 500
		message := "Internal server error"
		var ae *APIError
		if errors.As(e, &ae) {
			status, message = ae.Status, ae.Message
		}
		a.recordLog("WARN", method+" "+path+" rejected")
		respond(w, status, Document{"errorMessage": message, "errorCode": status, "origin": method + " " + path, "timestamp": now()})
	})
}
func (a *App) base() string {
	return Systems[a.Config.Role].Base
}
func (a *App) commonRoutes() {
	a.route("GET", a.base()+"/monitor/echo", "certificate", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return textResponse("Got it!"), 200, nil
	})
	a.route("GET", a.base()+"/general/mgmt/get-config", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		values := Document{"implementation": "Go", "version": "5.2.2", "role": a.Config.Role, "system.name": a.Config.Name, "server.ssl.enabled": "true", "server.ssl.client-auth": "need", "persistence": "atomic-json"}
		keys := r.URL.Query()["keys"]
		if len(keys) > 0 {
			selected := Document{}
			for _, entry := range keys {
				for _, key := range strings.Split(entry, ",") {
					if v, ok := values[key]; ok {
						selected[key] = v
					}
				}
			}
			values = selected
		}
		return Document{"map": values}, 200, nil
	})
	a.route("POST", a.base()+"/general/mgmt/logs", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		e = a.Store.View(func(d database) error {
			for _, row := range d["logs"] {
				if !timeRange(str(row, "entryDate"), str(req, "from"), str(req, "to")) {
					continue
				}
				if s := str(req, "severity"); s != "" && s != str(row, "severity") {
					continue
				}
				if s := str(req, "logger"); s != "" && s != str(row, "logger") {
					continue
				}
				rows = append(rows, row)
			}
			return nil
		})
		if e != nil {
			return nil, 0, e
		}
		if obj(req, "pagination") == nil {
			req["pagination"] = Document{"sortField": "entryDate", "direction": "DESC"}
		}
		out, e := page(rows, req, "entries")
		return out, 200, e
	})
}

func (a *App) recordLog(severity, message string) {
	_ = a.Store.Update(func(d database) error {
		logs := bucket(d, "logs")
		id := uuid()
		logs[id] = Document{"logId": id, "entryDate": now(), "logger": a.Config.Role, "severity": severity, "message": message, "exception": nil}
		if len(logs) > 1000 {
			oldest, key := "", ""
			for k, v := range logs {
				if key == "" || str(v, "entryDate") < oldest {
					oldest, key = str(v, "entryDate"), k
				}
			}
			delete(logs, key)
		}
		return nil
	})
}

// checkBlacklist refuses (403) a requester that Blacklist lists (security finding J12, the Go counterpart of the Java
// BlacklistFilter). Blacklist itself, blacklistExclude and the system's own calls (its ah-probe healthcheck) are not
// checked; while Blacklist cannot be reached the request is refused, unless blacklistOptional is set.
func (a *App) checkBlacklist(ctx context.Context, name string) error {
	if a.Config.BlacklistURL == "" || name == "Blacklist" || a.Config.Name == "Blacklist" || name == a.Config.Name {
		return nil
	}
	for _, excluded := range a.Config.BlacklistExclude {
		if excluded == name {
			return nil
		}
	}
	var blacklisted bool
	if e := a.Remote.Call(ctx, "blacklist", "GET", "/blacklist/check/"+url.PathEscape(name), nil, &blacklisted); e != nil {
		if a.Config.BlacklistOptional {
			return nil
		}
		return &APIError{403, "Blacklist system is not available, the system might be blacklisted"}
	}
	if blacklisted {
		return &APIError{403, name + " system is blacklisted"}
	}
	return nil
}
