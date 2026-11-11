// SPDX-License-Identifier: EPL-2.0
package cloud

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Role, SystemName, Cloud, Organization, RegistryURL string
	Secure                                             bool
}
type Resource struct {
	ID, Kind, Owner, CreatedAt, UpdatedAt string
	Payload                               map[string]any
}
type State struct{ Resources map[string]Resource }
type Store struct {
	mu        sync.RWMutex
	Data      State
	path      string
	committed []byte
}
type App struct {
	Config    Config
	Store     *Store
	tlsConfig *tls.Config
	Call      func(string, string, any, map[string]string) ([]byte, error)
	Identity  func(*http.Request) (string, error)
	Token     func() (string, error)
	ClientFor func(string) *http.Client
}

func New(c Config, path string, t *tls.Config, call func(string, string, any, map[string]string) ([]byte, error), identity func(*http.Request) (string, error), token func() (string, error), clientFor func(string) *http.Client) (*Federation, error) {
	s := &Store{Data: State{Resources: map[string]Resource{}}, path: path}
	if path != "" {
		b, e := os.ReadFile(path)
		if e == nil {
			if e = json.Unmarshal(b, &s.Data); e != nil {
				return nil, e
			}
			s.committed = b
		} else if !os.IsNotExist(e) {
			return nil, e
		}
	}
	a := &App{Config: c, Store: s, tlsConfig: t, Call: call, Identity: identity, Token: token, ClientFor: clientFor}
	return newFederation(a)
}
func (s *Store) SaveLocked() error {
	b, e := json.Marshal(s.Data)
	if e != nil {
		return e
	}
	if s.path == "" {
		s.committed = b
		return nil
	}
	if e = os.MkdirAll(filepath.Dir(s.path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(s.path), ".relay-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, s.path)
	}
	if e != nil {
		if len(s.committed) > 0 {
			_ = json.Unmarshal(s.committed, &s.Data)
		}
		return e
	}
	s.committed = b
	return nil
}
func (a *App) call(method, endpoint string, payload any, headers map[string]string) ([]byte, error) {
	if a.Call == nil {
		return nil, errors.New("No service client")
	}
	return a.Call(method, endpoint, payload, headers)
}
func (a *App) ownToken() (string, error) {
	if a.Token == nil {
		return "", errors.New("No identity client")
	}
	return a.Token()
}
func (a *App) requester(r *http.Request) (string, error) {
	if a.Identity == nil {
		return "", errors.New("No identity verifier")
	}
	return a.Identity(r)
}
func (a *App) commonName(name string) string {
	return name + "." + a.Config.Cloud + "." + a.Config.Organization + ".arrowhead.eu"
}
func loadTLS(cert, key, ca string) (*tls.Config, error) {
	pair, e := tls.LoadX509KeyPair(cert, key)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	b, e := os.ReadFile(ca)
	if e != nil {
		return nil, e
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("Empty relay trust store")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}
func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
func csv(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func randomID() string {
	b := make([]byte, 18)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}
func mapString(v any) string { s, _ := v.(string); return s }
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	}
	return 0, false
}
func stringSlice(v any) []string {
	out := []string{}
	for _, x := range list(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
func list(v any) []any { a, _ := v.([]any); return a }
func sortedKeys[V any](m map[string]V) []string {
	keys := []string{}
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func listResponse(v []any) map[string]any { return map[string]any{"entries": v, "count": len(v)} }
func decode(r *http.Request, v any) error {
	b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil {
		return e
	}
	if len(b) > 1<<20 {
		return errors.New("Body too large")
	}
	return json.Unmarshal(b, v)
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func apiError(w http.ResponseWriter, status int, msg, origin string) {
	jsonOut(w, status, map[string]any{"errorMessage": msg, "errorCode": status, "origin": origin})
}
