// SPDX-License-Identifier: EPL-2.0
package core

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// Endpoint principles: a configured listening port and a predefined default (see port.go).
const portTestRole = "EventHandler"

func writePortConfig(t *testing.T, listen string) string {
	t.Helper()
	doc := map[string]any{"name": "PortTest", "cloudSuffix": "GoCloud.Company.arrowhead.eu", "state": filepath.Join(t.TempDir(), "state.json")}
	if listen != "" {
		doc["listen"] = listen
	}
	b, e := json.Marshal(doc)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if e = os.WriteFile(path, b, 0o600); e != nil {
		t.Fatal(e)
	}
	return path
}

func TestListeningPortDefault(t *testing.T) {
	t.Setenv(PortEnv, "")
	cfg, e := LoadConfig(writePortConfig(t, ""), portTestRole)
	if e != nil {
		t.Fatal(e)
	}
	want := net.JoinHostPort(DefaultListenHost, strconv.Itoa(DefaultPorts[portTestRole]))
	if DefaultPorts[portTestRole] == 0 || cfg.Listen != want {
		t.Fatalf("default listen = %q, want %q", cfg.Listen, want)
	}
}

func TestListeningPortConfigured(t *testing.T) {
	t.Setenv(PortEnv, "")
	cfg, e := LoadConfig(writePortConfig(t, "0.0.0.0:9000"), portTestRole)
	if e != nil || cfg.Listen != "0.0.0.0:9000" {
		t.Fatalf("configured listen = %q, %v", cfg.Listen, e)
	}
}

func TestListeningPortOverrides(t *testing.T) {
	t.Setenv(PortEnv, "9100")
	cfg, e := LoadConfig(writePortConfig(t, "0.0.0.0:9000"), portTestRole)
	if e != nil || cfg.Listen != "0.0.0.0:9100" {
		t.Fatalf("SERVER_PORT override = %q, %v", cfg.Listen, e)
	}
	if e = ApplyPort(&cfg, 9200); e != nil || cfg.Listen != "0.0.0.0:9200" {
		t.Fatalf("-server.port override = %q, %v", cfg.Listen, e)
	}
	if e = ApplyPort(&cfg, 0); e != nil || cfg.Listen != "0.0.0.0:9200" {
		t.Fatalf("absent flag changed listen to %q, %v", cfg.Listen, e)
	}
	if e = ApplyPort(&cfg, 70000); e == nil {
		t.Fatal("out-of-range flag port accepted")
	}
	for _, bad := range []string{"abc", "0", "65536", "-1"} {
		t.Setenv(PortEnv, bad)
		if _, e := LoadConfig(writePortConfig(t, ""), portTestRole); e == nil {
			t.Fatalf("SERVER_PORT=%q accepted", bad)
		}
	}
	t.Setenv(PortEnv, "")
	if _, e := LoadConfig(writePortConfig(t, "no-port"), portTestRole); e == nil {
		t.Fatal("listen without port accepted")
	}
}

func TestListeningPortDefaultsUnique(t *testing.T) {
	seen := map[int]string{}
	for role, port := range DefaultPorts {
		if other, ok := seen[port]; ok {
			t.Fatalf("roles %s and %s share default port %d", role, other, port)
		}
		seen[port] = role
	}
}

// The resolved default (and an override) is a real address that accepts connections.
func TestListeningPortAcceptsConnections(t *testing.T) {
	t.Setenv(PortEnv, "")
	cfg, e := LoadConfig(writePortConfig(t, ""), portTestRole)
	if e != nil {
		t.Fatal(e)
	}
	accept := func(addr string) {
		ln, e := net.Listen("tcp", addr)
		if errors.Is(e, syscall.EADDRINUSE) {
			t.Logf("%s is in use on this host (another system is running); bind check skipped", addr)
			return
		}
		if e != nil {
			t.Fatal(e)
		}
		defer ln.Close()
		go func() {
			if c, e := ln.Accept(); e == nil {
				c.Close()
			}
		}()
		c, e := net.Dial("tcp", addr)
		if e != nil {
			t.Fatal(e)
		}
		c.Close()
	}
	accept(cfg.Listen)
	free, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	t.Setenv(PortEnv, strconv.Itoa(port))
	cfg, e = LoadConfig(writePortConfig(t, ""), portTestRole)
	if e != nil || cfg.Listen != net.JoinHostPort(DefaultListenHost, strconv.Itoa(port)) {
		t.Fatalf("override listen = %q, %v", cfg.Listen, e)
	}
	accept(cfg.Listen)
}
