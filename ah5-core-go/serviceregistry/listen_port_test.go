// SPDX-License-Identifier: EPL-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Endpoint principles: a configured listening port (server.port / SERVER_PORT / --server.port) and a predefined
// default (8443).
func TestListeningPortDefaultAndOverride(t *testing.T) {
	dir := t.TempDir()
	pw, key := filepath.Join(dir, "pw"), filepath.Join(dir, "key")
	_ = os.WriteFile(pw, []byte("s3cretPassword\n"), 0o600)
	_ = os.WriteFile(key, []byte("authKey123"), 0o600)
	t.Setenv("AUTHENTICATOR_PASSWORD_FILE", pw)
	t.Setenv("AUTHENTICATOR_SECRET_KEY_FILE", key)
	t.Setenv("AUTHENTICATION_POLICY", "outsourced")
	t.Setenv("SERVER_PORT", "") // registers restoration of the caller's value
	os.Unsetenv("SERVER_PORT")
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "absent.properties"))
	if err != nil || cfg.ServerPort != 8443 {
		t.Fatalf("default server.port = %v, %v; want 8443", cfg, err)
	}
	file := filepath.Join(t.TempDir(), "application.properties")
	if err = os.WriteFile(file, []byte("server.port=9443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err = LoadConfig(file); err != nil || cfg.ServerPort != 9443 {
		t.Fatalf("configured server.port = %v, %v; want 9443", cfg, err)
	}
	t.Setenv("SERVER_PORT", "9543")
	if cfg, err = LoadConfig(file); err != nil || cfg.ServerPort != 9543 {
		t.Fatalf("SERVER_PORT override = %v, %v; want 9543", cfg, err)
	}
	for _, bad := range []string{"0", "65536", "abc"} {
		t.Setenv("SERVER_PORT", bad)
		if _, err = LoadConfig(file); err == nil {
			t.Fatalf("SERVER_PORT=%q accepted", bad)
		}
	}
}
