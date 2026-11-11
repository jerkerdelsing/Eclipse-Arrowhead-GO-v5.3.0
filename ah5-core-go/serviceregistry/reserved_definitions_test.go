package main

import (
	"os"
	"path/filepath"
	"testing"
)

// J9: core and support service definitions only for their owning systems; application definitions stay open.
func TestReservedServiceDefinitions(t *testing.T) {
	e := newEnv(t, nil)
	status, body := e.do("POST", "/serviceregistry/system-discovery/register", "AuditClient", map[string]any{"version": "1.0.0", "addresses": []string{"localhost"}})
	expect(t, status, 201, body)
	for _, def := range []string{"certificateSigning", "serviceDiscovery", "dataHistorian", "serviceOrchestrationPlantManagement"} {
		status, body = e.do("POST", "/serviceregistry/service-discovery/register", "AuditClient", map[string]any{"serviceDefinitionName": def, "version": "1.0.0", "interfaces": []any{httpIface("localhost", 9999)}})
		expect(t, status, 403, body)
	}
	status, body = e.do("POST", "/serviceregistry/service-discovery/register", "AuditClient", map[string]any{"serviceDefinitionName": "auditProbe", "version": "1.0.0", "interfaces": []any{httpIface("localhost", 9999)}})
	expect(t, status, 201, body)
}

func TestReservedDefinitionOverrides(t *testing.T) {
	r, err := parseReservedDefs("randomNumberProducer:RandomDataProducer, time:TimeManager|ClockBridge, aiGym:")
	if err != nil {
		t.Fatal(err)
	}
	if len(r["randomNumberProducer"]) != 1 || len(r["time"]) != 2 {
		t.Fatalf("overrides not applied: %v %v", r["randomNumberProducer"], r["time"])
	}
	if _, ok := r["aiGym"]; ok {
		t.Fatal("empty owner list must lift the reservation")
	}
	if _, err = parseReservedDefs("noColon"); err == nil {
		t.Fatal("malformed entry accepted")
	}
}

// J7: the identity password and Authentication's secret key can come from files instead of the environment.
func TestSecretFiles(t *testing.T) {
	dir := t.TempDir()
	pw, key := filepath.Join(dir, "pw"), filepath.Join(dir, "key")
	_ = os.WriteFile(pw, []byte("s3cretPassword\n"), 0o600)
	_ = os.WriteFile(key, []byte("authKey123"), 0o600)
	t.Setenv("AUTHENTICATOR_PASSWORD_FILE", pw)
	t.Setenv("AUTHENTICATOR_SECRET_KEY_FILE", key)
	t.Setenv("AUTHENTICATION_POLICY", "outsourced")
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthenticatorPassword != "s3cretPassword" || cfg.AuthenticatorSecretKeys["Authentication"] != "authKey123" {
		t.Fatalf("secrets not read from files: %q %v", cfg.AuthenticatorPassword, cfg.AuthenticatorSecretKeys)
	}
	_ = os.WriteFile(pw, []byte("bad'quote"), 0o600)
	if _, err = LoadConfig(""); err == nil {
		t.Fatal("secret with a quote accepted")
	}
}
