// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestNativeServiceRegistryIntegration(t *testing.T) {
	binary, e := filepath.Abs(filepath.Join("..", "..", "bin", "serviceregistry"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(binary); os.IsNotExist(e) {
		t.Skip("run make build before this optional native-process integration test")
	}
	f := isolatedCloud(t)
	seed(t, f.auth, "Authentication", false)
	cert := f.pki.cert(t, "ServiceRegistry", "sy")
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"), filepath.Join(dir, "ca.pem")
	for path, data := range map[string][]byte{certFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), keyFile: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))}), caFile: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.pki.root.Raw})} {
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	properties := fmt.Sprintf("server.address=127.0.0.1\nserver.port=%d\ndomain.name=127.0.0.1\nserver.ssl.enabled=true\nserver.ssl.client-auth=need\nserver.ssl.cert-file=%s\nserver.ssl.key-file=%s\nserver.ssl.trust-file=%s\nauthentication.policy=certificate\nenable.management.filter=true\nmanagement.policy=sysop-only\nstandalone.mode=false\ndata.file=%s\n", port, certFile, keyFile, caFile, filepath.Join(dir, "registry.json"))
	config := filepath.Join(dir, "registry.properties")
	properties += "service.discovery.direct.access=Orchestrator\n"
	if e = os.WriteFile(config, []byte(properties), 0600); e != nil {
		t.Fatal(e)
	}
	logfile, e := os.Create(filepath.Join(dir, "registry.log"))
	if e != nil {
		t.Fatal(e)
	}
	defer logfile.Close()
	cmd := exec.Command(binary, "-config", config)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	cmd.Stdout, cmd.Stderr = logfile, logfile
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})
	base := "https://127.0.0.1:" + strconv.Itoa(port)
	client := f.clients["Provider"]
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		e = client.request(ctx, "ServiceRegistry", base, "GET", "/serviceregistry/monitor/echo", "", nil, nil)
		if e == nil {
			break
		}
		select {
		case <-ctx.Done():
			b, _ := os.ReadFile(filepath.Join(dir, "registry.log"))
			t.Fatalf("registry did not start: %v %s", e, b)
		case <-ticker.C:
		}
	}
	client.cfg.ServiceRegistryURL = base
	var row Document
	if e = client.Call(ctx, "registry", "POST", "/serviceregistry/system-discovery/register", Document{"version": "1.0.0", "addresses": []string{"127.0.0.1"}}, &row); e != nil {
		t.Fatal(e)
	}
	req := Document{"systemName": "Provider", "serviceDefinitionName": "temperature", "version": "1.0.0", "metadata": Document{"allowExclusivity": "60"}, "interfaces": []Document{{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{"127.0.0.1"}, "accessPort": 12345, "basePath": "/temperature", "operations": Document{"read": Document{"method": "GET", "path": "/"}}}}}}
	if e = client.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/register", req, &row); e != nil {
		t.Fatal(e)
	}
	f.dynamic.Config.ServiceRegistryURL = base
	f.dynamic.Remote = NewRemote(f.dynamic.Config, f.dynamic.TLS)
	f.grant(t)
	result := f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", Document{"serviceRequirement": Document{"serviceDefinition": "temperature", "operations": []string{"read"}}, "exclusivityDuration": 10})
	if len(list(result, "results")) != 1 {
		t.Fatal(result)
	}
	if str(list(result, "results")[0].(map[string]any), "exclusiveUntil") == "" {
		t.Fatal("provider-consented exclusivity not acquired")
	}
	// Requested operations are authorization scopes: a consumer granted only the read scope gets the provider when
	// it asks for read, and not for an all-scopes request.
	req["serviceDefinitionName"] = "humidity"
	if e = client.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/register", req, &row); e != nil {
		t.Fatal(e)
	}
	f.call(t, "Provider", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization/grant", Document{"targetType": "SERVICE_DEF", "target": "humidity", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []string{"Other"}}, "scopedPolicies": Document{"read": Document{"policyType": "WHITELIST", "policyList": []string{"Consumer"}}}})
	result = f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", Document{"serviceRequirement": Document{"serviceDefinition": "humidity", "operations": []string{"read"}}})
	if len(list(result, "results")) != 1 {
		t.Fatal("scoped grant not honoured", result)
	}
	result = f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", Document{"serviceRequirement": Document{"serviceDefinition": "humidity"}})
	if len(list(result, "results")) != 0 {
		t.Fatal("all-scopes request granted by a scoped policy only", result)
	}
	// Verify that all advertised services survive the real registry's template validators.
	f.auth.Config.AuthenticationURL = f.authURL
	f.auth.Config.PasswordFile = f.clients["Consumer"].cfg.PasswordFile
	f.auth.TLS = f.pki.tls(f.pki.cert(t, "Authentication", "sy"))
	for _, a := range []*App{f.auth, f.authz, f.dynamic, f.simple} {
		a.Config.ServiceRegistryURL = base
		a.Config.AdvertiseAddress = "127.0.0.1"
		a.Config.AdvertisePort = 8443
		a.Remote = NewRemote(a.Config, a.TLS)
		if e = a.Register(ctx); e != nil {
			t.Fatal(a.Config.Role, e)
		}
	}
}
