package main

import "testing"

func TestParseExtraInterfacesDefaultsAndValidation(t *testing.T) {
	out, err := parseExtraInterfaces(`[{"serviceDefinition":"generalManagement","templateName":"generic_https","address":"registry-bootstrap-proxy","port":8501}]`)
	if err != nil || len(out) != 1 {
		t.Fatalf("parse: %v %v", out, err)
	}
	if out[0].Protocol != "https" || out[0].Policy != "NONE" {
		t.Fatalf("defaults not applied: %+v", out[0])
	}
	if out, err := parseExtraInterfaces("[]"); err != nil || len(out) != 0 {
		t.Fatalf("empty list: %v %v", out, err)
	}
	if _, err := parseExtraInterfaces(`not json`); err == nil {
		t.Fatal("invalid JSON accepted")
	}
	if _, err := parseExtraInterfaces(`[{"serviceDefinition":"systemDiscovery"}]`); err == nil {
		t.Fatal("missing address and port accepted")
	}
}

func TestSelfRequestAddsConfiguredIngress(t *testing.T) {
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	props["domain.name"] = "serviceregistry"
	props["authentication.policy"] = "declared"
	props["service.registry.extra.interfaces"] = `[{"serviceDefinition":"systemDiscovery","templateName":"generic_https","protocol":"https","policy":"CERT_AUTH","address":"authentication-registry-mtls","port":8443}]`
	cfg, err := NewConfig(props)
	if err != nil {
		t.Fatal(err)
	}
	rg := &Registry{cfg: cfg}
	for _, sv := range selfServices() {
		req, err := rg.selfRequest(sv)
		if err != nil {
			t.Fatal(err)
		}
		if sv.def != "systemDiscovery" {
			if len(req.Interfaces) != 1 {
				t.Fatalf("%s: unexpected extra interface", sv.def)
			}
			continue
		}
		if len(req.Interfaces) != 2 {
			t.Fatalf("systemDiscovery: %d interfaces", len(req.Interfaces))
		}
		extra := req.Interfaces[1]
		if extra.TemplateName != "generic_https" || extra.Policy != "CERT_AUTH" || extra.Protocol != "https" {
			t.Fatalf("extra interface: %+v", extra)
		}
		if extra.Properties["basePath"] != req.Interfaces[0].Properties["basePath"] {
			t.Fatalf("base path not copied: %v", extra.Properties["basePath"])
		}
		addrs, _ := extra.Properties["accessAddresses"].([]any)
		if len(addrs) != 1 || addrs[0] != "authentication-registry-mtls" {
			t.Fatalf("address: %v", extra.Properties["accessAddresses"])
		}
	}
}
