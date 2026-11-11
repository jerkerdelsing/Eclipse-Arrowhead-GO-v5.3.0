package main

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMQTTAdapter(t *testing.T) {
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	props["authentication.policy"] = "declared"
	props["enable.management.filter"] = "true"
	props["service.discovery.interface.policy"] = "extendable"
	cfg, err := NewConfig(props)
	if err != nil {
		t.Fatal(err)
	}
	log := NewLogger(100)
	log.quiet = true
	st, _ := NewStore("")
	rg := NewRegistry(cfg, st, log)
	h := NewServer(cfg, rg, log, NewAuthenticator(cfg, rg, log, nil)).Handler()
	verify := func(token string) (string, bool, error) {
		if token == "bad" {
			return "", false, errAuth("invalid")
		}
		return token, token == "Sysop", nil
	}
	call := func(topic, token, responseTopic string, params map[string]string, payload any) (string, *mqttResponse) {
		b, _ := json.Marshal(map[string]any{"traceId": "t", "authentication": "IDENTITY-TOKEN//" + token, "responseTopic": responseTopic, "params": params, "payload": payload})
		return handleMQTT(context.Background(), cfg, h, verify, topic, b)
	}
	topic, resp := call("arrowhead/serviceregistry/monitor/echo", "SystemA", "arrowhead/response/SystemA/1", nil, nil)
	if topic != "arrowhead/response/SystemA/1" || resp.Status != 200 || resp.Payload != "Got it!" || resp.Receiver != "SystemA" {
		t.Fatalf("%s %+v", topic, resp)
	}
	if topic, _ = call("arrowhead/serviceregistry/monitor/echo", "SystemA", "arrowhead/response/SystemB/1", nil, nil); topic != "" {
		t.Fatal("answered on a foreign response topic")
	}
	if topic, _ = call("arrowhead/serviceregistry/monitor/echo", "bad", "arrowhead/response/SystemA/1", nil, nil); topic != "" {
		t.Fatal("answered an invalid token")
	}
	// system registration and lookup act as the token's system
	_, resp = call("arrowhead/serviceregistry/system-discovery/register", "SystemA", "arrowhead/response/SystemA/2", nil, map[string]any{"version": "1.0.0", "addresses": []string{"10.0.0.1"}})
	if resp.Status != 201 {
		t.Fatalf("%+v", resp)
	}
	_, resp = call("arrowhead/serviceregistry/system-discovery/lookup", "SystemA", "arrowhead/response/SystemA/3", map[string]string{"verbose": "false"}, map[string]any{"systemNames": []string{"SystemA"}})
	if p, _ := resp.Payload.(map[string]any); resp.Status != 200 || p["count"] != float64(1) {
		t.Fatalf("%+v", resp)
	}
	// management: refused for SystemA, removal list payload for Sysop
	if _, resp = call("arrowhead/serviceregistry/management/system-remove", "SystemA", "arrowhead/response/SystemA/4", nil, []string{"SystemA"}); resp.Status != 403 {
		t.Fatalf("%+v", resp)
	}
	if _, resp = call("arrowhead/serviceregistry/management/system-remove", "Sysop", "arrowhead/response/Sysop/1", nil, []string{"SystemA"}); resp.Status != 200 {
		t.Fatalf("%+v", resp)
	}
	_, resp = call("arrowhead/serviceregistry/system-discovery/lookup", "SystemA", "arrowhead/response/SystemA/5", nil, map[string]any{"systemNames": []string{"SystemA"}})
	if p, _ := resp.Payload.(map[string]any); p["count"] != float64(0) {
		t.Fatalf("%+v", resp)
	}
	if _, resp = call("arrowhead/serviceregistry/service-discovery/revoke", "SystemA", "arrowhead/response/SystemA/6", nil, nil); resp.Status != 400 {
		t.Fatalf("missing instanceId: %+v", resp)
	}
}

func TestMQTTRegistrationInterface(t *testing.T) {
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	props["mqtt.api.enabled"] = "true"
	props["mqtt.broker.address"] = "mqtt-broker"
	if _, err := NewConfig(props); err == nil {
		t.Fatal("MQTT API accepted without TLS and outsourced authentication")
	}
	props["server.ssl.enabled"], props["authentication.policy"] = "true", "outsourced"
	cfg, err := NewConfig(props)
	if err != nil {
		t.Fatal(err)
	}
	rg := &Registry{cfg: cfg}
	for _, sv := range selfServices() {
		mi := rg.mqttInterface(sv)
		p := mi["properties"].(map[string]any)
		if p["baseTopic"] == "" || p["accessPort"] != 8883 || len(p["operations"].([]any)) != len(sv.ops) {
			t.Fatal(sv.def, p)
		}
		if sv.def == "serviceDiscovery" && p["baseTopic"] != "arrowhead/serviceregistry/service-discovery/" {
			t.Fatal(p)
		}
	}
}

func TestBlacklistIsNotCheckedForItself(t *testing.T) {
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	props["authentication.policy"] = "declared"
	props["enable.blacklist.filter"], props["force.blacklist.filter"] = "true", "true"
	cfg, err := NewConfig(props)
	if err != nil {
		t.Fatal(err)
	}
	log := NewLogger(10)
	log.quiet = true
	st, _ := NewStore("")
	rg := NewRegistry(cfg, st, log)
	a := NewAuthenticator(cfg, rg, log, nil)
	if err := a.checkBlacklist("Blacklist"); err != nil {
		t.Fatal("Blacklist checked against itself:", err)
	}
	if err := a.checkBlacklist("SystemA"); err == nil {
		t.Fatal("forced check without a Blacklist passed")
	}
}
