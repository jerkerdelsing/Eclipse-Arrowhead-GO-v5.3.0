// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"encoding/json"
	"testing"
)

func mqttCall(t *testing.T, a *App, topic, token, responseTopic string, params map[string]string, payload any) (string, *MQTTResponse) {
	t.Helper()
	req := Document{"traceId": "trace-1", "authentication": "IDENTITY-TOKEN//" + token, "responseTopic": responseTopic, "params": params}
	if payload != nil {
		req["payload"] = payload
	}
	b, _ := json.Marshal(req)
	return a.HandleMQTT(context.Background(), topic, b)
}

func TestMQTTRequestRunsTheHTTPSOperation(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "Sysop", true)
	seed(t, a, "SystemA", false)
	sysop, token := loginLocal(t, a, "Sysop"), loginLocal(t, a, "SystemA")
	topic, resp := mqttCall(t, a, "arrowhead/authentication/identity/identity-verify", token, "arrowhead/response/SystemA/1", nil, token)
	if topic != "arrowhead/response/SystemA/1" || resp.Status != 200 || resp.TraceID != "trace-1" || resp.Receiver != "SystemA" {
		t.Fatalf("%s %+v", topic, resp)
	}
	if p, _ := resp.Payload.(map[string]any); p["verified"] != true || p["systemName"] != "SystemA" {
		t.Fatal(resp.Payload)
	}
	if _, resp = mqttCall(t, a, "arrowhead/authentication/monitor/echo", token, "arrowhead/response/SystemA/2", nil, nil); resp.Status != 200 || resp.Payload != "Got it!" {
		t.Fatalf("%+v", resp)
	}
	// management: refused for SystemA, a list payload is the query parameter of a removal
	if _, resp = mqttCall(t, a, "arrowhead/authentication/identity/management/identity-mgmt-query", token, "arrowhead/response/SystemA/3", nil, Document{}); resp.Status != 403 {
		t.Fatalf("%+v", resp)
	}
	if p, _ := resp.Payload.(Document); p["exceptionType"] != "FORBIDDEN" || p["origin"] != "arrowhead/authentication/identity/management/identity-mgmt-query" {
		t.Fatal(resp.Payload)
	}
	if _, resp = mqttCall(t, a, "arrowhead/authentication/identity/management/identity-mgmt-remove", sysop, "arrowhead/response/Sysop/1", nil, []string{"SystemA"}); resp.Status != 200 {
		t.Fatalf("%+v", resp)
	}
	if v, _ := a.verifyIdentity(token); flag(v, "verified") {
		t.Fatal("identity removal over MQTT did not apply")
	}
}

func TestMQTTResponseBinding(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "SystemA", false)
	token := loginLocal(t, a, "SystemA")
	for _, rt := range []string{"arrowhead/response/SystemB/1", "arrowhead/response/SystemA", "arrowhead/response/SystemA/#", "other/topic"} {
		if topic, _ := mqttCall(t, a, "arrowhead/authentication/monitor/echo", token, rt, nil, nil); topic != "" {
			t.Fatalf("answered on %s", topic)
		}
	}
	if topic, _ := mqttCall(t, a, "arrowhead/authentication/monitor/echo", "not-a-token", "arrowhead/response/SystemA/1", nil, nil); topic != "" {
		t.Fatal("answered an invalid token")
	}
	// credential operations need the client certificate
	if _, resp := mqttCall(t, a, "arrowhead/authentication/identity/identity-login", token, "arrowhead/response/SystemA/1", nil, Document{"systemName": "SystemA", "credentials": Document{"password": "test-password"}}); resp.Status != 401 {
		t.Fatalf("%+v", resp)
	}
	if _, resp := mqttCall(t, a, "arrowhead/authentication/identity/no-such-op", token, "arrowhead/response/SystemA/1", nil, nil); resp.Status != 404 {
		t.Fatalf("%+v", resp)
	}
}

func TestMQTTTopicsAndInterface(t *testing.T) {
	a := fixture(t, "serviceorchestration-dynamic")
	a.Config.MQTTURL = "ssl://mqtt-broker:8883"
	ops := a.mqttOperations()
	for topic, want := range map[string]mqttOperation{
		"arrowhead/serviceorchestration/orchestration/pull":                     {"POST", "/serviceorchestration/orchestration/pull"},
		"arrowhead/serviceorchestration/orchestration/unsubscribe":              {"DELETE", "/serviceorchestration/orchestration/unsubscribe/{id}"},
		"arrowhead/serviceorchestration/orchestration/management/lock/remove":   {"DELETE", "/serviceorchestration/orchestration/mgmt/lock/remove/{owner}"},
		"arrowhead/serviceorchestration/general/management/get-config":          {"GET", "/serviceorchestration/general/mgmt/get-config"},
		"arrowhead/serviceorchestration/orchestration/management/history/query": {"POST", "/serviceorchestration/orchestration/mgmt/history/query"},
	} {
		if ops[topic] != want {
			t.Fatalf("%s: %+v", topic, ops[topic])
		}
	}
	a.Config.MQTTTopicPrefix = "arrowhead/serviceorchestration-dynamic/"
	if a.MQTTBaseTopic("serviceOrchestration") != "arrowhead/serviceorchestration-dynamic/orchestration/" {
		t.Fatal(a.MQTTBaseTopic("serviceOrchestration"))
	}
	for _, s := range a.Services() {
		if s.Definition != "serviceOrchestration" {
			continue
		}
		props := obj(a.mqttInterface(s), "properties")
		if props["accessPort"] != 8883 || props["baseTopic"] != "arrowhead/serviceorchestration-dynamic/orchestration/" || len(props["operations"].([]string)) != 3 {
			t.Fatal(props)
		}
	}
	r, e := mqttHTTPRequest(context.Background(), mqttOperation{"DELETE", "/serviceorchestration/orchestration/mgmt/lock/remove/{owner}"}, MQTTRequest{Params: map[string]string{"owner": "A B"}, Payload: json.RawMessage(`["i1","i2"]`)})
	if e != nil || r.URL.Path != "/serviceorchestration/orchestration/mgmt/lock/remove/A B" || r.URL.Query().Get("instanceIds") != "" && len(r.URL.Query()["instanceIds"]) != 2 {
		t.Fatal(e, r.URL)
	}
	if _, e = mqttHTTPRequest(context.Background(), mqttOperation{"DELETE", "/x/{id}"}, MQTTRequest{}); e == nil {
		t.Fatal("missing path parameter accepted")
	}
}
