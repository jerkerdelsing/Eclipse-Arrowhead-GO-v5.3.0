package cloud

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestTunnelControlContractPersistsRoundTrip(t *testing.T) {
	a := testApp(t, "gatetunnel")
	f := fixtureFederation(t, a)
	call := func(path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		data, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", path, bytes.NewReader(data))
		w := httptest.NewRecorder()
		f.TunnelHTTP(w, r, "Gatekeeper")
		return w
	}
	w := call("/gatetunnel/connect_provider", map[string]any{"consumer": "Consumer", "provider": "Provider", "consumerCloud": "TestCloud|Company", "providerCloud": "GoCloud|Company", "relay": map[string]any{"address": "amqp-broker"}, "serviceDefinition": "temperature"})
	if w.Code != 201 {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if created["state"] != "PROVIDER_READY" || created["serverPort"] != float64(8000) {
		t.Fatalf("create DTO %v", created)
	}
	w = call("/gateway/connect_consumer", map[string]any{"queueId": created["queueId"]})
	if w.Code != 201 {
		t.Fatalf("connect: %d %s", w.Code, w.Body.String())
	}
	var active map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &active)
	if active["state"] != "ACTIVE" || active["sessionId"] != created["sessionId"] {
		t.Fatal("connect DTO mismatch")
	}
	reloaded, err := OpenStore(a.Store.path)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Data.Resources[mapString(created["sessionId"])].Payload["state"] != "ACTIVE" {
		t.Fatal("control session not persisted")
	}
	w = call("/gatetunnel/close_sessions", []int{8000})
	if w.Code != 200 || w.Body.String() != "[]\n" {
		t.Fatalf("close: %d %s", w.Code, w.Body.String())
	}
	w = call("/gatetunnel/connect_consumer", map[string]any{"queueId": created["queueId"]})
	if w.Code != 404 {
		t.Fatal("closed control session reactivated")
	}
}
func TestTunnelControlRefusesOrdinaryCaller(t *testing.T) {
	a := testApp(t, "gatetunnel")
	f := fixtureFederation(t, a)
	r := httptest.NewRequest("POST", "/gatetunnel/connect_provider", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	f.TunnelHTTP(w, r, "OrdinaryClient")
	if w.Code != 403 {
		t.Fatalf("ordinary client got %d", w.Code)
	}
}
