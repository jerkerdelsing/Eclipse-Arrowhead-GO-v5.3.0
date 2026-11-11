package cloud

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

type fixtureMessage struct {
	topic    string
	payload  []byte
	retained bool
}

func testEndpoint(t *testing.T, endpoint string) (string, int) {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return u.Hostname(), port
}
func (m fixtureMessage) Duplicate() bool   { return false }
func (m fixtureMessage) Qos() byte         { return 1 }
func (m fixtureMessage) Retained() bool    { return m.retained }
func (m fixtureMessage) Topic() string     { return m.topic }
func (m fixtureMessage) MessageID() uint16 { return 1 }
func (m fixtureMessage) Payload() []byte   { return m.payload }
func (m fixtureMessage) Ack()              {}

func fixtureFederation(t *testing.T, a *App) *Federation {
	t.Helper()
	return &Federation{app: a, pending: map[string]relayWaiter{}, responses: map[string]relayCache{}, inflight: map[string]bool{}, providers: map[string]*tunnelSession{}, consumers: map[string]*tunnelSession{}, slots: make(chan struct{}, 64), stop: make(chan struct{})}
}
func TestRelayRepliesBoundToExpectedPeerAndInbox(t *testing.T) {
	a := testApp(t, "gatetunnel")
	a.Config.Cloud = "GoCloud"
	a.Config.Organization = "Company"
	t.Setenv("NEIGHBOR_CLOUDS", "TestCloud,ThirdCloud")
	f := fixtureFederation(t, a)
	waiter := relayWaiter{peer: "GateTunnel.TestCloud.Company.arrowhead.eu", ch: make(chan map[string]any, 1)}
	f.pending["correlation"] = waiter
	data, _ := json.Marshal(map[string]any{"id": "msg", "type": "reply", "correlationId": "correlation", "status": 200})
	for _, topic := range []string{"arrowhead/relay/GoCloud/gatetunnel/in/GateTunnel.ThirdCloud.Company.arrowhead.eu/msg", "arrowhead/relay/OtherCloud/gatetunnel/in/GateTunnel.TestCloud.Company.arrowhead.eu/msg", "arrowhead/relay/GoCloud/gatekeeper/in/GateTunnel.TestCloud.Company.arrowhead.eu/msg", "arrowhead/relay/GoCloud/gatetunnel/in/Gatekeeper.TestCloud.Company.arrowhead.eu/msg", "arrowhead/relay/GoCloud/gatetunnel/in/GateTunnel.TestCloud.Company.arrowhead.eu/different-id"} {
		f.receive(nil, fixtureMessage{topic: topic, payload: data})
		select {
		case <-waiter.ch:
			t.Fatalf("untrusted reply accepted: %s", topic)
		default:
		}
	}
	topic := "arrowhead/relay/GoCloud/gatetunnel/in/GateTunnel.TestCloud.Company.arrowhead.eu/msg"
	f.receive(nil, fixtureMessage{topic: topic, payload: data, retained: true})
	select {
	case <-waiter.ch:
		t.Fatal("retained reply accepted")
	default:
	}
	f.receive(nil, fixtureMessage{topic: topic, payload: data})
	select {
	case reply := <-waiter.ch:
		if reply["senderCN"] != waiter.peer {
			t.Fatal("peer identity missing")
		}
	default:
		t.Fatal("valid reply rejected")
	}
}

func TestTunnelProviderForwardsOnlyNegotiatedOperations(t *testing.T) {
	p := makePKI(t)
	auth := tlsTestServer(t, p, "Authentication.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, Session{Token: "own-token"}) }))
	a := secureTestApp(t, p, "gatetunnel", auth.URL)
	t.Setenv("NEIGHBOR_CLOUDS", "TestCloud")
	f := fixtureFederation(t, a)
	calls := 0
	provider := tlsTestServer(t, p, "DataManager.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "PUT" || r.URL.Path != "/historian/data" || r.Header.Get("Authorization") != "Bearer IDENTITY-TOKEN//own-token" || r.Header.Get("X-Arrowhead-Remote-Consumer") != "Producer|TestCloud|Company" {
			t.Error("provider forwarding contract mismatch")
		}
		jsonOut(w, 201, map[string]any{"stored": true})
	}))
	host, port := testEndpoint(t, provider.URL)
	s := &tunnelSession{ID: "session", Consumer: "Producer", ConsumerCloud: "TestCloud|Company", Provider: "DataManager", Definition: "dataHistorian", Peer: "GateTunnel.TestCloud.Company.arrowhead.eu", Created: time.Now(), LastUsed: time.Now(), Target: map[string]any{"address": host, "port": port, "basePath": "/historian", "operations": map[string]any{"put-data": map[string]any{"method": "PUT", "path": "/data"}}}}
	f.providers[s.ID] = s
	request := map[string]any{"type": "http-request", "sessionId": s.ID, "method": "PUT", "path": "/historian/data", "body": base64.StdEncoding.EncodeToString([]byte(`{"value":1}`)), "contentType": "application/json"}
	reply, err := f.handleTunnel(s.Peer, request)
	if err != nil || reply["status"] != 201 {
		t.Fatalf("forward: %v %v", reply, err)
	}
	request["method"] = "DELETE"
	reply, err = f.handleTunnel(s.Peer, request)
	if err != nil || reply["status"] != 403 {
		t.Fatalf("method scope: %v %v", reply, err)
	}
	if _, err = f.handleTunnel("GateTunnel.ThirdCloud.Company.arrowhead.eu", request); err == nil {
		t.Fatal("wrong peer accepted")
	}
	s.Created = time.Now().Add(-13 * time.Hour)
	if _, err = f.handleTunnel(s.Peer, request); err == nil {
		t.Fatal("expired session accepted")
	}
	if calls != 1 {
		t.Fatalf("provider executed %d calls; want 1", calls)
	}
}

func TestFederationCannotStartInInsecureMode(t *testing.T) {
	a := testApp(t, "gatekeeper")
	t.Setenv("FEDERATION_PROFILE", "legacy-mtls")
	if _, err := newFederation(a); err == nil {
		t.Fatal("insecure federation accepted")
	}
}

func TestTunnelConsumerMustOwnSession(t *testing.T) {
	p := makePKI(t)
	auth := tlsTestServer(t, p, "Authentication.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/authentication/identity/login" {
			jsonOut(w, 200, Session{Token: "own"})
		} else {
			jsonOut(w, 200, map[string]any{"verified": true, "systemName": "OtherConsumer"})
		}
	}))
	a := secureTestApp(t, p, "gatetunnel", auth.URL)
	f := fixtureFederation(t, a)
	s := &tunnelSession{ID: "session", Consumer: "Producer", Created: time.Now(), LastUsed: time.Now()}
	f.consumers[s.ID] = s
	w := httptest.NewRecorder()
	f.forward(s, w, certificateRequest(t, p, "OtherConsumer", "sy"))
	if w.Code != 401 {
		t.Fatalf("wrong consumer got %d", w.Code)
	}
}
