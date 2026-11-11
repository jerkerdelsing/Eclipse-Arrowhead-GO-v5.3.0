package cloud

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplicitForeignOrganizationBinding(t *testing.T) {
	peers, e := parsePeerOrganizations("RustDev=Lab", "GoCloud", "Company")
	if e != nil {
		t.Fatal(e)
	}
	t.Setenv("NEIGHBOR_CLOUDS", "TestCloud,RustDev")
	f := &Federation{app: &App{Config: Config{Cloud: "GoCloud", Organization: "Company", Role: "gatetunnel"}, Store: &Store{}}, peerOrganizations: peers}
	for _, cn := range []string{"GateTunnel.TestCloud.Company.arrowhead.eu", "GateTunnel.RustDev.Lab.arrowhead.eu"} {
		if !f.trustedPeer(cn) {
			t.Fatalf("expected configured peer %s", cn)
		}
	}
	for _, cn := range []string{"GateTunnel.RustDev.Company.arrowhead.eu", "GateTunnel.TestCloud.Lab.arrowhead.eu", "Gatekeeper.RustDev.Lab.arrowhead.eu", "GateTunnel.Unknown.Lab.arrowhead.eu"} {
		if f.trustedPeer(cn) {
			t.Fatalf("unexpected trusted peer %s", cn)
		}
	}
	if f.validTarget("RustDev|Company") || !f.validTarget("RustDev|Lab") {
		t.Fatal("target organization is not bound")
	}
	if peerCloudIdentity("GateTunnel.RustDev.Lab.arrowhead.eu") != "RustDev|Lab" {
		t.Fatal("peer cloud binding")
	}
}
func TestInvalidPeerOrganizations(t *testing.T) {
	for _, raw := range []string{"RustDev=Lab,RustDev=Company", "RustDev=", "=Lab", "RustDev=Lab,", "../Rust=Lab", "GoCloud=Lab"} {
		if _, e := parsePeerOrganizations(raw, "GoCloud", "Company"); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

// SOS-7 (2026-11-10): neighbours of another organisation are reachable only when listed in FEDERATION_FOREIGN_TARGETS.
func TestForeignTargetsPolicy(t *testing.T) {
	peers, _ := parsePeerOrganizations("RustDev=Lab", "GoCloud", "Company")
	for _, raw := range []string{"RustDev", "RustDev|Company", "RustDev|Other", "GoCloud|Lab", "|Lab", "TestCloud|Company", "Unknown|Lab"} {
		if _, e := parseForeignTargets(raw, "GoCloud", "Company", peers); e == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	app := &App{Config: Config{Cloud: "GoCloud", Organization: "Company"}, Store: &Store{}}
	none, _ := parseForeignTargets("", "GoCloud", "Company", peers)
	f := &Federation{app: app, peerOrganizations: peers, foreignTargets: none}
	if !f.targetAllowed("TestCloud") || f.targetAllowed("RustDev") {
		t.Fatal("default: own organisation only")
	}
	listed, e := parseForeignTargets(" RustDev|Lab ", "GoCloud", "Company", peers)
	if e != nil {
		t.Fatal(e)
	}
	f.foreignTargets = listed
	if !f.targetAllowed("RustDev") || !f.targetAllowed("TestCloud") {
		t.Fatal("listed foreign neighbour refused")
	}
}

// SOS-7: the Gatekeeper's consumer-side operations refuse a foreign neighbour that is not listed, before any relay
// request (the federation has no relay client here: a request would fail the test).
func TestForeignTargetsAreRefusedBeforeTheRelay(t *testing.T) {
	t.Setenv("NEIGHBOR_CLOUDS", "RustDev")
	peers, _ := parsePeerOrganizations("RustDev=Lab", "GoCloud", "Company")
	f := &Federation{app: &App{Config: Config{Cloud: "GoCloud", Organization: "Company", Role: "gatekeeper"}, Store: &Store{}}, peerOrganizations: peers, foreignTargets: map[string]bool{}}
	call := func(path, body string) (int, map[string]any) {
		w := httptest.NewRecorder()
		f.GatekeeperHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)), "DynamicServiceOrchestration")
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := call("/gatekeeper/init_gsd", `{"serviceRequirement":{"serviceDefinition":"dataHistorian"},"consumerSystem":"RandomDataProducer"}`); code != 200 || out["queriedClouds"] != float64(0) {
		t.Fatalf("default discovery: %d %v", code, out)
	}
	if code, out := call("/gatekeeper/init_gsd", `{"serviceRequirement":{"serviceDefinition":"dataHistorian"},"consumerSystem":"RandomDataProducer","targetClouds":["RustDev"]}`); code != 200 || fmt.Sprint(out["refusedClouds"]) != "[RustDev|Lab]" {
		t.Fatalf("named foreign cloud: %d %v", code, out)
	}
	if code, _ := call("/gatekeeper/init_icn", `{"targetCloud":"RustDev","providerName":"DataManager","serviceDefinition":"dataHistorian","consumerSystem":"RandomDataProducer"}`); code != 403 {
		t.Fatalf("negotiation with a foreign cloud: %d", code)
	}
}
