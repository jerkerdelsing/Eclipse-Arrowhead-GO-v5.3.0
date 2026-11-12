// SPDX-License-Identifier: EPL-2.0
package cloud

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// providerStub answers like the Go ServiceRegistry, DataManager, SysMonitor and PlantDescriptionEngine of this
// distribution, including their refusals: an unfiltered service-instances query is a 400, unknown paths are 404.
func providerStub(t *testing.T, seen *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.Method+" "+r.URL.RequestURI())
		body, _ := io.ReadAll(r.Body)
		reply := func(v any) { w.Header().Set("Content-Type", "application/json"); _ = json.NewEncoder(w).Encode(v) }
		switch r.Method + " " + r.URL.Path {
		case "POST /serviceregistry/mgmt/systems/query":
			reply(map[string]any{"entries": []any{map[string]any{"name": "DataManager"}, map[string]any{"name": "SysMonitor"}, map[string]any{"name": "DataManager"}}, "count": 3})
		case "POST /serviceregistry/mgmt/service-instances/query":
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			names := anySlice(req["providerNames"])
			if len(names) == 0 && len(anySlice(req["instanceIds"])) == 0 && len(anySlice(req["serviceDefinitionNames"])) == 0 {
				http.Error(w, `{"errorMessage":"One of the following filters must be used"}`, http.StatusBadRequest)
				return
			}
			if len(names) != 2 || names[0] != "DataManager" || names[1] != "SysMonitor" {
				t.Errorf("providerNames = %v", names)
			}
			reply(map[string]any{"entries": []any{map[string]any{"instanceId": "DataManager|dataHistorian|1.0.0", "provider": map[string]any{"name": "DataManager"}, "serviceDefinition": map[string]any{"name": "dataHistorian"}, "interfaces": []any{map[string]any{"templateName": "generic_https"}}}}, "count": 1})
		case "POST /serviceorchestration/orchestration/mgmt/simple-store/query":
			reply(map[string]any{"entries": []any{}, "count": 0})
		case "GET /datamanager/data-historian/systems":
			reply(map[string]any{"systems": []any{"RandomDataProducer"}})
		case "GET /datamanager/data-historian/systems/RandomDataProducer/services":
			reply(map[string]any{"services": []any{"randomData"}})
		case "GET /datamanager/data-historian/systems/RandomDataProducer/services/randomData/data":
			if r.URL.Query().Get("count") == "" {
				t.Error("data query without count")
			}
			reply([]any{map[string]any{"bn": "producer/", "bt": 1700000010.0, "n": "temperature", "u": "Cel", "v": 21.5}, map[string]any{"bn": "producer/", "bt": 1700000000.0, "n": "temperature", "u": "Cel", "v": 20.0}})
		case "GET /sysmonitor/history/systems":
			reply(map[string]any{"systems": []any{map[string]any{"systemName": "ServiceRegistry", "observationCount": 2, "lastObservationTime": "2026-11-11T20:00:00Z"}, map[string]any{"systemName": "Quiet", "observationCount": 0}}, "retentionDays": 7})
		case "GET /sysmonitor/history/systems/ServiceRegistry/latest":
			reply(map[string]any{"systemName": "ServiceRegistry", "latest": map[string]any{"echo": map[string]any{"observationType": "echo", "sourceTime": "2026-11-11T20:00:00Z", "value": map[string]any{"status": "alive"}, "quality": "good"}}})
		case "GET /sysmonitor/history/systems/ServiceRegistry/observations":
			reply(map[string]any{"systemName": "ServiceRegistry", "count": 1, "observations": []any{map[string]any{"observationType": "echo", "sourceTime": "2026-11-11T20:00:00Z", "value": map[string]any{"status": "alive"}}}})
		case "GET /plantdescriptionengine/mgmt/plant-descriptions":
			reply(map[string]any{"entries": []any{map[string]any{"id": "p1", "plantDescription": "Plant"}}, "count": 1})
		default:
			http.NotFound(w, r)
		}
	}))
}

func providerViewsApp(t *testing.T, server *httptest.Server) *App {
	a := testApp(t, "localcloudmanager")
	a.Config.RegistryURL = server.URL
	for _, k := range []string{"DATAMANAGER_URL", "SYSMONITOR_URL", "PLANT_DESCRIPTION_ENGINE_URL", "SIMPLE_ORCHESTRATION_URL"} {
		t.Setenv(k, server.URL)
	}
	return a
}

func TestServiceInstanceQueryNamesRegisteredProviders(t *testing.T) {
	var seen []string
	server := providerStub(t, &seen)
	defer server.Close()
	a := providerViewsApp(t, server)
	services, err := a.registryQuery("service-instances")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries(services)) != 1 {
		t.Fatalf("services = %v", services)
	}
	overview, err := a.managerOverview()
	if err != nil {
		t.Fatal(err)
	}
	if errs := object(overview["errors"]); errs["arrowhead"] != nil {
		t.Fatalf("overview registry error: %v", errs["arrowhead"])
	}
	if _, err := a.managerConsumers(); err != nil {
		t.Fatal(err)
	}
	rules, err := a.managerRules()
	if err != nil || rules["count"] != 0 {
		t.Fatal(rules, err)
	}
}

func TestServiceInstanceQueryWithoutSystemsSkipsRegistry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/service-instances/query") {
			t.Error("unfiltered service-instances query sent")
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"entries": []any{}, "count": 0})
	}))
	defer server.Close()
	a := testApp(t, "localcloudmanager")
	a.Config.RegistryURL = server.URL
	services, err := a.registryQuery("service-instances")
	if err != nil || len(entries(services)) != 0 {
		t.Fatal(services, err)
	}
}

func TestDataViewReadsHistorianPerSystemAndService(t *testing.T) {
	var seen []string
	server := providerStub(t, &seen)
	defer server.Close()
	a := providerViewsApp(t, server)
	payload, err := a.managerData(httptest.NewRequest("GET", "/api/datamanager?limit=10", nil))
	if err != nil {
		t.Fatal(err)
	}
	if payload["count"] != 2 || len(anySlice(payload["errors"])) != 0 {
		t.Fatalf("payload = %v", payload)
	}
	newest := object(anySlice(payload["entries"])[0])
	if newest["name"] != "producer/temperature" || newest["time"] != 1700000010.0 || newest["system"] != "RandomDataProducer" || newest["unit"] != "Cel" {
		t.Fatalf("newest = %v", newest)
	}
	series := anySlice(payload["series"])
	if len(series) != 1 || len(anySlice(object(series[0])["points"])) != 2 {
		t.Fatalf("series = %v", series)
	}
}

func TestSysMonitorViewReadsHistoryService(t *testing.T) {
	var seen []string
	server := providerStub(t, &seen)
	defer server.Close()
	a := providerViewsApp(t, server)
	payload, err := a.managerSysMonitor(httptest.NewRequest("GET", "/api/sysmonitor?system=ServiceRegistry", nil))
	if err != nil {
		t.Fatal(err)
	}
	if payload["storedObservations"] != 2 || payload["selectedSystem"] != "ServiceRegistry" || len(anySlice(payload["observations"])) != 1 {
		t.Fatalf("payload = %v", payload)
	}
	systems := anySlice(payload["systems"])
	if len(systems) != 2 || object(object(object(systems[1])["latest"])["echo"])["quality"] != "good" {
		t.Fatalf("systems = %v", systems)
	}
}

func TestPlantDescriptionViewUsesManagementPath(t *testing.T) {
	var seen []string
	server := providerStub(t, &seen)
	defer server.Close()
	a := providerViewsApp(t, server)
	payload, err := a.managerPlantDescriptions()
	if err != nil {
		t.Fatal(err)
	}
	if len(anySlice(payload["entries"])) != 1 || len(anySlice(payload["services"])) != 1 {
		t.Fatalf("payload = %v", payload)
	}
}

func TestConsumerAndIntercloudViewsNameTheConfiguredCloud(t *testing.T) {
	var seen []string
	server := providerStub(t, &seen)
	defer server.Close()
	a := providerViewsApp(t, server)
	a.Config.Cloud = "GoCloud"
	consumers, err := a.managerConsumers()
	if err != nil {
		t.Fatal(err)
	}
	if consumers["localCloud"] != "GoCloud" || object(anySlice(consumers["rows"])[0])["providerCloud"] != "GoCloud" {
		t.Fatalf("consumers = %v", consumers)
	}
	if a.managerIntercloud()["localCloud"] != "GoCloud" {
		t.Fatal("intercloud view names another cloud")
	}
}
