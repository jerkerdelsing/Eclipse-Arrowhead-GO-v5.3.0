// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

// peer creates another system of the fixture's cloud (same PKI and Authentication) served over mutual TLS.
func (f *fixture) peer(t *testing.T, role string) (*App, *httptest.Server) {
	t.Helper()
	s, e := OpenStore("")
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Role: role, Name: role, CloudSuffix: suffix, AuthenticationURL: f.auth.URL, PasswordFile: f.app.Config.PasswordFile, AuthorizationPolicy: "identity-only", TimeZone: "UTC", DefaultSubscription: "none", RetentionDays: 30}
	app, e := New(cfg, s, f.p.tls(f.p.cert(t, role, "sy")))
	if e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewUnstartedServer(app)
	srv.TLS = f.p.tls(f.p.cert(t, role, "sy"))
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return app, srv
}

func hostPort(t *testing.T, raw string) (string, int) {
	u, _ := url.Parse(raw)
	host, port, _ := net.SplitHostPort(u.Host)
	n, _ := strconv.Atoi(port)
	return host, n
}

// registered returns the service instance an app would register (its Services plus TestTranslation metadata).
func registered(app *App, srv *httptest.Server, def string) Document {
	host, port := hostPort(nil, srv.URL)
	for _, s := range app.Services() {
		if s.Definition != def {
			continue
		}
		props := Document{"accessAddresses": []any{host}, "accessPort": float64(port), "basePath": s.BasePath, "operations": map[string]any{}}
		for name, op := range s.Operations {
			props["operations"].(map[string]any)[name] = map[string]any(op)
		}
		if def == "dataHistorian" {
			props["dataModels"] = map[string]any{"get-data": map[string]any{"output": "senml"}}
		}
		md := testTranslationMetadata(def)
		var metadata any = map[string]any{}
		if md != nil {
			b, _ := json.Marshal(md)
			_ = json.Unmarshal(b, &metadata)
		}
		return Document{"instanceId": app.Config.Name + "|" + def + "|1.0.0", "provider": map[string]any{"name": app.Config.Name}, "serviceDefinition": map[string]any{"name": def}, "version": "1.0.0", "metadata": metadata, "interfaces": []any{map[string]any{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": props}}}
	}
	return nil
}

func TestTranslationBridgeEndToEnd(t *testing.T) {
	f := newFixture(t, "TranslationManager")
	tm := f.app
	tmSrv := httptest.NewUnstartedServer(tm)
	tmSrv.TLS = f.p.tls(f.p.cert(t, "TranslationManager", "sy"))
	tmSrv.StartTLS()
	t.Cleanup(tmSrv.Close)
	tt, ttSrv := f.peer(t, "TestTranslation")
	dm, dmSrv := f.peer(t, "DataManager")
	ttHost, ttPort := hostPort(t, ttSrv.URL)
	tt.Config.AdvertiseAddress, tt.Config.AdvertisePort = ttHost, ttPort
	tt.Config.Upstreams = map[string]string{"TranslationManager": tmSrv.URL}
	tt.Remote = NewRemote(tt.Config, tt.TLS)
	// SenML data in the DataManager
	_ = dm.Store.Update(func(d database) error {
		bucket(d, "senml")["1"] = Document{"id": "1", "system": "Sensor", "service": "temp", "signal": "Sensor/temp", "epoch": 1.7e9, "record": Document{"bn": "Sensor/", "n": "temp", "v": 21.5, "u": "Cel", "bt": 1.7e9}, "receivedAt": now()}
		return nil
	})
	target := registered(dm, dmSrv, "dataHistorian")
	bridgeMgmt := registered(tt, ttSrv, "interfaceBridgeManagement")
	dmt := registered(tt, ttSrv, "dataModelTranslation")
	registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		entries := []any{}
		switch list(in, "serviceDefinitionNames")[0] {
		case "interfaceBridgeManagement":
			entries = append(entries, bridgeMgmt)
		case "dataModelTranslation":
			entries = append(entries, dmt)
		}
		respond(w, 200, Document{"entries": entries, "count": len(entries)})
	}))
	registry.TLS = f.p.tls(f.p.cert(t, "ServiceRegistry", "sy"))
	registry.StartTLS()
	t.Cleanup(registry.Close)
	tm.Config.ServiceRegistryURL = registry.URL
	tm.Remote = NewRemote(tm.Config, tm.TLS)

	// discovery: the consumer wants get-data in simpleJson; the DataManager offers senml
	s, v := f.request(t, "POST", "/translation/bridge/discovery", "Consumer", Document{"candidates": []any{target}, "operation": "get-data", "interfaceTemplateNames": []string{"generic_https"}, "outputDataModelId": "simpleJson"})
	out := objectResult(t, s, 200, v)
	bridgeID := str(out, "bridgeId")
	if bridgeID == "" || len(list(out, "candidates")) != 1 {
		t.Fatal("no bridge discovered", out)
	}
	// negotiation by another consumer is refused; by the creator it initializes the bridge
	if s, _ = f.request(t, "POST", "/translation/bridge/negotiation", "Other", Document{"bridgeId": bridgeID, "target": target}); s != 403 {
		t.Fatal("foreign negotiation accepted", s)
	}
	s, v = f.request(t, "POST", "/translation/bridge/negotiation", "Consumer", Document{"bridgeId": bridgeID, "target": target})
	out = objectResult(t, s, 200, v)
	intf := obj(out, "bridgeInterface")
	if str(intf, "policy") != bridgePolicy {
		t.Fatal(out)
	}
	props := obj(intf, "properties")
	// only the bridge's interface translator may report about it
	if s, _ = f.request(t, "POST", "/translation/event/report", "Consumer", Document{"bridgeId": bridgeID, "timestamp": now(), "state": "USED"}); s != 403 {
		t.Fatal("report by a non-translator accepted", s)
	}
	// the consumer calls the bridge: SenML is translated to simpleJson
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: func() *tls.Config {
		c := f.p.tls(f.p.cert(t, "Consumer", "sy"))
		c.ClientAuth = tls.NoClientCert
		return c
	}()}}
	call := func(token string) (int, []byte) {
		u := ttSrv.URL + str(props, "basePath") + "/data-historian/systems/Sensor/services/temp/data"
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Authorization", token)
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	if code, _ := call("Bearer TRANSLATION-BRIDGE-TOKEN//wrong"); code != 401 {
		t.Fatal("bridge call without its token accepted", code)
	}
	code, body := call(bridgeTokenPrefix + bridgeID)
	var records []Document
	if code != 200 || json.Unmarshal(body, &records) != nil || len(records) != 1 || records[0]["name"] != "Sensor/temp" || records[0]["value"] != 21.5 || records[0]["unit"] != "Cel" {
		t.Fatal("translated result", code, string(body))
	}
	// the translator reported the use
	deadline := time.Now().Add(3 * time.Second)
	for {
		row, _ := tm.row("bridges", bridgeID)
		if str(row, "status") == "USED" && number(row, "usageReportCount", 0) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no USED report", row)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// abort: TranslationManager marks it and tells the translator; the bridge no longer forwards
	s, v = f.request(t, "DELETE", "/translation/bridge/abort/"+bridgeID, "Consumer", nil)
	if s != 200 || v != true {
		t.Fatal("abort", s, v)
	}
	if code, _ := call(bridgeTokenPrefix + bridgeID); code != 404 {
		t.Fatal("aborted bridge still forwards", code)
	}
	if row, _ := tm.row("bridges", bridgeID); str(row, "status") != "ABORTED" {
		t.Fatal(row)
	}
}

func TestTranslationDataModels(t *testing.T) {
	senml, e := translateDataModel("simpleJson", "senml", []byte(`[{"name":"a","value":1,"unit":"m","time":"2026-10-24T10:00:00Z"},{"name":"b","boolValue":true}]`))
	if e != nil || string(senml) != `[{"n":"a","t":1792836000,"u":"m","v":1},{"n":"b","vb":true}]` {
		t.Fatal(string(senml), e)
	}
	back, e := translateDataModel("senml", "simpleJson", senml)
	if e != nil || string(back) != `[{"name":"a","time":"2026-10-24T10:00:00Z","unit":"m","value":1},{"boolValue":true,"name":"b"}]` {
		t.Fatal(string(back), e)
	}
	if _, e := translateDataModel("senml", "other", senml); e == nil {
		t.Fatal("unsupported pair accepted")
	}
	if !pathMatches("/systems/{s}/data", "/systems/A/data") || pathMatches("/systems/{s}/data", "/systems/../data") || pathMatches("/a/{b}", "/a/b/c") {
		t.Fatal("path matching")
	}
	for from, to := range map[string]string{"INITIALIZED": "USED", "USED": "USED", "DISCOVERED": "PENDING"} {
		if !bridgeTransition(from, to) {
			t.Fatal(from, to)
		}
	}
	if bridgeTransition("ABORTED", "USED") || bridgeTransition("PENDING", "USED") {
		t.Fatal("invalid transition allowed")
	}
}

func TestTranslationFactoryFallback(t *testing.T) {
	f := newFixture(t, "TranslationManager")
	initialized := make(chan Document, 1)
	factory := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch r.URL.Path {
		case "/factory/check":
			respond(w, 200, str(in, "fromModelId") == "senml" && str(in, "toModelId") == "simpleJson")
		case "/factory/initialize-translator":
			initialized <- in
			respond(w, 200, Document{"dataModelTranslatorName": "MadeTranslator", "interfaceProperties": Document{"accessAddresses": []string{"127.0.0.1"}, "accessPort": 1, "basePath": "/made"}})
		}
	}))
	factory.TLS = f.p.tls(f.p.cert(t, "Factory", "sy"))
	factory.StartTLS()
	t.Cleanup(factory.Close)
	host, port := hostPort(t, factory.URL)
	factoryInstance := Document{"provider": map[string]any{"name": "Factory"}, "interfaces": []any{map[string]any{"templateName": "generic_https", "policy": "CERT_AUTH", "properties": map[string]any{"accessAddresses": []any{host}, "accessPort": float64(port), "basePath": "/factory", "operations": map[string]any{"check": map[string]any{"method": "POST", "path": "/check"}}}}}}
	registry := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		entries := []any{}
		if list(in, "serviceDefinitionNames")[0] == "dataModelTranslatorFactoryControl" {
			entries = append(entries, factoryInstance)
		}
		respond(w, 200, Document{"entries": entries})
	}))
	registry.TLS = f.p.tls(f.p.cert(t, "ServiceRegistry", "sy"))
	registry.StartTLS()
	t.Cleanup(registry.Close)
	f.app.Config.ServiceRegistryURL = registry.URL
	f.app.Remote = NewRemote(f.app.Config, f.app.TLS)
	treq := &translationRequest{operation: "get", outputModel: "simpleJson", flags: map[string]bool{}}
	models, e := f.app.addDataModelTranslators(context.Background(), treq, []Document{{"interfaceTranslator": "IT", "targetOutputDataModelId": "senml", "outputDataModelIdRequirement": "simpleJson"}})
	if e != nil || len(models) != 1 || str(models[0], "outputDataModelTranslator") != "Factory" || !flag(models[0], "outputDataModelTranslatorFactory") {
		t.Fatal("factory not selected", models, e)
	}
	// unsupported direction: the model is dropped
	models, _ = f.app.addDataModelTranslators(context.Background(), treq, []Document{{"interfaceTranslator": "IT", "targetOutputDataModelId": "xml", "outputDataModelIdRequirement": "simpleJson"}})
	if len(models) != 0 {
		t.Fatal("model without translator kept", models)
	}
}

func TestTestTranslationMQTTTargets(t *testing.T) {
	f := newFixture(t, "TestTranslation")
	a := f.app
	a.Config.MQTTURL = "ssl://mqtt-broker:8883"
	md, _ := json.Marshal(testTranslationMetadataFor("interfaceBridgeManagement", true))
	if string(md) != `{"interfaceBridge":{"from":["generic_https","generic_mqtts"],"to":"generic_https"}}` {
		t.Fatal(string(md))
	}
	mqttIntf := func(host string, port int, ops ...string) map[string]any {
		o := []any{}
		for _, op := range ops {
			o = append(o, op)
		}
		return map[string]any{"templateName": "generic_mqtts", "policy": "CERT_AUTH", "properties": map[string]any{"accessAddresses": []any{host}, "accessPort": float64(port), "baseTopic": "arrowhead/blacklist/", "operations": o}}
	}
	s, v := f.request(t, "POST", "/testtranslation/interface-bridge/check-targets", "TranslationManager", Document{"targetOperation": "check", "targets": []any{
		map[string]any{"instanceId": "A", "interfaces": []any{mqttIntf("mqtt-broker", 8883, "check", "lookup")}},
		map[string]any{"instanceId": "B", "interfaces": []any{mqttIntf("other-broker", 8883, "check")}},
		map[string]any{"instanceId": "C", "interfaces": []any{mqttIntf("mqtt-broker", 8883, "lookup")}},
	}})
	out := objectResult(t, s, 200, v)
	if targets := list(out, "targets"); len(targets) != 1 || str(targets[0].(map[string]any), "instanceId") != "A" {
		t.Fatal(out)
	}
	// without a broker connection no MQTT bridge is initialized
	s, _ = f.request(t, "POST", "/testtranslation/interface-bridge/initialize-bridge", "TranslationManager", Document{"bridgeId": "b1", "operation": "check", "inputInterface": "generic_https", "targetInterface": "generic_mqtts", "targetInterfaceProperties": mqttIntf("mqtt-broker", 8883, "check")["properties"]})
	if s != 400 {
		t.Fatal("MQTT bridge initialized without a broker connection", s)
	}
	a.broker.bridgeMQTT.connected.Store(true)
	s, v = f.request(t, "POST", "/testtranslation/interface-bridge/initialize-bridge", "TranslationManager", Document{"bridgeId": "b2", "operation": "check", "inputInterface": "generic_https", "targetInterface": "generic_mqtts", "targetInterfaceProperties": mqttIntf("mqtt-broker", 8883, "check")["properties"]})
	out = objectResult(t, s, 200, v)
	if ops := obj(obj(out, "properties"), "operations"); str(obj(ops, "check"), "method") != "POST" || str(obj(ops, "check"), "path") != "/check" {
		t.Fatal(out)
	}
	s, v = f.request(t, "POST", "/testtranslation/interface-bridge/initialize-bridge", "TranslationManager", Document{"bridgeId": "b3", "operation": "get-data", "inputInterface": "generic_mqtts", "targetInterface": "generic_https", "targetInterfaceProperties": map[string]any{"accessAddresses": []any{"datamanager"}, "accessPort": float64(8461), "basePath": "/datamanager", "operations": map[string]any{"get-data": map[string]any{"method": "GET", "path": "/data-historian/systems/{systemName}/data"}}}})
	out = objectResult(t, s, 200, v)
	if str(out, "templateName") != "generic_mqtts" || str(obj(out, "properties"), "baseTopic") != "arrowhead/testtranslation/bridge/b3/" {
		t.Fatal(out)
	}
	if s, _ = f.request(t, "POST", "/testtranslation/interface-bridge/initialize-bridge", "TranslationManager", Document{"bridgeId": "b4", "operation": "check", "inputInterface": "generic_mqtts", "targetInterface": "generic_mqtts", "targetInterfaceProperties": mqttIntf("mqtt-broker", 8883, "check")["properties"]}); s != 400 {
		t.Fatal("MQTT to MQTT bridge accepted", s)
	}
}
