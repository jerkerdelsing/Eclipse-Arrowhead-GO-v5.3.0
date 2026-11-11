// SPDX-License-Identifier: EPL-2.0
package core

// TestTranslation (2026-10-24): a test application system for the TranslationManager. It is
//   - an interface translator (interfaceBridgeManagement, generic_https -> generic_https; check-targets,
//     initialize-bridge, abort-bridge), whose bridges forward one negotiated operation to the target and report
//     usage to the TranslationManager (translationReport), and
//   - a data model translator (dataModelTranslation; init-translation, get-translation-result, abort-translation)
//     between "simpleJson" ([{name, value|stringValue|boolValue, unit, time}]) and "senml" (RFC 8428 records).
// A bridge is offered with policy TRANSLATION_BRIDGE_TOKEN_AUTH: the consumer calls
// <basePath>/<operation path> over mutual TLS (local-cloud system certificate) with
// "Authorization: Bearer TRANSLATION-BRIDGE-TOKEN//<bridgeId>". The translator calls the target and the data model
// translators with its own identity (targets with CERT_AUTH or NONE policies).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const bridgeTokenPrefix = "Bearer TRANSLATION-BRIDGE-TOKEN//"

// testTranslationMetadata: the registry metadata TranslationManager selects translators by.
func testTranslationMetadata(def string) Document { return testTranslationMetadataFor(def, false) }

// testTranslationMetadataFor: with MQTT, interfaceBridgeManagement 1.0.0 also accepts MQTT consumers (to
// generic_https); the HTTPS -> MQTT bridges are the second instance (testTranslationMQTTTargetMetadata, 1.1.0), as
// "to" is a single template.
func testTranslationMetadataFor(def string, withMQTT bool) Document {
	switch def {
	case "interfaceBridgeManagement":
		from := []string{translationTemplateHTTPS}
		if withMQTT {
			from = append(from, translationTemplateMQTTS)
		}
		return Document{"interfaceBridge": Document{"from": from, "to": translationTemplateHTTPS}}
	case "dataModelTranslation":
		return Document{"dataModelIds": [][]string{{"simpleJson", "senml"}, {"senml", "simpleJson"}}}
	}
	return nil
}

type translationTask struct {
	status, result, mimeType string
}

type translationTasks struct {
	mu    sync.Mutex
	tasks map[string]*translationTask
}

// translateDataModel converts a payload between the supported data models.
func translateDataModel(from, to string, payload []byte) ([]byte, error) {
	var v any
	if e := json.Unmarshal(payload, &v); e != nil {
		return nil, errors.New("payload is not JSON")
	}
	records, ok := v.([]any)
	if !ok {
		records = []any{v}
	}
	out := []Document{}
	switch {
	case from == "senml" && to == "simpleJson":
		baseName, baseTime, baseUnit := "", 0.0, ""
		for _, r := range records {
			rec, ok := r.(map[string]any)
			if !ok {
				return nil, errors.New("invalid SenML record")
			}
			if s, ok := rec["bn"].(string); ok {
				baseName = s
			}
			if f, ok := rec["bt"].(float64); ok {
				baseTime = f
			}
			if s, ok := rec["bu"].(string); ok {
				baseUnit = s
			}
			item := Document{"name": baseName + str(rec, "n")}
			unit := str(rec, "u")
			if unit == "" {
				unit = baseUnit
			}
			if unit != "" {
				item["unit"] = unit
			}
			if t := baseTime + toFloat(rec["t"]); t > 0 {
				sec, frac := math.Modf(t)
				item["time"] = time.Unix(int64(sec), int64(frac*1e9)).UTC().Format(time.RFC3339Nano)
			}
			switch {
			case rec["v"] != nil:
				item["value"] = rec["v"]
			case rec["vs"] != nil:
				item["stringValue"] = rec["vs"]
			case rec["vb"] != nil:
				item["boolValue"] = rec["vb"]
			default:
				continue // base-only record
			}
			out = append(out, item)
		}
	case from == "simpleJson" && to == "senml":
		for _, r := range records {
			rec, ok := r.(map[string]any)
			if !ok || str(rec, "name") == "" {
				return nil, errors.New("invalid simpleJson record (name required)")
			}
			item := Document{"n": rec["name"]}
			if s := str(rec, "unit"); s != "" {
				item["u"] = s
			}
			if s := str(rec, "time"); s != "" {
				t, e := time.Parse(time.RFC3339Nano, s)
				if e != nil {
					return nil, errors.New("invalid simpleJson time")
				}
				item["t"] = float64(t.UnixNano()) / 1e9
			}
			switch {
			case rec["value"] != nil:
				item["v"] = rec["value"]
			case rec["stringValue"] != nil:
				item["vs"] = rec["stringValue"]
			case rec["boolValue"] != nil:
				item["vb"] = rec["boolValue"]
			default:
				return nil, errors.New("simpleJson record without value")
			}
			out = append(out, item)
		}
	default:
		return nil, fmt.Errorf("unsupported translation %s -> %s", from, to)
	}
	return json.Marshal(out)
}

func toFloat(v any) float64 {
	f, _ := v.(float64)
	return f
}

// pathMatches compares a request path with an operation path template ("{x}" matches one segment).
func pathMatches(template, path string) bool {
	tp, rp := strings.Split(strings.Trim(template, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/")
	if len(tp) != len(rp) {
		return false
	}
	for i, part := range tp {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if rp[i] == "" || rp[i] == "." || rp[i] == ".." {
				return false
			}
			continue
		}
		if part != rp[i] {
			return false
		}
	}
	return true
}

// useDataModelTranslator runs a translation at the data model translator described by the bridge descriptor.
func (a *App) useDataModelTranslator(ctx context.Context, descriptor Document, payload []byte) ([]byte, error) {
	props := obj(descriptor, "interfaceProperties")
	origin, e := httpsOrigin(props)
	if e != nil {
		return nil, e
	}
	base := str(props, "basePath")
	method, path := operationEndpoint(props, "init-translation", "POST", "/init-translation")
	var started Document
	if e = a.Remote.callLocal(ctx, origin, method, base+path, Document{"inputModelId": descriptor["fromModelId"], "outputModelId": descriptor["toModelId"], "payload": string(payload), "settings": descriptor["configurationSettings"]}, &started); e != nil {
		return nil, fmt.Errorf("data model translation not started: %w", e)
	}
	id := str(started, "translationId")
	method, path = operationEndpoint(props, "get-translation-result", "GET", "/get-translation-result")
	for i := 0; i < 50; i++ {
		var result Document
		if e = a.Remote.callLocal(ctx, origin, method, base+path+"/"+url.PathEscape(id), nil, &result); e != nil {
			return nil, e
		}
		switch str(result, "status") {
		case "DONE":
			return []byte(str(result, "result")), nil
		case "ERROR":
			return nil, errors.New("data model translation failed: " + str(result, "result"))
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, errors.New("data model translation timed out")
}

// reportBridge sends a bridge event to the TranslationManager (best effort).
func (a *App) reportBridge(bridgeID, state, message string) {
	if a.Config.Upstreams["TranslationManager"] == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	report := Document{"bridgeId": bridgeID, "timestamp": now(), "state": state}
	if message != "" {
		report["errorMessage"] = message
	}
	if e := a.consume(ctx, "TranslationManager", "POST", "/translation/event/report", report, nil); e != nil {
		a.recordLog("WARN", "Bridge report failed: "+state)
	}
}

func (a *App) testTranslationRoutes() {
	b := a.base()
	tasks := &translationTasks{tasks: map[string]*translationTask{}}
	// interface translator
	a.serviceRoute("POST", b+"/interface-bridge/check-targets", "interfaceBridgeManagement", "check-targets", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		operation := str(req, "targetOperation")
		reachable := []Document{}
		for _, target := range listOf(req, "targets") {
			good := []any{}
			for _, v := range list(target, "interfaces") {
				intf, ok := v.(map[string]any)
				props := obj(intf, "properties")
				if !ok || (str(intf, "policy") != "CERT_AUTH" && str(intf, "policy") != "NONE") {
					continue
				}
				switch str(intf, "templateName") {
				case translationTemplateHTTPS:
					if _, e := httpsOrigin(props); e != nil || obj(obj(props, "operations"), operation) == nil {
						continue
					}
				case translationTemplateMQTTS:
					if !a.mqttTargetUsable(props, operation) {
						continue
					}
				default:
					continue
				}
				good = append(good, intf)
			}
			if len(good) > 0 {
				reachable = append(reachable, Document{"instanceId": target["instanceId"], "interfaces": good})
			}
		}
		return Document{"targets": reachable}, 200, nil
	})
	a.serviceRoute("POST", b+"/interface-bridge/initialize-bridge", "interfaceBridgeManagement", "initialize-bridge", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		id, operation := str(req, "bridgeId"), str(req, "operation")
		input, targetTemplate := str(req, "inputInterface"), str(req, "targetInterface")
		props := obj(req, "targetInterfaceProperties")
		row := Document{"bridgeId": id, "status": "ACTIVE", "operation": operation, "inputTemplate": input, "targetTemplate": targetTemplate, "targetProperties": props, "inputTranslator": req["inputDataModelTranslator"], "resultTranslator": req["resultDataModelTranslator"], "createdBy": caller(r).Name, "createdAt": now(), "uses": 0}
		mqttReady := a.Config.MQTTURL != "" && a.broker.bridgeMQTT.connected.Load()
		switch {
		case id == "" || operation == "":
			return nil, 0, bad("bridgeId and operation are required")
		case input != translationTemplateHTTPS && !(input == translationTemplateMQTTS && mqttReady):
			return nil, 0, bad("Unsupported input interface: " + input)
		case targetTemplate == translationTemplateHTTPS:
			op := obj(obj(props, "operations"), operation)
			if str(op, "method") == "" || str(op, "path") == "" {
				return nil, 0, bad("Unknown target operation")
			}
			if _, e := httpsOrigin(props); e != nil {
				return nil, 0, bad(e.Error())
			}
			row["method"], row["path"] = strings.ToUpper(str(op, "method")), str(op, "path")
		case targetTemplate == translationTemplateMQTTS && input == translationTemplateHTTPS && mqttReady:
			if !a.mqttTargetUsable(props, operation) {
				return nil, 0, bad("MQTT target not reachable over this translator's broker")
			}
			// the HTTPS side of an MQTT operation: POST <basePath>/<operation>, body = payload, query = params
			row["method"], row["path"] = "POST", "/"+operation
		default:
			return nil, 0, bad("Unsupported bridge: " + input + " to " + targetTemplate)
		}
		if e = a.Store.Update(func(d database) error {
			if d["bridges"][id] != nil {
				return &APIError{409, "Bridge already exists"}
			}
			bucket(d, "bridges")[id] = row
			return nil
		}); e != nil {
			return nil, 0, e
		}
		dataModels := Document{"input": req["inputDataModelRequirement"], "output": req["resultDataModelRequirement"]}
		if input == translationTemplateMQTTS {
			host, port, _ := a.mqttBrokerAddress()
			return Document{"templateName": translationTemplateMQTTS, "protocol": "ssl", "policy": bridgePolicy, "properties": Document{
				"accessAddresses": []string{host}, "accessPort": port, "baseTopic": bridgeTopicPrefix + id + "/",
				"operations": []string{operation}, "dataModels": Document{operation: dataModels}}}, 200, nil
		}
		return Document{"templateName": translationTemplateHTTPS, "protocol": "https", "policy": bridgePolicy, "properties": Document{
			"accessAddresses": []string{a.Config.AdvertiseAddress}, "accessPort": a.Config.AdvertisePort, "basePath": b + "/bridge/" + id,
			"operations": Document{operation: Document{"method": row["method"], "path": row["path"]}},
			"dataModels": Document{operation: dataModels}}}, 200, nil
	})
	a.serviceRoute("DELETE", b+"/interface-bridge/abort-bridge/{bridgeId}", "interfaceBridgeManagement", "abort-bridge", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		e := a.Store.Update(func(d database) error {
			row := d["bridges"][r.PathValue("bridgeId")]
			if row == nil {
				return &APIError{404, "Unknown bridge"}
			}
			if str(row, "createdBy") != caller(r).Name {
				return forbidden()
			}
			row["status"], row["abortedAt"] = "ABORTED", now()
			return nil
		})
		return nil, 200, e
	})
	// data model translator
	a.serviceRoute("POST", b+"/data-model/init-translation", "dataModelTranslation", "init-translation", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		task := &translationTask{status: "DONE", mimeType: "application/json"}
		result, e := translateDataModel(str(req, "inputModelId"), str(req, "outputModelId"), []byte(str(req, "payload")))
		if e != nil {
			task.status, task.result = "ERROR", e.Error()
		} else {
			task.result = string(result)
		}
		id := uuid()
		tasks.mu.Lock()
		tasks.tasks[id] = task
		if len(tasks.tasks) > 1000 { // results are fetched at once; keep the store bounded
			for k := range tasks.tasks {
				if k != id {
					delete(tasks.tasks, k)
					break
				}
			}
		}
		tasks.mu.Unlock()
		return Document{"translationId": id}, 201, nil
	})
	a.serviceRoute("GET", b+"/data-model/get-translation-result/{translationId}", "dataModelTranslation", "get-translation-result", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		tasks.mu.Lock()
		task := tasks.tasks[r.PathValue("translationId")]
		tasks.mu.Unlock()
		if task == nil {
			return nil, 0, &APIError{404, "Unknown translation"}
		}
		return Document{"status": task.status, "result": task.result, "mimeType": task.mimeType}, 200, nil
	})
	a.serviceRoute("DELETE", b+"/data-model/abort-translation/{translationId}", "dataModelTranslation", "abort-translation", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		tasks.mu.Lock()
		delete(tasks.tasks, r.PathValue("translationId"))
		tasks.mu.Unlock()
		return nil, 200, nil
	})
	// bridge data plane (not a registered service; created per bridge)
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		a.route(method, b+"/bridge/{bridgeId}/{rest...}", "bridge", a.bridgeCall)
	}
}

// bridgeCall forwards one HTTPS consumer call over an active bridge (HTTPS input).
func (a *App) bridgeCall(w http.ResponseWriter, r *http.Request) (any, int, error) {
	id := r.PathValue("bridgeId")
	if r.Header.Get("Authorization") != bridgeTokenPrefix+id {
		return nil, 0, &APIError{401, "Translation bridge token required"}
	}
	row, e := a.row("bridges", id)
	if e != nil || str(row, "status") != "ACTIVE" || (str(row, "inputTemplate") != "" && str(row, "inputTemplate") != translationTemplateHTTPS) {
		return nil, 0, &APIError{404, "Unknown or inactive bridge"}
	}
	path := "/" + r.PathValue("rest")
	if r.Method != str(row, "method") || !pathMatches(str(row, "path"), path) {
		return nil, 0, &APIError{403, "Operation outside the negotiated bridge"}
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		return nil, 0, bad("Unreadable body")
	}
	req := bridgeRequest{method: r.Method, path: path, rawQuery: r.URL.RawQuery, body: body, contentType: r.Header.Get("Content-Type"), params: map[string]string{}}
	for k, v := range r.URL.Query() {
		req.params[k] = strings.Join(v, ",")
	}
	status, result, contentType, e := a.bridgeForward(r.Context(), id, row, req)
	if e != nil {
		return nil, 0, e
	}
	return rawResponse{status: status, body: result, contentType: contentType}, status, nil
}

// bridgeRequest is one consumer call: the HTTPS request (relative to the target base path) for HTTPS targets, the
// params and body (payload) for MQTT targets.
type bridgeRequest struct {
	method, path, rawQuery string
	params                 map[string]string
	body                   []byte
	contentType            string
}

// bridgeForward translates the input, calls the target (HTTPS or MQTT) with this system's identity, translates the
// result and records/report the use.
func (a *App) bridgeForward(ctx context.Context, id string, row Document, req bridgeRequest) (int, []byte, string, error) {
	body := req.body
	var e error
	if in := obj(row, "inputTranslator"); in != nil && len(body) > 0 {
		if body, e = a.useDataModelTranslator(ctx, in, body); e != nil {
			go a.reportBridge(id, "INTERNAL_ERROR", e.Error())
			return 0, nil, "", &APIError{502, "Input translation failed"}
		}
	}
	props := obj(row, "targetProperties")
	var status int
	var result []byte
	var contentType string
	if str(row, "targetTemplate") == translationTemplateMQTTS {
		var payload any
		if len(bytes.TrimSpace(body)) > 0 && json.Unmarshal(body, &payload) != nil {
			return 0, nil, "", bad("The body of an MQTT operation must be JSON")
		}
		var reply any
		status, reply, e = a.bridgeMQTTCall(ctx, str(props, "baseTopic")+str(row, "operation"), req.params, payload)
		if e == nil {
			if s, isString := reply.(string); !isString || s != "" {
				result, _ = json.Marshal(reply)
			}
			contentType = "application/json"
		}
	} else {
		origin, _ := httpsOrigin(props)
		target := origin + str(props, "basePath") + req.path
		if req.rawQuery != "" {
			target += "?" + req.rawQuery
		}
		status, result, contentType, e = a.forwardLocal(ctx, req.method, target, body, req.contentType)
	}
	if e != nil {
		go a.reportBridge(id, "EXTERNAL_ERROR", e.Error())
		_ = a.Store.Update(func(d database) error {
			if b := d["bridges"][id]; b != nil {
				b["status"] = "ERROR"
			}
			return nil
		})
		return 0, nil, "", &APIError{502, "Target not reachable"}
	}
	if out := obj(row, "resultTranslator"); out != nil && status/100 == 2 && len(result) > 0 {
		if result, e = a.useDataModelTranslator(ctx, out, result); e != nil {
			go a.reportBridge(id, "INTERNAL_ERROR", e.Error())
			return 0, nil, "", &APIError{502, "Result translation failed"}
		}
		contentType = "application/json"
	}
	_ = a.Store.Update(func(d database) error {
		if b := d["bridges"][id]; b != nil {
			b["uses"] = number(b, "uses", 0) + 1
			b["lastUsedAt"] = now()
		}
		return nil
	})
	go a.reportBridge(id, "USED", "")
	if contentType == "" {
		contentType = "application/json"
	}
	return status, result, contentType, nil
}

// forwardLocal sends a raw request with this system's identity to a local-cloud system (see Remote.localClient).
func (a *App) forwardLocal(ctx context.Context, method, target string, body []byte, contentType string) (int, []byte, string, error) {
	token, e := a.Remote.ownToken(ctx)
	if e != nil {
		return 0, nil, "", e
	}
	req, e := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if e != nil {
		return 0, nil, "", e
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//"+token)
	c := a.Remote.localClient()
	defer c.CloseIdleConnections()
	resp, e := c.Do(req)
	if e != nil {
		return 0, nil, "", e
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return resp.StatusCode, data, resp.Header.Get("Content-Type"), e
}

// rawResponse is written as is by the route wrapper.
type rawResponse struct {
	status      int
	body        []byte
	contentType string
}
