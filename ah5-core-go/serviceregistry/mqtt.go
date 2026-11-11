// MQTT API of the ServiceRegistry (Java mqtt.api.enabled): the Java request envelope on
// arrowhead/serviceregistry/{device-discovery,system-discovery,service-discovery,management,general/management,
// monitor}/<operation>. The adapter verifies the identity token and runs the request in process through the HTTPS
// handler chain (blacklist and management filters included); the response goes to the request's responseTopic,
// which must lie under arrowhead/response/<requester>/ (the broker lets each client read only its own prefix).
// Requests with an invalid token are not answered. Same rules as the core systems (ah5-core-go/internal/core/mqtt.go).

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type mqttPrincipalKey struct{}
type mqttPrincipal struct {
	name  string
	sysop bool
}

type mqttRequest struct {
	TraceID        string            `json:"traceId"`
	Authentication string            `json:"authentication"`
	ResponseTopic  string            `json:"responseTopic"`
	QoS            *int              `json:"qosRequirement"`
	Params         map[string]string `json:"params"`
	Payload        json.RawMessage   `json:"payload"`
}

type mqttResponse struct {
	Status   int    `json:"status"`
	TraceID  string `json:"traceId"`
	Receiver string `json:"receiver"`
	Payload  any    `json:"payload"`
}

type mqttOperation struct{ method, path string }

var mqttBaseTopics = map[string]string{
	"monitor":                   "/monitor/",
	"generalManagement":         "/general/management/",
	"serviceRegistryManagement": "/management/",
	"deviceDiscovery":           "/device-discovery/",
	"systemDiscovery":           "/system-discovery/",
	"serviceDiscovery":          "/service-discovery/",
}

// removal operations take their names as a JSON list payload; over HTTPS the list is this query parameter
var mqttListParameters = map[string]string{
	"DELETE " + basePath + "/mgmt/devices":             "names",
	"DELETE " + basePath + "/mgmt/systems":             "names",
	"DELETE " + basePath + "/mgmt/service-definitions": "names",
	"DELETE " + basePath + "/mgmt/service-instances":   "serviceInstances",
	"DELETE " + basePath + "/mgmt/interface-templates": "names",
	"GET " + basePath + "/general/mgmt/get-config":     "keys",
}

func mqttBaseTopic(cfg *Config, definition string) string {
	if t := mqttBaseTopics[definition]; t != "" {
		return cfg.MQTTTopicPrefix + t
	}
	return ""
}

func mqttOperations(cfg *Config) map[string]mqttOperation {
	out := map[string]mqttOperation{mqttBaseTopic(cfg, "monitor") + "echo": {"GET", basePath + "/monitor/echo"}}
	for _, sv := range selfServices() {
		for name, op := range sv.ops {
			out[mqttBaseTopic(cfg, sv.def)+name] = mqttOperation{op[0], sv.path + op[1]}
		}
	}
	return out
}

// mqttInterface is the generic_mqtts interface of an own service, registered besides HTTPS.
func (rg *Registry) mqttInterface(sv selfService) map[string]any {
	if !rg.cfg.MQTTEnabled {
		return nil
	}
	ops := []any{}
	names := []string{}
	for name := range sv.ops {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, n := range names {
		ops = append(ops, n)
	}
	return map[string]any{"templateName": "generic_mqtts", "protocol": "ssl", "policy": "CERT_AUTH", "properties": map[string]any{
		"accessAddresses": []any{rg.cfg.MQTTBrokerAddress}, "accessPort": rg.cfg.MQTTBrokerPort,
		"baseTopic": mqttBaseTopic(rg.cfg, sv.def), "operations": ops}}
}

var placeholderRE = regexp.MustCompile(`\{([A-Za-z]+)\}`)

func mqttHTTPRequest(ctx context.Context, op mqttOperation, req mqttRequest) (*http.Request, error) {
	params := map[string]string{}
	for k, v := range req.Params {
		params[k] = v
	}
	var payload any
	if len(bytes.TrimSpace(req.Payload)) > 0 {
		if err := json.Unmarshal(req.Payload, &payload); err != nil {
			return nil, errInvalid("Invalid payload")
		}
	}
	placeholders := placeholderRE.FindAllStringSubmatch(op.path, -1)
	path := op.path
	for _, m := range placeholders {
		value, ok := params[m[1]]
		if !ok {
			if s, isString := payload.(string); isString && len(placeholders) == 1 {
				value, ok, payload = s, true, nil
			}
		}
		if !ok || value == "" {
			return nil, errInvalid(m[1] + " is required")
		}
		delete(params, m[1])
		path = strings.Replace(path, m[0], url.PathEscape(value), 1)
	}
	query := url.Values{}
	for k, v := range params {
		query.Set(k, v)
	}
	if key := mqttListParameters[op.method+" "+op.path]; key != "" {
		if items, isList := payload.([]any); isList {
			for _, item := range items {
				s, ok := item.(string)
				if !ok {
					return nil, errInvalid(key + " must be a list of strings")
				}
				query.Add(key, s)
			}
			payload = nil
		}
	}
	var body []byte
	if payload != nil {
		body, _ = json.Marshal(payload)
	}
	target := path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	r, err := http.NewRequestWithContext(ctx, op.method, target, bytes.NewReader(body))
	if err != nil {
		return nil, errInvalid("Invalid request parameters")
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

func mqttExceptionType(status int) string {
	switch status {
	case 400:
		return "INVALID_PARAMETER"
	case 401:
		return "AUTH"
	case 403:
		return "FORBIDDEN"
	case 404:
		return "DATA_NOT_FOUND"
	case 408:
		return "TIMEOUT"
	case 423:
		return "LOCKED"
	case 503:
		return "EXTERNAL_SERVER_ERROR"
	}
	return "INTERNAL_SERVER_ERROR"
}

// handleMQTT answers one request: response topic and response, or "" when it is not answered.
func handleMQTT(ctx context.Context, cfg *Config, h http.Handler, verify func(string) (string, bool, error), topic string, message []byte) (string, *mqttResponse) {
	var req mqttRequest
	if len(message) > 1<<20 || json.Unmarshal(message, &req) != nil {
		return "", nil
	}
	token, ok := strings.CutPrefix(req.Authentication, "IDENTITY-TOKEN//")
	if !ok || token == "" {
		return "", nil
	}
	name, sysop, err := verify(token)
	if err != nil || req.ResponseTopic == "" {
		return "", nil
	}
	if !strings.HasPrefix(req.ResponseTopic, "arrowhead/response/"+name+"/") || strings.ContainsAny(req.ResponseTopic, "+#") {
		return "", nil
	}
	respond := func(status int, payload any) (string, *mqttResponse) {
		return req.ResponseTopic, &mqttResponse{Status: status, TraceID: req.TraceID, Receiver: name, Payload: payload}
	}
	failure := func(status int, message string) (string, *mqttResponse) {
		return respond(status, map[string]any{"errorMessage": message, "errorCode": status, "exceptionType": mqttExceptionType(status), "origin": topic})
	}
	op, known := mqttOperations(cfg)[topic]
	if !known {
		return failure(404, "Unknown operation")
	}
	hr, err := mqttHTTPRequest(context.WithValue(ctx, mqttPrincipalKey{}, mqttPrincipal{name, sysop}), op, req)
	if err != nil {
		return failure(400, err.Error())
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, hr)
	var payload any = ""
	if body := bytes.TrimSpace(rec.Body.Bytes()); len(body) > 0 {
		if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || json.Unmarshal(body, &payload) != nil {
			payload = string(body)
		}
	}
	if rec.Code >= 400 {
		d, _ := payload.(map[string]any)
		message, _ := d["errorMessage"].(string)
		return failure(rec.Code, message)
	}
	return respond(rec.Code, payload)
}

// startMQTT connects to the broker with the registry certificate and serves the MQTT API (at most 32 concurrent
// requests); the returned function disconnects.
func startMQTT(cfg *Config, srv *Server, auth *Authenticator, tlsCfg *tls.Config) func() {
	ctx, cancel := context.WithCancel(context.Background())
	h := srv.Handler()
	slots := make(chan struct{}, 32)
	handler := func(c mqtt.Client, m mqtt.Message) {
		select {
		case slots <- struct{}{}:
		default:
			srv.log.Warnf("mqtt", "%s: too many concurrent requests, dropped", m.Topic())
			return
		}
		go func() {
			defer func() { <-slots }()
			call, done := context.WithTimeout(ctx, 30*time.Second)
			defer done()
			topic, resp := handleMQTT(call, cfg, h, auth.verifyIdentityToken, m.Topic(), m.Payload())
			if topic == "" {
				srv.log.Warnf("mqtt", "%s: request not answered (envelope, token or response topic refused)", m.Topic())
				return
			}
			var req mqttRequest
			_ = json.Unmarshal(m.Payload(), &req)
			qos := byte(0)
			if req.QoS != nil && *req.QoS >= 0 && *req.QoS <= 2 {
				qos = byte(*req.QoS)
			}
			body, _ := json.Marshal(resp)
			if t := c.Publish(topic, qos, false, body); !t.WaitTimeout(10*time.Second) || t.Error() != nil {
				srv.log.Warnf("mqtt", "response to %s failed", topic)
			}
		}()
	}
	clientTLS := tlsCfg.Clone()
	clientTLS.ClientAuth = tls.NoClientCert
	clientTLS.RootCAs = tlsCfg.ClientCAs
	clientTLS.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 {
			return errors.New("unverified MQTT broker")
		}
		if cfg.SSLCRLFile != "" {
			return checkPeerRevocation(cfg.SSLCRLFile, s)
		}
		return nil
	}
	filters := map[string]byte{}
	for topic := range mqttOperations(cfg) {
		filters[topic[:strings.LastIndex(topic, "/")+1]+"+"] = 1
	}
	options := mqtt.NewClientOptions().AddBroker("ssl://" + net.JoinHostPort(cfg.MQTTBrokerAddress, strconv.Itoa(cfg.MQTTBrokerPort))).
		SetClientID(systemName + "-" + strconv.FormatInt(time.Now().UnixNano(), 36)).SetTLSConfig(clientTLS).SetCleanSession(true).
		SetOrderMatters(false).SetConnectTimeout(5 * time.Second).SetWriteTimeout(10 * time.Second).SetAutoReconnect(true).
		SetConnectRetry(true).SetConnectRetryInterval(10 * time.Second).SetMaxReconnectInterval(30 * time.Second).
		SetOnConnectHandler(func(c mqtt.Client) {
			if t := c.SubscribeMultiple(filters, handler); !t.WaitTimeout(10*time.Second) || t.Error() != nil {
				srv.log.Errorf("mqtt", "subscription failed: %v", t.Error())
				return
			}
			srv.log.Infof("mqtt", "MQTT API on %s:%d (%d request topics)", cfg.MQTTBrokerAddress, cfg.MQTTBrokerPort, len(mqttOperations(cfg)))
		}).
		SetConnectionLostHandler(func(_ mqtt.Client, err error) { srv.log.Warnf("mqtt", "connection lost: %v", err) })
	client := mqtt.NewClient(options)
	client.Connect()
	return func() {
		cancel()
		client.Disconnect(250)
	}
}
