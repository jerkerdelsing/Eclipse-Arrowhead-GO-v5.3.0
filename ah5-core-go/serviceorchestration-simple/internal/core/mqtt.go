// SPDX-License-Identifier: EPL-2.0
package core

// MQTT API of the core systems (the Java mqtt.api.enabled counterpart). Requests use the Java envelope
// (MqttRequestTemplate: traceId, authentication "IDENTITY-TOKEN//<token>", responseTopic, qosRequirement, params,
// payload) on <base topic><operation>, with the Java base topics per service. The adapter verifies the identity token
// and runs the request in process through the HTTPS route of the operation, so the blacklist, management and
// authorization checks and the handlers are the same as over HTTPS; the response (MqttResponseTemplate: status,
// traceId, receiver, payload) goes to the request's responseTopic.
//
// Differences to Java, for the broker binding of responses: the response topic must lie under
// arrowhead/response/<requester>/ (the requester of the verified token; the broker lets each client read only its
// own response prefix), requests with an invalid token are not answered, and operations that bind credentials to the
// client certificate (identity login/logout/change) stay HTTPS only.

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"log"
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

// MQTTRequest is the Java MqttRequestTemplate.
type MQTTRequest struct {
	TraceID        string            `json:"traceId"`
	Authentication string            `json:"authentication"`
	ResponseTopic  string            `json:"responseTopic"`
	QoS            *int              `json:"qosRequirement"`
	Params         map[string]string `json:"params"`
	Payload        json.RawMessage   `json:"payload"`
}

// MQTTResponse is the Java MqttResponseTemplate.
type MQTTResponse struct {
	Status   int    `json:"status"`
	TraceID  string `json:"traceId"`
	Receiver string `json:"receiver"`
	Payload  any    `json:"payload"`
}

type mqttOperation struct{ method, path string }

// MQTTResponsePrefix is the topic prefix under which a system receives its MQTT responses.
func MQTTResponsePrefix(system string) string { return "arrowhead/response/" + system + "/" }

// mqttListParameters: removal operations take their names as a JSON list payload (Java readPayload(List<String>));
// over HTTPS the list is this query parameter.
var mqttListParameters = map[string]string{
	"DELETE /authentication/mgmt/identities":                                "names",
	"DELETE /authentication/mgmt/sessions":                                  "names",
	"DELETE /consumerauthorization/authorization/mgmt/revoke":               "instanceIds",
	"DELETE /consumerauthorization/authorization/mgmt/token/revoke":         "tokenReferences",
	"DELETE /consumerauthorization/authorization/mgmt/token/encryption-key": "systemNames",
	"DELETE /serviceorchestration/orchestration/mgmt/simple-store/remove":   "uuids",
	"DELETE /serviceorchestration/orchestration/mgmt/lock/remove/{owner}":   "instanceIds",
	"DELETE /serviceorchestration/orchestration/mgmt/push/unsubscribe":      "ids",
}

func (a *App) mqttTopicPrefix() string {
	if a.Config.MQTTTopicPrefix != "" {
		return strings.TrimSuffix(a.Config.MQTTTopicPrefix, "/")
	}
	switch a.Config.Role {
	case "authentication":
		return "arrowhead/authentication"
	case "consumer-authorization":
		return "arrowhead/consumer-authorization"
	default:
		return "arrowhead/serviceorchestration"
	}
}

// MQTTBaseTopic returns the Java base topic of a service definition (ending with "/"), empty for none.
func (a *App) MQTTBaseTopic(definition string) string {
	p := a.mqttTopicPrefix()
	topic := map[string]string{
		"monitor":                                   "/monitor/",
		"generalManagement":                         "/general/management/",
		"identity":                                  "/identity/",
		"identityManagement":                        "/identity/management/",
		"authorization":                             "/authorization/",
		"authorizationManagement":                   "/authorization/management/",
		"authorizationToken":                        "/authorization-token/",
		"authorizationTokenManagement":              "/authorization-token/management/",
		"serviceOrchestration":                      "/orchestration/",
		"serviceOrchestrationPushManagement":        "/orchestration/management/push/",
		"serviceOrchestrationHistoryManagement":     "/orchestration/management/history/",
		"serviceOrchestrationLockManagement":        "/orchestration/management/lock/",
		"serviceOrchestrationSimpleStoreManagement": "/orchestration/management/store/",
		"serviceOrchestrationPlantManagement":       "/orchestration/management/plant-rules/",
	}[definition]
	if topic == "" {
		return ""
	}
	return p + topic
}

// mqttOperations maps every request topic to its HTTPS route.
func (a *App) mqttOperations() map[string]mqttOperation {
	out := map[string]mqttOperation{a.MQTTBaseTopic("monitor") + "echo": {"GET", a.base() + "/monitor/echo"}}
	for _, s := range a.Services() {
		base := a.MQTTBaseTopic(s.Definition)
		if base == "" {
			continue
		}
		for name, op := range s.Operations {
			out[base+name] = mqttOperation{str(op, "method"), s.BasePath + str(op, "path")}
		}
	}
	return out
}

func (a *App) mqttTopics() []string {
	seen := map[string]bool{}
	var out []string
	for topic := range a.mqttOperations() {
		base := topic[:strings.LastIndex(topic, "/")+1]
		if !seen[base] {
			seen[base] = true
			out = append(out, base+"+")
		}
	}
	return out
}

// mqttBroker returns the broker host and port of mqttURL (ssl://host:port).
func (a *App) mqttBroker() (string, int, error) {
	u, e := url.Parse(a.Config.MQTTURL)
	if e != nil || (u.Scheme != "ssl" && u.Scheme != "tls" && u.Scheme != "mqtts") || u.Hostname() == "" || u.User != nil {
		return "", 0, errors.New("mqttURL must be ssl://host:port without credentials")
	}
	port := 8883
	if u.Port() != "" {
		if port, e = strconv.Atoi(u.Port()); e != nil {
			return "", 0, e
		}
	}
	return u.Hostname(), port, nil
}

// mqttInterface is the generic_mqtts interface of a service, registered besides generic_https.
func (a *App) mqttInterface(s Service) Document {
	base := a.MQTTBaseTopic(s.Definition)
	host, port, e := a.mqttBroker()
	if base == "" || e != nil {
		return nil
	}
	ops := []string{}
	for name := range s.Operations {
		ops = append(ops, name)
	}
	sort.Strings(ops)
	return Document{"templateName": "generic_mqtts", "protocol": "ssl", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{host}, "accessPort": port, "baseTopic": base, "operations": ops}}
}

var placeholderRE = regexp.MustCompile(`\{([A-Za-z]+)\}`)

// mqttHTTPRequest builds the HTTPS request of an MQTT request: params fill the path placeholders (a single
// placeholder also takes a string payload), the other params become the query, a list payload of a removal operation
// becomes its query parameter, and any other payload the JSON body.
func mqttHTTPRequest(ctx context.Context, op mqttOperation, req MQTTRequest) (*http.Request, error) {
	params := map[string]string{}
	for k, v := range req.Params {
		params[k] = v
	}
	var payload any
	if len(bytes.TrimSpace(req.Payload)) > 0 {
		if e := json.Unmarshal(req.Payload, &payload); e != nil {
			return nil, bad("Invalid payload")
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
			return nil, bad(m[1] + " is required")
		}
		delete(params, m[1])
		path = strings.Replace(path, m[0], url.PathEscape(value), 1)
	}
	query := url.Values{}
	for k, v := range params {
		query.Set(k, v)
	}
	if listKey := mqttListParameters[op.method+" "+op.path]; listKey != "" || strings.HasSuffix(op.path, "/get-config") {
		if listKey == "" {
			listKey = "keys"
		}
		if items, isList := payload.([]any); isList {
			for _, item := range items {
				s, ok := item.(string)
				if !ok {
					return nil, bad(listKey + " must be a list of strings")
				}
				query.Add(listKey, s)
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
	r, e := http.NewRequestWithContext(ctx, op.method, target, bytes.NewReader(body))
	if e != nil {
		return nil, bad("Invalid request parameters")
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	return r, nil
}

func exceptionType(status int) string {
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

// HandleMQTT answers one MQTT request: the response topic and the response, or an empty topic when the request is
// not answered (no or a foreign response topic, invalid envelope or token).
func (a *App) HandleMQTT(ctx context.Context, topic string, message []byte) (string, *MQTTResponse) {
	var req MQTTRequest
	if len(message) > 1<<20 || json.Unmarshal(message, &req) != nil {
		log.Printf("%s MQTT %s: invalid request envelope", a.Config.Role, topic)
		return "", nil
	}
	token, ok := strings.CutPrefix(req.Authentication, "IDENTITY-TOKEN//")
	if !ok || token == "" {
		log.Printf("%s MQTT %s: identity token required", a.Config.Role, topic)
		return "", nil
	}
	name, sysop, e := a.verifyToken(ctx, token)
	if e != nil {
		log.Printf("%s MQTT %s: identity token refused (%v)", a.Config.Role, topic, e)
		return "", nil
	}
	if req.ResponseTopic == "" {
		return "", nil
	}
	if !strings.HasPrefix(req.ResponseTopic, MQTTResponsePrefix(name)) || strings.ContainsAny(req.ResponseTopic, "+#") {
		log.Printf("%s MQTT %s by %s: response topic outside %s refused", a.Config.Role, topic, name, MQTTResponsePrefix(name))
		return "", nil
	}
	respond := func(status int, payload any) (string, *MQTTResponse) {
		return req.ResponseTopic, &MQTTResponse{Status: status, TraceID: req.TraceID, Receiver: name, Payload: payload}
	}
	failure := func(status int, message string) (string, *MQTTResponse) {
		return respond(status, Document{"errorMessage": message, "errorCode": status, "exceptionType": exceptionType(status), "origin": topic})
	}
	op, known := a.mqttOperations()[topic]
	if !known {
		return failure(404, "Unknown operation")
	}
	hr, e := mqttHTTPRequest(context.WithValue(ctx, mqttPrincipalKey{}, principal{name, sysop}), op, req)
	if e != nil {
		var ae *APIError
		errors.As(e, &ae)
		return failure(ae.Status, ae.Message)
	}
	rec := httptest.NewRecorder()
	a.ServeHTTP(rec, hr)
	var payload any = ""
	if body := bytes.TrimSpace(rec.Body.Bytes()); len(body) > 0 {
		if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			if json.Unmarshal(body, &payload) != nil {
				payload = string(body)
			}
		} else {
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

func mqttQoS(q *int) byte {
	if q == nil || *q < 0 || *q > 2 {
		return 0
	}
	return byte(*q)
}

// RunMQTT serves the MQTT API while mqttURL is set: connects to the broker with the system certificate, subscribes to
// the request topics and answers the requests concurrently (at most 32 at a time).
func (a *App) RunMQTT(ctx context.Context) {
	if a.Config.MQTTURL == "" {
		return
	}
	host, port, e := a.mqttBroker()
	if e != nil {
		log.Printf("%s MQTT API disabled: %v", a.Config.Role, e)
		return
	}
	slots := make(chan struct{}, 32)
	var client mqtt.Client
	handler := func(c mqtt.Client, m mqtt.Message) {
		select {
		case slots <- struct{}{}:
		default:
			log.Printf("%s MQTT %s: too many concurrent requests, dropped", a.Config.Role, m.Topic())
			return
		}
		go func() {
			defer func() { <-slots }()
			call, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			topic, resp := a.HandleMQTT(call, m.Topic(), m.Payload())
			if topic == "" {
				return
			}
			var req MQTTRequest
			_ = json.Unmarshal(m.Payload(), &req)
			body, _ := json.Marshal(resp)
			if t := c.Publish(topic, mqttQoS(req.QoS), false, body); !t.WaitTimeout(10*time.Second) || t.Error() != nil {
				log.Printf("%s MQTT response to %s failed", a.Config.Role, topic)
			}
		}()
	}
	topics := a.mqttTopics()
	options := mqtt.NewClientOptions().AddBroker("ssl://" + net.JoinHostPort(host, strconv.Itoa(port))).
		SetClientID(a.Config.Name + "-" + uuid()[:8]).SetTLSConfig(a.mqttTLS()).SetCleanSession(true).SetOrderMatters(false).
		SetConnectTimeout(5 * time.Second).SetWriteTimeout(10 * time.Second).SetAutoReconnect(true).SetConnectRetry(true).
		SetConnectRetryInterval(10 * time.Second).SetMaxReconnectInterval(30 * time.Second).
		SetOnConnectHandler(func(c mqtt.Client) {
			filters := map[string]byte{}
			for _, t := range topics {
				filters[t] = 1
			}
			if t := c.SubscribeMultiple(filters, handler); !t.WaitTimeout(10*time.Second) || t.Error() != nil {
				log.Printf("%s MQTT subscription failed: %v", a.Config.Role, t.Error())
				return
			}
			log.Printf("%s MQTT API on %s (%d request topics)", a.Config.Role, a.Config.MQTTURL, len(a.mqttOperations()))
		}).
		SetConnectionLostHandler(func(_ mqtt.Client, e error) { log.Printf("%s MQTT connection lost: %v", a.Config.Role, e) })
	client = mqtt.NewClient(options)
	client.Connect()
	a.background.Add(1)
	go func() {
		defer a.background.Done()
		<-ctx.Done()
		client.Disconnect(250)
	}()
}

// mqttTLS is the client TLS of the broker connection: the system certificate, the broker certificate verified
// against the cloud CA and the CRL.
func (a *App) mqttTLS() *tls.Config {
	if a.TLS == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := a.TLS.Clone()
	c.ClientAuth = tls.NoClientCert
	c.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 {
			return errors.New("unverified MQTT broker")
		}
		return checkPeerRevocation(a.Config.CRLFile, s)
	}
	return c
}
