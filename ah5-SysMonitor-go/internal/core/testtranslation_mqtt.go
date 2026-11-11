// SPDX-License-Identifier: EPL-2.0
package core

// MQTT side of TestTranslation (2026-10-24), with mqttURL set:
//   - HTTPS -> MQTT bridges: the consumer calls POST <bridge basePath>/<operation> (body = payload, query = params);
//     TestTranslation sends the request in the Arrowhead MQTT envelope (Java MqttRequestTemplate) with its own identity
//     token to <target baseTopic><operation> and answers with the response status and payload.
//   - MQTT -> HTTPS bridges: the bridge interface is generic_mqtts with baseTopic arrowhead/testtranslation/bridge/<id>/;
//     the consumer publishes the envelope with authentication "TRANSLATION-BRIDGE-TOKEN//<bridgeId>" and a response
//     topic under arrowhead/response/; params fill the target path placeholders (the others become the query) and the
//     payload is the body.
// Targets must be on the broker TestTranslation is connected to. Responses to TestTranslation's own requests arrive on
// arrowhead/response/TestTranslation/<traceId>.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	translationTemplateMQTTS = "generic_mqtts"
	bridgeTopicPrefix        = "arrowhead/testtranslation/bridge/"
	bridgeMQTTTokenPrefix    = "TRANSLATION-BRIDGE-TOKEN//"
)

type bridgeMQTTState struct {
	connected atomic.Bool
	mu        sync.Mutex
	client    mqtt.Client
	pending   map[string]chan Document
}

// testTranslationMQTTTargetMetadata is the metadata of the second interfaceBridgeManagement instance (1.1.0).
func testTranslationMQTTTargetMetadata() Document {
	return Document{"interfaceBridge": Document{"from": []string{translationTemplateHTTPS}, "to": translationTemplateMQTTS}}
}

func (a *App) mqttBrokerAddress() (string, int, error) {
	u, e := url.Parse(a.Config.MQTTURL)
	if e != nil || u.Scheme != "ssl" || u.Hostname() == "" || u.User != nil {
		return "", 0, errors.New("mqttURL must be ssl://host:port")
	}
	port := 8883
	if u.Port() != "" {
		if port, e = strconv.Atoi(u.Port()); e != nil {
			return "", 0, e
		}
	}
	return u.Hostname(), port, nil
}

// mqttTargetUsable: a generic_mqtts target interface on this translator's broker offering the operation.
func (a *App) mqttTargetUsable(props Document, operation string) bool {
	host, port, e := a.mqttBrokerAddress()
	if e != nil {
		return false
	}
	addresses := list(props, "accessAddresses")
	base := str(props, "baseTopic")
	if len(addresses) == 0 || addresses[0] != host || number(props, "accessPort", 0) != port || !strings.HasSuffix(base, "/") || strings.ContainsAny(base, "+#") {
		return false
	}
	return contains(list(props, "operations"), operation)
}

// runTestTranslationMQTT keeps the broker connection with the bridge and response subscriptions.
func (a *App) runTestTranslationMQTT(ctx context.Context) {
	host, port, e := a.mqttBrokerAddress()
	if e != nil {
		a.recordLog("ERROR", e.Error())
		return
	}
	st := &a.broker.bridgeMQTT
	st.mu.Lock()
	st.pending = map[string]chan Document{}
	st.mu.Unlock()
	responses := "arrowhead/response/" + a.Config.Name + "/+"
	options := mqtt.NewClientOptions().AddBroker("ssl://" + net.JoinHostPort(host, strconv.Itoa(port))).
		SetClientID(a.Config.Name + "-go-" + uuid()[:8]).SetTLSConfig(a.brokerTLS()).SetCleanSession(true).SetOrderMatters(false).
		SetConnectTimeout(5 * time.Second).SetWriteTimeout(10 * time.Second).SetAutoReconnect(true).SetConnectRetry(true).
		SetConnectRetryInterval(10 * time.Second).SetMaxReconnectInterval(30 * time.Second).
		SetOnConnectHandler(func(c mqtt.Client) {
			t := c.SubscribeMultiple(map[string]byte{bridgeTopicPrefix + "+/+": 1, responses: 1}, func(c mqtt.Client, m mqtt.Message) {
				if strings.HasPrefix(m.Topic(), bridgeTopicPrefix) {
					go a.bridgeMQTTRequest(ctx, c, m.Topic(), m.Payload())
					return
				}
				var resp Document
				if len(m.Payload()) > 8<<20 || json.Unmarshal(m.Payload(), &resp) != nil {
					return
				}
				st.mu.Lock()
				ch := st.pending[str(resp, "traceId")]
				st.mu.Unlock()
				if ch != nil {
					select {
					case ch <- resp:
					default:
					}
				}
			})
			ok := t.WaitTimeout(10*time.Second) && t.Error() == nil
			st.connected.Store(ok)
			if !ok {
				a.recordLog("ERROR", "MQTT bridge subscription failed")
			}
		}).
		SetConnectionLostHandler(func(mqtt.Client, error) { st.connected.Store(false) })
	client := mqtt.NewClient(options)
	st.mu.Lock()
	st.client = client
	st.mu.Unlock()
	client.Connect()
	<-ctx.Done()
	st.connected.Store(false)
	client.Disconnect(250)
}

// bridgeMQTTCall sends one MQTT API request with this system's identity and waits for the response.
func (a *App) bridgeMQTTCall(ctx context.Context, topic string, params map[string]string, payload any) (int, any, error) {
	st := &a.broker.bridgeMQTT
	st.mu.Lock()
	client := st.client
	st.mu.Unlock()
	if client == nil || !st.connected.Load() {
		return 0, nil, errors.New("not connected to the MQTT broker")
	}
	token, e := a.Remote.ownToken(ctx)
	if e != nil {
		return 0, nil, e
	}
	trace := uuid()
	ch := make(chan Document, 1)
	st.mu.Lock()
	st.pending[trace] = ch
	st.mu.Unlock()
	defer func() {
		st.mu.Lock()
		delete(st.pending, trace)
		st.mu.Unlock()
	}()
	req := Document{"traceId": trace, "authentication": "IDENTITY-TOKEN//" + token, "responseTopic": "arrowhead/response/" + a.Config.Name + "/" + trace, "qosRequirement": 1, "params": params, "payload": payload}
	body, _ := json.Marshal(req)
	if t := client.Publish(topic, 1, false, body); !t.WaitTimeout(10*time.Second) || t.Error() != nil {
		return 0, nil, errors.New("MQTT request not published")
	}
	select {
	case resp := <-ch:
		return number(resp, "status", 500), resp["payload"], nil
	case <-time.After(15 * time.Second):
		return 0, nil, errors.New("no MQTT response from the target")
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

// bridgeMQTTRequest serves one MQTT consumer request on arrowhead/testtranslation/bridge/<bridgeId>/<operation>.
func (a *App) bridgeMQTTRequest(ctx context.Context, c mqtt.Client, topic string, message []byte) {
	parts := strings.Split(strings.TrimPrefix(topic, bridgeTopicPrefix), "/")
	var req struct {
		TraceID        string            `json:"traceId"`
		Authentication string            `json:"authentication"`
		ResponseTopic  string            `json:"responseTopic"`
		QoS            *int              `json:"qosRequirement"`
		Params         map[string]string `json:"params"`
		Payload        json.RawMessage   `json:"payload"`
	}
	if len(parts) != 2 || len(message) > 1<<20 || json.Unmarshal(message, &req) != nil {
		return
	}
	id, operation := parts[0], parts[1]
	// the bridge token is the consumer's credential; without it (or a response topic) the request is not answered
	if req.Authentication != bridgeMQTTTokenPrefix+id || !strings.HasPrefix(req.ResponseTopic, "arrowhead/response/") || strings.ContainsAny(req.ResponseTopic, "+#") {
		return
	}
	reply := func(status int, payload any) {
		qos := byte(0)
		if req.QoS != nil && *req.QoS >= 0 && *req.QoS <= 2 {
			qos = byte(*req.QoS)
		}
		body, _ := json.Marshal(Document{"status": status, "traceId": req.TraceID, "receiver": "", "payload": payload})
		c.Publish(req.ResponseTopic, qos, false, body).WaitTimeout(10 * time.Second)
	}
	failure := func(e error) {
		status, message := 500, "Internal server error"
		var ae *APIError
		if errors.As(e, &ae) {
			status, message = ae.Status, ae.Message
		}
		reply(status, Document{"errorMessage": message, "errorCode": status, "exceptionType": mqttExceptionType(status), "origin": topic})
	}
	row, e := a.row("bridges", id)
	if e != nil || str(row, "status") != "ACTIVE" || str(row, "inputTemplate") != translationTemplateMQTTS {
		failure(&APIError{404, "Unknown or inactive bridge"})
		return
	}
	if operation != str(row, "operation") {
		failure(&APIError{403, "Operation outside the negotiated bridge"})
		return
	}
	// the target request: params fill the placeholders of the target path, the others are the query
	params := map[string]string{}
	for k, v := range req.Params {
		params[k] = v
	}
	path := str(row, "path")
	for {
		open := strings.Index(path, "{")
		end := strings.Index(path, "}")
		if open < 0 || end < open {
			break
		}
		name := path[open+1 : end]
		value, ok := params[name]
		if !ok || value == "" {
			failure(bad(name + " is required"))
			return
		}
		delete(params, name)
		path = path[:open] + url.PathEscape(value) + path[end+1:]
	}
	query := url.Values{}
	for k, v := range params {
		query.Set(k, v)
	}
	call := bridgeRequest{method: str(row, "method"), path: path, rawQuery: query.Encode(), params: req.Params}
	if p := bytes.TrimSpace(req.Payload); len(p) > 0 && string(p) != "null" {
		call.body, call.contentType = p, "application/json"
	}
	timeout, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	status, result, contentType, e := a.bridgeForward(timeout, id, row, call)
	if e != nil {
		failure(e)
		return
	}
	var payload any = ""
	if len(bytes.TrimSpace(result)) > 0 {
		if !strings.Contains(contentType, "json") || json.Unmarshal(result, &payload) != nil {
			payload = string(result)
		}
	}
	reply(status, payload)
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
	case 502, 503:
		return "EXTERNAL_SERVER_ERROR"
	}
	return "INTERNAL_SERVER_ERROR"
}
