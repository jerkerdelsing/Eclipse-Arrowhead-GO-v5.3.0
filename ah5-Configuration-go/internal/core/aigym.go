// SPDX-License-Identifier: EPL-2.0
package core

// AIGym sysMonitorData subscription (2026-10-17), as the Java AIGym: every 30 s AIGym orchestrates
// sysMonitorData.subscribe (generic_mqtts) through ServiceOrchestration, subscribes to <baseTopic>/+/+ on the
// orchestrated MQTT broker with its own certificate (QoS 1) and keeps the latest 200 observations for experiments
// (GET /aigym/observations). The connection and orchestration state is reported by GET /aigym/status.

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const gymObservationLimit = 200

type gymState struct {
	mu                sync.Mutex
	observations      []Document
	topic, broker     string
	orchestrationErr  string
	registrationErr   string
	registered        bool
	registrationKnown bool
}

func (g *gymState) add(o Document) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.observations = append([]Document{o}, g.observations...)
	if len(g.observations) > gymObservationLimit {
		g.observations = g.observations[:gymObservationLimit]
	}
}

func (g *gymState) snapshot() []Document {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]Document{}, g.observations...)
}

// setRegistration records the outcome of the last registration round (all support systems).
func (a *App) setRegistration(e error) {
	g := &a.broker.gym
	g.mu.Lock()
	defer g.mu.Unlock()
	g.registrationKnown, g.registered, g.registrationErr = true, e == nil, ""
	if e != nil {
		g.registrationErr = e.Error()
	}
}

// sysMonitorDataEndpoint orchestrates sysMonitorData.subscribe and returns the broker address and base topic.
func (a *App) sysMonitorDataEndpoint(ctx context.Context) (string, string, error) {
	var response Document
	req := Document{"serviceRequirement": Document{"serviceDefinition": "sysMonitorData", "operations": []string{"subscribe"}, "interfaceTemplateNames": []string{"generic_mqtts"}}}
	if e := a.consume(ctx, "ServiceOrchestration", "POST", "/serviceorchestration/orchestration/pull", req, &response); e != nil {
		return "", "", e
	}
	for _, raw := range list(response, "results") {
		row, _ := raw.(map[string]any)
		for _, iv := range list(row, "interfaces") {
			intf, _ := iv.(map[string]any)
			if str(intf, "templateName") != "generic_mqtts" {
				continue
			}
			p := obj(intf, "properties")
			addresses := list(p, "accessAddresses")
			port := number(p, "accessPort", 0)
			base := str(p, "baseTopic")
			if len(addresses) == 0 || port < 1 || port > 65535 || base == "" {
				continue
			}
			host, _ := addresses[0].(string)
			if host == "" {
				continue
			}
			return "ssl://" + net.JoinHostPort(host, strconv.Itoa(port)), base, nil
		}
	}
	return "", "", fmt.Errorf("no authorized sysMonitorData provider")
}

func (a *App) runAIGymSubscriber(ctx context.Context) {
	g := &a.broker.gym
	var client mqtt.Client
	defer func() {
		if client != nil {
			client.Disconnect(250)
		}
		a.broker.mqttConnected.Store(false)
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		broker, base, e := a.sysMonitorDataEndpoint(ctx)
		g.mu.Lock()
		g.orchestrationErr = ""
		if e != nil {
			g.orchestrationErr = e.Error()
		}
		current := g.broker
		g.mu.Unlock()
		if e == nil {
			if client == nil || broker != current || !client.IsConnected() {
				if client != nil {
					client.Disconnect(250)
				}
				options := mqtt.NewClientOptions().AddBroker(broker).SetClientID("AIGym-go-" + uuid()).SetTLSConfig(a.brokerTLS()).
					SetConnectTimeout(5 * time.Second).SetWriteTimeout(5 * time.Second).SetAutoReconnect(false).SetCleanSession(true)
				client = mqtt.NewClient(options)
				token := client.Connect()
				ok := token.WaitTimeout(5*time.Second) && token.Error() == nil
				g.mu.Lock()
				g.broker, g.topic = broker, ""
				if !ok {
					g.orchestrationErr = "MQTT connection to " + broker + " failed"
				}
				g.mu.Unlock()
				a.broker.mqttConnected.Store(ok)
			}
			topic := base + "/+/+"
			g.mu.Lock()
			subscribed := g.topic
			g.mu.Unlock()
			if client.IsConnected() && topic != subscribed {
				token := client.Subscribe(topic, 1, func(_ mqtt.Client, m mqtt.Message) {
					var o Document
					if len(m.Payload()) > 1<<20 || json.Unmarshal(m.Payload(), &o) != nil {
						return
					}
					o["mqttTopic"], o["receivedByAIGym"] = m.Topic(), now()
					g.add(o)
				})
				if token.WaitTimeout(5*time.Second) && token.Error() == nil {
					g.mu.Lock()
					g.topic = topic
					g.mu.Unlock()
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// aiGymStatus has the field layout of the Java AIGym status, plus the Go model inventory.
func (a *App) aiGymStatus(inventory Document) Document {
	g := &a.broker.gym
	g.mu.Lock()
	defer g.mu.Unlock()
	connected := a.broker.mqttConnected.Load()
	status := "degraded"
	if connected && g.registered {
		status = "running"
	}
	amqpBroker, amqpPort, _ := a.amqpHostPort()
	return Document{"status": status, "system": a.Config.Name, "implementation": "Go", "arrowheadVersion": "5.4.0", "models": inventory, "time": now(),
		"registration":   Document{"registered": g.registered, "error": g.registrationErr},
		"mqtt":           Document{"connected": connected, "broker": g.broker},
		"amqp":           Document{"broker": net.JoinHostPort(amqpBroker, strconv.Itoa(amqpPort)), "exchange": "arrowhead", "routingKey": a.monitorBaseRoutingKey()},
		"sysMonitorData": Document{"topic": g.topic, "received": len(g.observations), "error": g.orchestrationErr},
		"security":       "mutual TLS + Arrowhead identity token + ConsumerAuthorization"}
}

func (a *App) amqpHostPort() (string, int, error) {
	u, e := url.Parse(a.Config.AMQPURL)
	if e != nil || u.Hostname() == "" {
		return "", 0, fmt.Errorf("no AMQP broker configured")
	}
	port := 5671
	if u.Port() != "" {
		if port, e = strconv.Atoi(u.Port()); e != nil {
			return "", 0, e
		}
	}
	return u.Hostname(), port, nil
}

func (a *App) monitorBaseRoutingKey() string {
	return strings.Split(a.Config.CloudSuffix, ".")[0] + ".sysmonitor." + a.Config.Name + "." + a.Config.Name
}
