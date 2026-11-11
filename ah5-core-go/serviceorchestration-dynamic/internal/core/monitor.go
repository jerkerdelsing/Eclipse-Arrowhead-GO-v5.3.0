// SPDX-License-Identifier: EPL-2.0
package core

// Native sysMonitor telemetry of the core systems (2026-10-17), as in ah5-support-go: the system registers a
// sysMonitor offer on generic_amqps and publishes echo/power/status observations to the topic exchange "arrowhead"
// under <cloud>.sysmonitor.<system>.<system>.<type>, authenticated with its own certificate (SASL EXTERNAL) and
// confirmed by the broker.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

var monitorObservationTypes = []string{"echo", "power", "status"}

func (a *App) monitorRoutingKey() string {
	return strings.Split(a.Config.CloudSuffix, ".")[0] + ".sysmonitor." + a.Config.Name + "." + a.Config.Name
}

func (a *App) amqpEndpoint() (host string, port int, e error) {
	u, e := url.Parse(a.Config.AMQPURL)
	if e != nil || u.Scheme != "amqps" || u.Hostname() == "" || u.User != nil {
		return "", 0, errors.New("monitoring requires an explicit amqps URL without embedded credentials")
	}
	port = 5671
	if u.Port() != "" {
		if port, e = strconv.Atoi(u.Port()); e != nil || port < 1 || port > 65535 {
			return "", 0, errors.New("invalid amqps port")
		}
	}
	return u.Hostname(), port, nil
}

// registerMonitor registers the sysMonitor offer (called from Register when monitorEnabled).
func (a *App) registerMonitor(ctx context.Context) error {
	host, port, e := a.amqpEndpoint()
	if e != nil {
		return e
	}
	req := Document{"systemName": a.Config.Name, "serviceDefinitionName": "sysMonitor", "version": "1.0.0",
		"metadata": Document{"publisherMode": "native", "observationTypes": monitorObservationTypes},
		"interfaces": []Document{{"templateName": "generic_amqps", "protocol": "amqps", "policy": "CERT_AUTH", "properties": Document{
			"accessAddresses": []string{host}, "accessPort": port, "exchange": "arrowhead", "baseRoutingKey": a.monitorRoutingKey(),
			"operations": monitorObservationTypes}}}}
	return a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/register", req, nil)
}

func (a *App) brokerTLS() *tls.Config {
	if a.TLS == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := a.TLS.Clone()
	c.ClientAuth = tls.NoClientCert
	return c
}

// publishMonitor sends one echo/power/status observation set with publisher confirms.
func (a *App) publishMonitor(ctx context.Context) error {
	if _, _, e := a.amqpEndpoint(); e != nil {
		return e
	}
	conn, e := amqp.DialConfig(a.Config.AMQPURL, amqp.Config{SASL: []amqp.Authentication{&amqp.ExternalAuth{}}, TLSClientConfig: a.brokerTLS(), Heartbeat: 30 * time.Second,
		Dial: func(network, address string) (net.Conn, error) {
			return net.DialTimeout(network, address, 5*time.Second)
		}})
	if e != nil {
		return e
	}
	defer conn.Close()
	ch, e := conn.Channel()
	if e != nil {
		return e
	}
	defer ch.Close()
	if e = ch.Confirm(false); e != nil {
		return e
	}
	values := map[string]Document{"echo": {"status": "alive"}, "power": {"supplyType": "line"}, "status": {"state": "running", "implementation": "Go", "system": a.Config.Name}}
	for _, typ := range monitorObservationTypes {
		msg := Document{"schemaVersion": "1.0", "observationId": uuid(), "providerSystem": a.Config.Name, "serviceInstance": a.Config.Name, "observationType": typ, "sourceTime": now(), "value": values[typ], "quality": "good", "metadata": Document{"publisherMode": "native", "implementation": "Go"}}
		body, e := json.Marshal(msg)
		if e != nil {
			return e
		}
		confirmation, e := ch.PublishWithDeferredConfirmWithContext(ctx, "arrowhead", a.monitorRoutingKey()+"."+typ, false, false,
			amqp.Publishing{ContentType: "application/json", DeliveryMode: amqp.Persistent, MessageId: str(msg, "observationId"), Timestamp: time.Now(), Body: body})
		if e != nil {
			return e
		}
		if confirmation == nil {
			return errors.New("no publisher confirmation")
		}
		if ok, e := confirmation.WaitContext(ctx); e != nil || !ok {
			return errors.New("broker did not confirm the monitoring message")
		}
	}
	return nil
}
