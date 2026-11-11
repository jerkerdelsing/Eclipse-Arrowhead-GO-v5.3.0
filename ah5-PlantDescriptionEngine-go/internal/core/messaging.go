// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	amqp "github.com/rabbitmq/amqp091-go"
	"net"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

type brokerState struct {
	amqpConnected, mqttConnected atomic.Bool
	gym                          gymState
	orchestration                orchestrationBroker
	bridgeMQTT                   bridgeMQTTState
}

func (a *App) brokerTLS() *tls.Config {
	if a.TLS == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := a.TLS.Clone()
	c.ClientAuth = tls.NoClientCert
	return c
}
func (a *App) amqpConnect() (*amqp.Connection, error) {
	u, e := url.Parse(a.Config.AMQPURL)
	if e != nil || u.Scheme != "amqps" || u.Host == "" || u.User != nil {
		return nil, errors.New("AMQP requires an explicit amqps URL without embedded credentials")
	}
	return amqp.DialConfig(a.Config.AMQPURL, amqp.Config{SASL: []amqp.Authentication{&amqp.ExternalAuth{}}, TLSClientConfig: a.brokerTLS(), Heartbeat: 30 * time.Second, Dial: func(network, address string) (net.Conn, error) {
		return net.DialTimeout(network, address, 5*time.Second)
	}})
}
func (a *App) publishNative(ctx context.Context) error {
	conn, e := a.amqpConnect()
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
	cloud := strings.Split(a.Config.CloudSuffix, ".")[0]
	for typ, value := range map[string]Document{"echo": {"status": "alive"}, "power": {"supplyType": "line"}, "status": {"state": "running", "implementation": "Go", "system": a.Config.Name}} {
		msg := Document{"schemaVersion": "1.0", "observationId": uuid(), "providerSystem": a.Config.Name, "serviceInstance": a.Config.Name, "observationType": typ, "sourceTime": now(), "value": value, "quality": "good", "metadata": Document{"publisherMode": "native", "implementation": "Go"}}
		body, e := json.Marshal(msg)
		if e != nil {
			return e
		}
		confirmation, e := ch.PublishWithDeferredConfirmWithContext(ctx, "arrowhead", cloud+".sysmonitor."+a.Config.Name+"."+a.Config.Name+"."+typ, false, false, amqp.Publishing{ContentType: "application/json", DeliveryMode: amqp.Persistent, MessageId: str(msg, "observationId"), Timestamp: time.Now(), Body: body})
		if e != nil {
			return e
		}
		if confirmation == nil {
			return errors.New("No publisher confirmation")
		}
		ok, e := confirmation.WaitContext(ctx)
		if e != nil || !ok {
			return errors.New("Broker did not confirm monitoring message")
		}
	}
	return nil
}
func (a *App) desiredBindings() map[string]bool {
	bindings := map[string]bool{}
	subs, offers := a.monitorLookup()
	for _, provider := range offers {
		name := str(provider, "providerSystem")
		row := subs[name]
		types := []any{}
		if row == nil {
			if a.Config.DefaultSubscription == "all" {
				types = []any{"*"}
			}
		} else if flag(row, "enabled") {
			types = list(row, "observationTypes")
		}
		for _, v := range types {
			typ, ok := v.(string)
			if ok {
				bindings[str(provider, "baseRoutingKey")+"."+typ] = true
			}
		}
	}
	return bindings
}
func (a *App) consumeMonitoring(ctx context.Context) error {
	conn, e := a.amqpConnect()
	if e != nil {
		return e
	}
	defer conn.Close()
	ch, e := conn.Channel()
	if e != nil {
		return e
	}
	defer ch.Close()
	queue, e := ch.QueueDeclare(a.Config.Name+".observations", true, false, false, false, nil)
	if e != nil {
		return e
	}
	if e = ch.Qos(500, 0, false); e != nil {
		return e
	}
	deliveries, e := ch.Consume(queue.Name, "go-sysmonitor", false, false, false, false, nil)
	if e != nil {
		return e
	}
	applied := map[string]bool{}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	a.broker.amqpConnected.Store(true)
	defer a.broker.amqpConnected.Store(false)
	for {
		desired := a.desiredBindings()
		for key := range desired {
			if !applied[key] {
				if e = ch.QueueBind(queue.Name, key, "arrowhead", false, nil); e != nil {
					return e
				}
			}
		}
		for key := range applied {
			if !desired[key] {
				if e = ch.QueueUnbind(queue.Name, key, "arrowhead", nil); e != nil {
					return e
				}
			}
		}
		applied = desired
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		case delivery, ok := <-deliveries:
			if !ok {
				return errors.New("AMQP intake closed")
			}
			if e = a.ingestBatch(delivery, deliveries); e != nil {
				return e
			}
		}
	}
}

// ingestBatch validates up to 500 deliveries (collected for at most 500 ms) and commits the valid ones in one
// store transaction, so the state snapshot is written once per batch instead of once per observation. Invalid
// messages are rejected individually; a storage failure requeues the whole batch.
func (a *App) ingestBatch(first amqp.Delivery, deliveries <-chan amqp.Delivery) error {
	batch := []amqp.Delivery{first}
	deadline := time.After(500 * time.Millisecond)
collect:
	for len(batch) < 500 {
		select {
		case d, ok := <-deliveries:
			if !ok {
				break collect
			}
			batch = append(batch, d)
		case <-deadline:
			break collect
		}
	}
	accepted := []amqp.Delivery{}
	records := []Document{}
	subs, offers := a.monitorLookup()
	for _, delivery := range batch {
		var body Document
		if len(delivery.Body) > 1<<20 || json.Unmarshal(delivery.Body, &body) != nil {
			_ = delivery.Reject(false)
			continue
		}
		record, e := a.prepareObservation(delivery.RoutingKey, body, subs, offers)
		if e != nil {
			var ae *APIError
			if errors.As(e, &ae) && ae.Status < 500 {
				_ = delivery.Reject(false)
				continue
			}
			for _, d := range batch {
				_ = d.Nack(false, true)
			}
			return e
		}
		accepted = append(accepted, delivery)
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil
	}
	e := a.Store.UpdateTables(func(d database) error {
		providers := map[string]bool{}
		for _, record := range records {
			if e := a.storeObservation(d, record); e != nil {
				return e
			}
			providers[str(record, "providerSystem")] = true
		}
		a.capObservations(d, providers)
		return nil
	}, "observations", "outbox")
	if e != nil {
		for _, d := range accepted {
			_ = d.Nack(false, true)
		}
		return e
	}
	for _, d := range accepted {
		_ = d.Ack(false)
	}
	return nil
}
func (a *App) mqttOutput(ctx context.Context) {
	if a.Config.MQTTURL == "" {
		return
	}
	u, e := url.Parse(a.Config.MQTTURL)
	if e != nil || u.Scheme != "ssl" || u.Host == "" || u.User != nil {
		a.recordLog("ERROR", "MQTT URL must use ssl without embedded credentials")
		return
	}
	options := mqtt.NewClientOptions().AddBroker(u.String()).SetClientID(a.Config.Name + "-go-" + uuid()).SetTLSConfig(a.brokerTLS()).SetConnectTimeout(5 * time.Second).SetWriteTimeout(5 * time.Second).SetAutoReconnect(false)
	client := mqtt.NewClient(options)
	defer client.Disconnect(250)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			a.broker.mqttConnected.Store(false)
			return
		case <-ticker.C:
		}
		if !client.IsConnected() {
			token := client.Connect()
			if !token.WaitTimeout(5*time.Second) || token.Error() != nil {
				a.broker.mqttConnected.Store(false)
				continue
			}
		}
		a.broker.mqttConnected.Store(true)
		n := 0
		sent := []string{}
		jobs := a.Store.Select("outbox", func(job Document) bool {
			if n >= 500 || str(job, "kind") != "observation" {
				return false
			}
			n++
			return true
		})
		// jobs carry only the observation id (older ones still embed the payload)
		pending := map[string]bool{}
		for _, job := range jobs {
			if job["payload"] == nil {
				pending[str(job, "id")] = true
			}
		}
		stored := map[string]Document{}
		if len(pending) > 0 {
			for _, row := range a.Store.Select("observations", func(row Document) bool { return pending[str(row, "observationId")] }) {
				stored[str(row, "observationId")] = row
			}
		}
		type publication struct {
			id    string
			token mqtt.Token
		}
		published := []publication{}
		for _, job := range jobs {
			id := str(job, "id")
			payload := obj(job, "payload")
			if job["payload"] == nil {
				if payload = stored[id]; payload == nil {
					sent = append(sent, id) // observation no longer stored: nothing to forward
					continue
				}
			}
			payload["publishedTime"] = now()
			body, e := json.Marshal(payload)
			if e != nil {
				continue
			}
			topic := "arrowhead/" + strings.Split(a.Config.CloudSuffix, ".")[0] + "/sysmonitor/data/" + str(payload, "observationType") + "/" + str(payload, "providerSystem")
			published = append(published, publication{id, client.Publish(topic, 1, false, body)})
		}
		for _, p := range published {
			if p.token.WaitTimeout(5*time.Second) && p.token.Error() == nil {
				sent = append(sent, p.id)
			}
		}
		// one store transaction per forwarding pass (an id is removed only after the broker acknowledged it)
		if len(sent) > 0 {
			_ = a.Store.UpdateTables(func(d database) error {
				for _, id := range sent {
					delete(d["outbox"], id)
				}
				return nil
			}, "outbox")
		}
	}
}
func (a *App) RunBackground(ctx context.Context) error {
	if a.Config.Role == "CertificateAuthority" {
		if _, _, e := a.caSigner(); e != nil {
			return e
		}
		if e := a.publishCRL(); e != nil {
			return e
		}
	}
	if e := a.startFederation(ctx); e != nil {
		return e
	}
	start := func(fn func()) { a.background.Add(1); go func() { defer a.background.Done(); fn() }() }
	if a.Config.Role == "TranslationManager" {
		start(func() { a.runTranslationCleaner(ctx) })
	}
	if a.Config.Role == "TestTranslation" && a.Config.MQTTURL != "" {
		start(func() { a.runTestTranslationMQTT(ctx) })
	}
	if a.Config.Role == "DeviceQoSEvaluator" && a.Config.QoSMeasurement {
		start(func() { a.runQoSMeasurement(ctx) })
	}
	if a.Config.Role == "PlantDescriptionEngine" && a.Config.Upstreams["DynamicServiceOrchestration"] != "" {
		start(func() { a.runPlantSync(ctx) })
	}
	if a.Config.Role == "AIGym" && a.Config.Upstreams["ServiceOrchestration"] != "" {
		start(func() { a.runAIGymSubscriber(ctx) })
	}
	if a.Config.Role == "CertificateAuthority" && a.Config.CRLExportFile != "" {
		start(func() {
			ticker := time.NewTicker(24 * time.Hour)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					a.revoked()
				}
			}
		})
	}
	if a.Config.Role == "SysMonitor" {
		if a.Config.AMQPURL != "" {
			start(func() {
				for {
					if ctx.Err() != nil {
						return
					}
					_ = a.consumeMonitoring(ctx)
					select {
					case <-ctx.Done():
						return
					case <-time.After(3 * time.Second):
					}
				}
			})
		}
		start(func() { a.mqttOutput(ctx) })
	}
	start(func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		iteration := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			iteration++
			switch a.Config.Role {
			case "EventHandler":
				a.deliverEvents(ctx)
			case "Choreographer":
				a.dispatchChoreography(ctx)
			case "SysMonitor":
				if iteration%15 == 1 {
					if e := a.reconcileMonitor(ctx); e != nil {
						a.recordLog("WARN", "Monitoring orchestration failed")
					}
				}
			}
			if iteration%15 == 1 && a.Config.MonitorEnabled {
				deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
				if e := a.publishNative(deadline); e != nil {
					a.recordLog("WARN", "Native monitoring publication failed")
				}
				cancel()
			}
			if iteration%1800 == 1 {
				a.prune()
			}
			if a.Config.Register && iteration%15 == 1 {
				e := a.Register(ctx)
				a.setRegistration(e)
				if e != nil {
					a.recordLog("WARN", "Service registration failed")
				}
			}
		}
	})
	return nil
}
func (a *App) prune() {
	days := a.Config.RetentionDays
	if days < 1 {
		days = 30
	}
	cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	// deletes only, so the large tables are not deep-copied
	_ = a.Store.UpdateTables(func(d database) error {
		for key, row := range d["observations"] {
			t, e := time.Parse(time.RFC3339Nano, str(row, "receivedTime"))
			if e == nil && t.Before(cutoff) && d["outbox"][key] == nil {
				delete(d["observations"], key)
			}
		}
		if a.Config.Role == "SysMonitor" {
			a.capObservations(d, nil)
		}
		for key, row := range d["senml"] {
			t, e := time.Parse(time.RFC3339Nano, str(row, "receivedAt"))
			if e == nil && t.Before(cutoff) {
				delete(d["senml"], key)
			}
		}
		return nil
	}, "observations", "outbox", "senml")
}
