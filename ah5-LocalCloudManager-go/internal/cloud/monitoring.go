package cloud

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

var observationTypes = []string{"echo", "power", "status"}

func (a *App) monitoringRegistration() map[string]any {
	port, _ := strconv.Atoi(env("AMQP_PORT", "5671"))
	return map[string]any{"serviceDefinitionName": "sysMonitor", "version": "1.0.0", "expiresAt": nil, "metadata": map[string]any{"contract": "SysMonitor-AMQP-IDD-5.2.2", "schemaVersion": "1.0", "publisherMode": "native", "observationTypes": observationTypes, "delivery": "persistent, publisher-confirmed"}, "interfaces": []any{map[string]any{"templateName": "generic_amqps", "protocol": "amqps", "policy": "CERT_AUTH", "properties": map[string]any{"accessAddresses": []string{env("AMQP_HOST", "amqp-broker")}, "accessPort": port, "exchange": "arrowhead", "baseRoutingKey": a.Config.Cloud + ".sysmonitor." + a.Config.SystemName + "." + a.Config.SystemName, "operations": observationTypes}}}}
}
func (a *App) monitoringLoop(ctx context.Context) {
	var conn *amqp.Connection
	var ch *amqp.Channel
	sequence := int64(0)
	started := time.Now()
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		err := func() error {
			if conn == nil || conn.IsClosed() {
				tlsConfig := a.tlsConfig.Clone()
				tlsConfig.ClientAuth = tls.NoClientCert
				host := env("AMQP_HOST", "amqp-broker")
				tlsConfig.ServerName = host
				var err error
				conn, err = amqp.DialConfig("amqps://"+net.JoinHostPort(host, env("AMQP_PORT", "5671"))+"/", amqp.Config{SASL: []amqp.Authentication{&amqp.ExternalAuth{}}, TLSClientConfig: tlsConfig, Heartbeat: 30 * time.Second, Properties: amqp.Table{"connection_name": a.Config.SystemName + "-go-sysMonitor"}, Dial: amqp.DefaultDial(10 * time.Second)})
				if err != nil {
					return err
				}
				ch, err = conn.Channel()
				if err != nil {
					return err
				}
				if err = ch.Confirm(false); err != nil {
					return err
				}
			}
			health, quality, status := "healthy", "good", "alive"
			if a.federation != nil && !a.federation.client.IsConnectionOpen() {
				health, quality, status = "degraded", "uncertain", "degraded"
			}
			values := []map[string]any{{"status": status, "uptimeSeconds": int(time.Since(started).Seconds()), "detail": a.Config.SystemName + " is running"}, {"supplyType": "line", "state": "available"}, {"state": "running", "health": health, "serviceCount": len(roleSpecs[a.Config.Role].Services)}}
			for i, kind := range observationTypes {
				sequence++
				now := time.Now()
				id := fmt.Sprintf("%s-%s-%d-%d", a.Config.SystemName, kind, now.UnixMilli(), sequence)
				observation := map[string]any{"schemaVersion": "1.0", "observationId": id, "providerSystem": a.Config.SystemName, "serviceInstance": a.Config.SystemName, "observationType": kind, "sourceTime": now.UTC().Format("2006-01-02T15:04:05.000Z"), "sequence": sequence, "value": values[i], "quality": quality, "metadata": map[string]any{"publisherMode": "native", "implementation": "go"}}
				if kind != "echo" {
					observation["unit"] = "1"
				}
				data, _ := json.Marshal(observation)
				deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
				confirmation, err := ch.PublishWithDeferredConfirmWithContext(deadline, "arrowhead", a.Config.Cloud+".sysmonitor."+a.Config.SystemName+"."+a.Config.SystemName+"."+kind, false, false, amqp.Publishing{ContentType: "application/json", DeliveryMode: amqp.Persistent, MessageId: id, Timestamp: now, Body: data})
				if err == nil {
					var ack bool
					ack, err = confirmation.WaitContext(deadline)
					if err == nil && !ack {
						err = errors.New("broker rejected observation")
					}
				}
				cancel()
				if err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			log.Printf("native sysMonitor publication failed: %v", err)
			if conn != nil {
				_ = conn.Close()
			}
			conn, ch = nil, nil
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
