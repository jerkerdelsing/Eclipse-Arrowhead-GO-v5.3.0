// Native sysMonitor publisher (SysMonitor-AMQP-IDD-5.2.2): the ServiceRegistry publishes echo, power and
// status observations about itself over AMQP 0-9-1 with mutual TLS. The broker authenticates the client
// certificate (SASL EXTERNAL); every message is persistent and confirmed by the broker.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

var sysMonitorTypes = []string{"echo", "power", "status"}

type sysMonitorPublisher struct {
	cfg        *Config
	rg         *Registry
	routingKey string
	started    time.Time
	sequence   int64

	mu      sync.Mutex
	conn    *amqp.Connection
	channel *amqp.Channel
}

func newSysMonitorPublisher(cfg *Config, rg *Registry) *sysMonitorPublisher {
	return &sysMonitorPublisher{
		cfg:        cfg,
		rg:         rg,
		routingKey: fmt.Sprintf("%s.sysmonitor.%s.%s", cfg.SysMonitorLocalCloud, systemName, systemName),
		started:    time.Now(),
	}
}

// serviceRequest is the registration of the native sysMonitor offer of the ServiceRegistry.
func (p *sysMonitorPublisher) serviceRequest() (*InstanceReq, error) {
	req := map[string]any{
		"systemName":            systemName,
		"serviceDefinitionName": "sysMonitor",
		"version":               serviceVersion,
		"metadata": map[string]any{
			"contract": "SysMonitor-AMQP-IDD-5.2.2", "schemaVersion": "1.0", "publisherMode": "native",
			"observationTypes": sysMonitorTypes, "delivery": "persistent, publisher-confirmed",
		},
		"interfaces": []any{map[string]any{
			"templateName": "generic_amqps",
			"protocol":     "amqps",
			"policy":       "CERT_AUTH",
			"properties": map[string]any{
				"accessAddresses": []any{p.cfg.SysMonitorBrokerAddress},
				"accessPort":      p.cfg.SysMonitorBrokerPort,
				"exchange":        p.cfg.SysMonitorExchange,
				"baseRoutingKey":  p.routingKey,
				"operations":      sysMonitorTypes,
			},
		}},
	}
	data, _ := json.Marshal(req)
	var out InstanceReq
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (p *sysMonitorPublisher) observation(kind string, value map[string]any, unit, quality string, now time.Time) map[string]any {
	p.sequence++
	obs := map[string]any{
		"schemaVersion":   "1.0",
		"observationId":   fmt.Sprintf("%s-%s-%d-%d", systemName, kind, now.UnixMilli(), p.sequence),
		"providerSystem":  systemName,
		"serviceInstance": systemName,
		"observationType": kind,
		"sourceTime":      now.UTC().Format("2006-01-02T15:04:05.000Z"),
		"sequence":        p.sequence,
		"value":           value,
		"quality":         quality,
		"metadata":        map[string]any{"publisherMode": "native"},
	}
	if unit != "" {
		obs["unit"] = unit
	}
	return obs
}

// observations builds echo, power and status; liveness is degraded when the snapshot file is not writable.
func (p *sysMonitorPublisher) observations(now time.Time) []map[string]any {
	healthy, detail := true, systemName+" is running"
	if p.cfg.DataFile != "" {
		if f, err := os.OpenFile(p.cfg.DataFile, os.O_WRONLY|os.O_CREATE, 0o644); err != nil {
			healthy, detail = false, "registry snapshot not writable: "+err.Error()
		} else {
			f.Close()
		}
	}
	quality, status, health := "good", "alive", "healthy"
	if !healthy {
		quality, status, health = "uncertain", "degraded", "degraded"
	}
	return []map[string]any{
		p.observation("echo", map[string]any{"status": status, "uptimeSeconds": int64(now.Sub(p.started).Seconds()), "detail": detail}, "", quality, now),
		p.observation("power", map[string]any{"supplyType": "line", "state": "available"}, "1", "good", now),
		p.observation("status", map[string]any{"state": "running", "health": health, "serviceCount": len(selfServices()) + 1}, "1", quality, now),
	}
}

// ---- AMQP 0-9-1 client ----

func (p *sysMonitorPublisher) connect() error {
	cert, err := tls.LoadX509KeyPair(p.cfg.SysMonitorCertFile, p.cfg.SysMonitorKeyFile)
	if err != nil {
		return fmt.Errorf("sysMonitor client certificate: %w", err)
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(p.cfg.SysMonitorCAFile)
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		return fmt.Errorf("sysMonitor CA bundle %s unusable", p.cfg.SysMonitorCAFile)
	}
	addr := net.JoinHostPort(p.cfg.SysMonitorBrokerAddress, strconv.Itoa(p.cfg.SysMonitorBrokerPort))
	conn, err := amqp.DialConfig("amqps://"+addr+"/", amqp.Config{
		SASL:            []amqp.Authentication{&amqp.ExternalAuth{}},
		TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: p.cfg.SysMonitorBrokerAddress, MinVersion: tls.VersionTLS12},
		Heartbeat:       30 * time.Second,
		Properties:      amqp.Table{"connection_name": systemName + "-sysMonitor"},
		Dial:            amqp.DefaultDial(10 * time.Second),
	})
	if err != nil {
		return err
	}
	channel, err := conn.Channel()
	if err == nil {
		err = channel.Confirm(false)
	}
	if err != nil {
		conn.Close()
		return err
	}
	p.conn, p.channel = conn, channel
	return nil
}

func (p *sysMonitorPublisher) publishOnce() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil || p.conn.IsClosed() {
		p.closeLocked()
		if err := p.connect(); err != nil {
			p.closeLocked()
			return err
		}
	}
	for _, obs := range p.observations(time.Now()) {
		payload, _ := json.Marshal(obs)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		confirm, err := p.channel.PublishWithDeferredConfirmWithContext(ctx, p.cfg.SysMonitorExchange,
			p.routingKey+"."+obs["observationType"].(string), false, false, amqp.Publishing{
				ContentType: "application/json", DeliveryMode: amqp.Persistent, MessageId: obs["observationId"].(string),
				Timestamp: time.Now(), Body: payload,
			})
		if err == nil {
			var acked bool
			if acked, err = confirm.WaitContext(ctx); err == nil && !acked {
				err = errors.New("broker refused the observation")
			}
		}
		cancel()
		if err != nil {
			p.closeLocked()
			return err
		}
	}
	return nil
}

func (p *sysMonitorPublisher) closeLocked() {
	if p.conn != nil {
		p.conn.Close()
	}
	p.conn, p.channel = nil, nil
}

func (p *sysMonitorPublisher) run(stop <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(p.cfg.SysMonitorInterval) * time.Second)
	defer ticker.Stop()
	for {
		if err := p.publishOnce(); err != nil {
			p.rg.log.Warnf("sysmonitor", "sysMonitor publication failed: %v", err)
		}
		select {
		case <-stop:
			p.mu.Lock()
			p.closeLocked()
			p.mu.Unlock()
			return
		case <-ticker.C:
		}
	}
}
