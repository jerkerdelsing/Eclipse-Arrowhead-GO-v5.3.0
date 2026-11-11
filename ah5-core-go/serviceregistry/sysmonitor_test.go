package main

import (
	"testing"
	"time"
)

func TestSysMonitorRegistrationAndObservations(t *testing.T) {
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	props["authentication.policy"] = "declared"
	cfg, err := NewConfig(props)
	if err != nil {
		t.Fatal(err)
	}
	cfg.SysMonitorBrokerAddress, cfg.SysMonitorBrokerPort, cfg.SysMonitorLocalCloud = "amqp-broker", 5671, "TestCloud"
	p := newSysMonitorPublisher(cfg, nil)

	req, err := p.serviceRequest()
	if err != nil {
		t.Fatal(err)
	}
	if req.ServiceDefinitionName != "sysMonitor" || req.Metadata["publisherMode"] != "native" {
		t.Fatalf("unexpected registration %+v", req)
	}
	if p.routingKey != "TestCloud.sysmonitor.ServiceRegistry.ServiceRegistry" {
		t.Fatalf("unexpected routing key %s", p.routingKey)
	}
	if props := req.Interfaces[0].Properties; req.Interfaces[0].TemplateName != "generic_amqps" || props["exchange"] != "arrowhead" {
		t.Fatalf("unexpected interface %+v", req.Interfaces[0])
	}

	obs := p.observations(time.Date(2026, 10, 11, 10, 0, 0, 250e6, time.UTC))
	if len(obs) != 3 || obs[0]["observationType"] != "echo" || obs[2]["observationType"] != "status" {
		t.Fatalf("unexpected observations %v", obs)
	}
	if obs[0]["sourceTime"] != "2026-10-11T10:00:00.250Z" || obs[0]["value"].(map[string]any)["status"] != "alive" {
		t.Fatalf("unexpected echo %v", obs[0])
	}
	if obs[1]["unit"] != "1" || obs[2]["sequence"].(int64) != 3 {
		t.Fatalf("unexpected power/status %v %v", obs[1], obs[2])
	}
}
