// SPDX-License-Identifier: EPL-2.0
package core

// DeviceQoSEvaluator measurement engine (2026-10-17), as the Java MeasurementEngine and its jobs:
//   - every 30 s the registered systems (ServiceRegistry systems query, verbose) are grouped into devices by shared
//     addresses; a device is "augmented" when one of its systems has metadata qos.deviceAugmented=true;
//   - every 15 s the RTT of each device is measured: 9 TCP connections to a random closed high port, the time to the
//     refusal (an open port is replaced by another one, a timeout gives no values);
//   - augmented devices are asked for CPU/memory/network load by GET http://<device>:59473/device-qos?batch=15;
//   - min/max/mean/median/current are stored per metric group (RTT, CPU_TOTAL_LOAD, MEMORY_USED,
//     NETWORK_EGRESS_LOAD, NETWORK_INGRESS_LOAD) for every system of the device, value = mean; raw data older than
//     15 minutes is removed. The measurements feed the existing quality evaluation.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strconv"
	"syscall"
	"time"
)

const (
	qosAugmentedPort = 59473
	qosRttProbes     = 9
	qosRttTimeout    = 5 * time.Second
	qosRawMaxAge     = 15 * time.Minute
)

var qosAugmentedGroups = map[string]string{"1.4": "CPU_TOTAL_LOAD", "2.1": "MEMORY_USED", "3.1": "NETWORK_EGRESS_LOAD", "3.2": "NETWORK_INGRESS_LOAD"}

type qosDevice struct {
	Address   string
	Systems   []string
	Augmented bool
}

type qosAddress struct {
	value, kind   string
	deviceRelated bool
}

// qosDevices groups systems into devices: systems sharing an address are on the same device (the device keeps the
// addresses common to its systems, as in Java).
func qosDevices(systems []Document) []qosDevice {
	type group struct {
		addresses map[string]qosAddress
		systems   []string
		augmented bool
	}
	groups := []*group{}
	for _, s := range systems {
		addresses := map[string]qosAddress{}
		for _, v := range list(obj(s, "device"), "addresses") {
			if a, ok := v.(map[string]any); ok && str(a, "type") != "MAC" {
				addresses[str(a, "address")] = qosAddress{str(a, "address"), str(a, "type"), true}
			}
		}
		for _, v := range list(s, "addresses") {
			if a, ok := v.(map[string]any); ok && str(a, "type") != "MAC" {
				if _, seen := addresses[str(a, "address")]; !seen {
					addresses[str(a, "address")] = qosAddress{str(a, "address"), str(a, "type"), false}
				}
			}
		}
		if len(addresses) == 0 {
			continue
		}
		var into *group
		for _, g := range groups {
			for k := range addresses {
				if _, ok := g.addresses[k]; ok {
					into = g
				}
			}
		}
		if into == nil {
			into = &group{addresses: addresses}
			groups = append(groups, into)
		} else {
			for k := range into.addresses {
				if _, ok := addresses[k]; !ok {
					delete(into.addresses, k)
				}
			}
		}
		into.systems = append(into.systems, str(s, "name"))
		if v := obj(obj(s, "metadata"), "qos")["deviceAugmented"]; v == true || v == "true" {
			into.augmented = true
		}
	}
	out := []qosDevice{}
	for _, g := range groups {
		if address := selectQoSAddress(g.addresses); address != "" {
			sort.Strings(g.systems)
			out = append(out, qosDevice{address, g.systems, g.augmented})
		}
	}
	return out
}

// selectQoSAddress prefers a device-related IP address, then any IP address, then a host name.
func selectQoSAddress(addresses map[string]qosAddress) string {
	keys := []string{}
	for k := range addresses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	best, rank := "", -1
	for _, k := range keys {
		a := addresses[k]
		r := 0
		if a.kind != "HOSTNAME" {
			r = 1
			if a.deviceRelated {
				r = 2
			}
		}
		if r > rank {
			best, rank = a.value, r
		}
	}
	return best
}

// qosRTT measures the time to a refused connection; nil when no closed port is found, error on timeout.
func qosRTT(ctx context.Context, address string, port int) (time.Duration, bool, error) {
	d := net.Dialer{Timeout: qosRttTimeout}
	start := time.Now()
	c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(port)))
	elapsed := time.Since(start)
	if e == nil {
		_ = c.Close()
		return 0, false, nil // port open: not usable for an RTT probe
	}
	if errors.Is(e, syscall.ECONNREFUSED) {
		return elapsed, true, nil
	}
	return 0, false, e
}

func qosStats(values []float64) Document {
	sorted := append([]float64{}, values...)
	sort.Float64s(sorted)
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	n := len(sorted)
	median := sorted[n/2]
	if n%2 == 0 {
		median = (sorted[n/2-1] + sorted[n/2]) / 2
	}
	return Document{"minimum": sorted[0], "maximum": sorted[n-1], "mean": sum / float64(n), "median": median, "current": values[n-1], "value": sum / float64(n)}
}

func (a *App) measureDevice(ctx context.Context, dev qosDevice, ports map[string]int) []Document {
	stats := map[string]Document{}
	port := ports[dev.Address]
	values := []float64{}
	for i := 0; i < qosRttProbes; i++ {
		var rtt time.Duration
		ok := false
		for attempt := 0; attempt < 5 && !ok; attempt++ {
			if port == 0 {
				port = 49152 + rand.Intn(65535-49152+1)
				if port == qosAugmentedPort {
					port++
				}
			}
			var e error
			rtt, ok, e = qosRTT(ctx, dev.Address, port)
			if e != nil {
				values = nil
				break
			}
			if !ok {
				port = 0
			}
		}
		if values == nil || !ok {
			values = nil
			break
		}
		values = append(values, float64(rtt.Microseconds())/1000)
	}
	ports[dev.Address] = port
	if len(values) == qosRttProbes {
		stats["RTT"] = qosStats(values)
	}
	if dev.Augmented {
		for group, v := range a.fetchAugmented(ctx, dev.Address) {
			stats[group] = qosStats(v)
		}
	}
	rows := []Document{}
	ts := now()
	for group, s := range stats {
		for _, system := range dev.Systems {
			row := Document{"systemName": system, "metricGroup": group, "timestamp": ts, "deviceAddress": dev.Address, "source": "DeviceQoSEvaluator"}
			for k, v := range s {
				row[k] = v
			}
			rows = append(rows, row)
		}
	}
	return rows
}

// fetchAugmented reads the device agent's load measurements (plain HTTP on the device, as the Java engine).
func (a *App) fetchAugmented(ctx context.Context, address string) map[string][]float64 {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "GET", "http://"+net.JoinHostPort(address, strconv.Itoa(qosAugmentedPort))+"/device-qos?batch=15", nil)
	if e != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	res, e := http.DefaultClient.Do(req)
	if e != nil {
		return nil
	}
	defer res.Body.Close()
	var raw map[string][]float64
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&raw) != nil {
		return nil
	}
	out := map[string][]float64{}
	for oid, group := range qosAugmentedGroups {
		if v := raw[oid]; len(v) > 0 {
			out[group] = v
		}
	}
	return out
}

func (a *App) runQoSMeasurement(ctx context.Context) {
	var devices []qosDevice
	ports := map[string]int{}
	organized := time.Time{}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if time.Since(organized) >= 30*time.Second {
			var list Document
			if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/mgmt/systems/query?verbose=true", Document{"pagination": Document{"page": 0, "size": 1000}}, &list); e == nil {
				systems := []Document{}
				for _, v := range listOf(list, "entries") {
					systems = append(systems, v)
				}
				devices, organized = qosDevices(systems), time.Now()
			} else {
				a.recordLog("WARN", "Device discovery failed")
			}
		}
		rows := []Document{}
		for _, dev := range devices {
			rows = append(rows, a.measureDevice(ctx, dev, ports)...)
		}
		cutoff := time.Now().Add(-qosRawMaxAge)
		_ = a.Store.Update(func(d database) error {
			for _, row := range rows {
				bucket(d, "measurements")[uuid()] = row
			}
			for key, row := range d["measurements"] {
				if t, e := time.Parse(time.RFC3339Nano, str(row, "timestamp")); e == nil && t.Before(cutoff) && str(row, "source") == "DeviceQoSEvaluator" {
					delete(d["measurements"], key)
				}
			}
			bucket(d, "qosDevices")["state"] = Document{"devices": len(devices), "measuredAt": now()}
			return nil
		})
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func listOf(d Document, k string) []Document {
	out := []Document{}
	for _, v := range list(d, k) {
		if m, ok := v.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
