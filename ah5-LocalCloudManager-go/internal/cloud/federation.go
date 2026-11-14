package cloud

// Compatibility transport for the deployed Arrowhead relay protocol. Local HTTP
// and MQTT hops use separate mutual-TLS identities. This profile deliberately
// does not claim AH-GT-1 end-to-end encryption, which requires peer migration.
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

type relayWaiter struct {
	peer string
	ch   chan map[string]any
}
type relayCache struct {
	value   map[string]any
	expires time.Time
}
type tunnelSession struct {
	ID, Consumer, ConsumerCloud, Provider, ProviderCloud, Definition, Peer string
	Target                                                                 map[string]any
	Created, LastUsed                                                      time.Time
	Requests                                                               int
	Port                                                                   int
	Server                                                                 *http.Server
}

type Federation struct {
	app                  *App
	client               mqtt.Client
	mu                   sync.Mutex
	pending              map[string]relayWaiter
	responses            map[string]relayCache
	inflight             map[string]bool
	providers, consumers map[string]*tunnelSession
	slots                chan struct{}
	stop                 chan struct{}
}

func newFederation(a *App) (*Federation, error) {
	if !a.Config.Secure {
		return nil, errors.New("federation requires mutual TLS")
	}
	if env("FEDERATION_PROFILE", "disabled") != "legacy-mtls" {
		return nil, errors.New("FEDERATION_PROFILE must explicitly select legacy-mtls for current relay compatibility; AH-GT-1 peer migration remains separate")
	}
	f := &Federation{app: a, pending: map[string]relayWaiter{}, responses: map[string]relayCache{}, inflight: map[string]bool{}, providers: map[string]*tunnelSession{}, consumers: map[string]*tunnelSession{}, slots: make(chan struct{}, 64), stop: make(chan struct{})}
	tlsCfg, err := loadTLS(env("RELAY_CHAIN_CERT", "/certs/"+a.Config.Role+"-relay-chain.crt"), env("RELAY_KEY", "/certs/"+a.Config.Role+"-relay.key"), env("RELAY_CA_CERT", "/certs/org-ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("relay identity: %w", err)
	}
	options := mqtt.NewClientOptions().AddBroker("ssl://" + net.JoinHostPort(env("RELAY_HOST", "arrowhead-relay"), env("RELAY_PORT", "8883"))).SetClientID(a.commonName(a.Config.SystemName) + "-go-" + randomID()).SetTLSConfig(tlsCfg).SetProtocolVersion(4).SetKeepAlive(30 * time.Second).SetConnectTimeout(10 * time.Second).SetWriteTimeout(10 * time.Second).SetAutoReconnect(true).SetConnectRetry(true).SetOrderMatters(false)
	options.SetOnConnectHandler(func(c mqtt.Client) {
		t := c.Subscribe("arrowhead/relay/"+a.Config.Cloud+"/"+a.Config.Role+"/in/#", 1, f.receive)
		if !t.WaitTimeout(10*time.Second) || t.Error() != nil {
			log.Printf("relay inbox subscription failed")
		}
	})
	f.client = mqtt.NewClient(options)
	return f, nil
}

func (f *Federation) Start() error {
	f.client.Connect() // Paho reconnects asynchronously; health reports disconnected until ready.
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-f.stop:
				return
			case <-ticker.C:
				f.expire()
			}
		}
	}()
	return nil
}
func (f *Federation) Close() {
	close(f.stop)
	f.mu.Lock()
	for _, s := range f.consumers {
		if s.Server != nil {
			_ = s.Server.Close()
		}
	}
	f.mu.Unlock()
	f.client.Disconnect(500)
}
func (f *Federation) Status() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := []any{}
	for _, side := range []struct {
		name     string
		sessions map[string]*tunnelSession
	}{{"provider", f.providers}, {"consumer", f.consumers}} {
		for _, s := range side.sessions {
			list = append(list, map[string]any{"sessionId": s.ID, "side": side.name, "consumer": s.Consumer, "consumerCloud": s.ConsumerCloud, "provider": s.Provider, "providerCloud": s.ProviderCloud, "serviceDefinition": s.Definition, "requests": s.Requests, "createdAt": float64(s.Created.Unix()), "state": "ACTIVE", "tunnelPort": s.Port})
		}
	}
	return map[string]any{"status": "ok", "system": f.app.Config.SystemName, "version": "5.4.0", "implementation": "go", "x509": true, "relay": map[string]any{"connected": f.client.IsConnectionOpen(), "broker": env("RELAY_HOST", "arrowhead-relay") + ":" + env("RELAY_PORT", "8883"), "profile": "legacy-mtls", "endToEndEncrypted": false}, "interCloud": map[string]any{"providerSessions": len(f.providers), "consumerSessions": len(f.consumers), "sessions": list}}
}
func (f *Federation) expire() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, sessions := range []map[string]*tunnelSession{f.providers, f.consumers} {
		for id, s := range sessions {
			if time.Since(s.Created) > 12*time.Hour || time.Since(s.LastUsed) > time.Hour {
				if s.Server != nil {
					_ = s.Server.Close()
				}
				delete(sessions, id)
			}
		}
	}
	for id, c := range f.responses {
		if time.Now().After(c.expires) {
			delete(f.responses, id)
		}
	}
}

func (f *Federation) peerCN(role, cloud string) string {
	return role + "." + cloud + "." + f.app.Config.Organization + ".arrowhead.eu"
}
func (f *Federation) trustedPeer(cn string) bool {
	parts := strings.Split(cn, ".")
	wanted := "Gatekeeper"
	if f.app.Config.Role == "gatetunnel" {
		wanted = "GateTunnel"
	}
	if len(parts) != 5 || cn != f.peerCN(wanted, parts[1]) || parts[1] == f.app.Config.Cloud {
		return false
	}
	for _, cloud := range csv(env("NEIGHBOR_CLOUDS", "")) {
		if cloud == parts[1] {
			return true
		}
	}
	// Gatekeeper's management data is authoritative for configured neighbours.
	f.app.Store.mu.RLock()
	defer f.app.Store.mu.RUnlock()
	for _, r := range f.app.Store.Data.Resources {
		if r.Kind == "federation-cloud" && mapString(r.Payload["name"]) == parts[1] && mapString(r.Payload["operator"]) == f.app.Config.Organization {
			return true
		}
	}
	return false
}
func (f *Federation) send(cloud string, value map[string]any) error {
	if strings.ContainsAny(cloud, "/+#|.") || cloud == "" {
		return errors.New("invalid relay target cloud")
	}
	if !f.client.IsConnectionOpen() {
		return errors.New("relay is disconnected")
	}
	if mapString(value["id"]) == "" {
		value["id"] = randomID()
	}
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(b) > 2<<20 {
		return errors.New("relay message too large")
	}
	t := f.client.Publish("arrowhead/relay/"+cloud+"/"+f.app.Config.Role+"/in/"+f.app.commonName(f.app.Config.SystemName)+"/"+mapString(value["id"]), 1, false, b)
	if !t.WaitTimeout(10 * time.Second) {
		return errors.New("relay publish timeout")
	}
	return t.Error()
}
func (f *Federation) request(cloud string, message map[string]any) (map[string]any, error) {
	role := "Gatekeeper"
	if f.app.Config.Role == "gatetunnel" {
		role = "GateTunnel"
	}
	peer := f.peerCN(role, cloud)
	if !f.trustedPeer(peer) {
		return nil, errors.New("cloud is not a configured federation neighbour")
	}
	id := randomID()
	waiter := relayWaiter{peer: peer, ch: make(chan map[string]any, 1)}
	f.mu.Lock()
	if len(f.pending) >= 128 {
		f.mu.Unlock()
		return nil, errors.New("too many pending relay requests")
	}
	f.pending[id] = waiter
	f.mu.Unlock()
	defer func() { f.mu.Lock(); delete(f.pending, id); f.mu.Unlock() }()
	message["correlationId"] = id
	if err := f.send(cloud, message); err != nil {
		return nil, err
	}
	select {
	case reply := <-waiter.ch:
		return reply, nil
	case <-time.After(15 * time.Second):
		return nil, errors.New("relay reply timeout")
	case <-f.stop:
		return nil, errors.New("relay stopped")
	}
}
func (f *Federation) reply(peer string, request, response map[string]any) {
	response["id"] = randomID()
	response["type"], response["correlationId"] = "reply", request["correlationId"]
	key := peer + "/" + mapString(request["id"])
	f.mu.Lock()
	f.responses[key] = relayCache{value: response, expires: time.Now().Add(2 * time.Minute)}
	delete(f.inflight, key)
	f.mu.Unlock()
	if err := f.send(strings.Split(peer, ".")[1], response); err != nil {
		log.Printf("relay reply failed: %v", err)
	}
}
func (f *Federation) receive(_ mqtt.Client, message mqtt.Message) {
	if message.Retained() || len(message.Payload()) > 2<<20 {
		return
	}
	parts := strings.Split(message.Topic(), "/")
	if len(parts) != 7 || parts[0] != "arrowhead" || parts[1] != "relay" || parts[2] != f.app.Config.Cloud || parts[3] != f.app.Config.Role || parts[4] != "in" || !f.trustedPeer(parts[5]) {
		return
	}
	var value map[string]any
	if json.Unmarshal(message.Payload(), &value) != nil || mapString(value["id"]) != parts[6] {
		return
	}
	peer := parts[5]
	if value["type"] == "reply" {
		f.mu.Lock()
		waiter, ok := f.pending[mapString(value["correlationId"])]
		f.mu.Unlock()
		if ok && waiter.peer == peer {
			value["senderCN"] = peer
			select {
			case waiter.ch <- value:
			default:
			}
		}
		return
	}
	key := peer + "/" + parts[6]
	f.mu.Lock()
	if cached, ok := f.responses[key]; ok && time.Now().Before(cached.expires) {
		f.mu.Unlock()
		_ = f.send(strings.Split(peer, ".")[1], cached.value)
		return
	}
	if f.inflight[key] || len(f.responses) >= 4096 {
		f.mu.Unlock()
		return
	}
	f.inflight[key] = true
	f.mu.Unlock()
	select {
	case f.slots <- struct{}{}:
	default:
		f.mu.Lock()
		delete(f.inflight, key)
		f.mu.Unlock()
		return
	}
	go func() {
		defer func() { <-f.slots; f.mu.Lock(); delete(f.inflight, key); f.mu.Unlock() }()
		var response map[string]any
		var err error
		if f.app.Config.Role == "gatekeeper" {
			response, err = f.handleGatekeeper(peer, value)
		} else {
			response, err = f.handleTunnel(peer, value)
		}
		if err != nil {
			log.Printf("relay %s from %s refused: %v", mapString(value["type"]), peer, err)
			response = map[string]any{"error": err.Error(), "accepted": false}
		}
		if response != nil {
			f.reply(peer, value, response)
		}
	}()
}

func (f *Federation) jsonCall(method, endpoint string, payload any) (map[string]any, error) {
	b, err := f.app.call(method, endpoint, payload, nil)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = json.Unmarshal(b, &out)
	return out, err
}
func (f *Federation) instances(def string) ([]any, error) {
	if def == "" {
		return nil, errors.New("serviceDefinition is required")
	}
	result, err := f.jsonCall("POST", f.app.Config.RegistryURL+"/serviceregistry/service-discovery/lookup", map[string]any{"serviceDefinitionNames": []string{def}, "interfaceTemplateNames": []string{"generic_https"}})
	if err != nil {
		return nil, err
	}
	out, _ := result["entries"].([]any)
	return out, nil
}
func httpsProperties(instance map[string]any) map[string]any {
	interfaces, _ := instance["interfaces"].([]any)
	for _, i := range interfaces {
		m := object(i)
		if m["templateName"] == "generic_https" && strings.EqualFold(mapString(m["protocol"]), "https") {
			return object(m["properties"])
		}
	}
	return nil
}
func (f *Federation) authorized(provider, consumer, cloud, definition string, operations []string) bool {
	if provider == "" || consumer == "" || definition == "" {
		return false
	}
	if len(operations) == 0 {
		operations = []string{""}
	}
	checks := []any{}
	for _, op := range operations {
		check := map[string]any{"provider": provider, "consumer": consumer, "cloud": cloud, "targetType": "SERVICE_DEF", "target": definition}
		if op != "" {
			check["scope"] = op
		}
		checks = append(checks, check)
	}
	result, err := f.jsonCall("POST", env("CONSUMER_AUTHORIZATION_URL", "https://consumerauthorization:8445")+"/consumerauthorization/authorization/mgmt/check", map[string]any{"list": checks})
	if err != nil {
		log.Printf("federation authorization check failed closed: %v", err)
		return false
	}
	entries, _ := result["entries"].([]any)
	if len(entries) != len(checks) {
		return false
	}
	for _, e := range entries {
		if object(e)["granted"] != true {
			return false
		}
	}
	return true
}
func (f *Federation) handleGatekeeper(peer string, m map[string]any) (map[string]any, error) {
	parts := strings.Split(peer, ".")
	cloud := parts[1] + "|" + parts[2]
	consumer := mapString(m["consumer"])
	if m["type"] == "gsd-request" {
		req := object(m["serviceRequirement"])
		def := mapString(req["serviceDefinition"])
		instances, err := f.instances(def)
		if err != nil {
			return nil, err
		}
		results := []any{}
		for _, raw := range instances {
			instance := object(raw)
			provider := mapString(object(instance["provider"])["name"])
			props := httpsProperties(instance)
			if props == nil {
				continue
			}
			ops := stringSlice(req["operations"])
			if len(ops) == 0 {
				ops = sortedKeys(object(props["operations"]))
			}
			if f.authorized(provider, consumer, cloud, def, ops) {
				results = append(results, map[string]any{"providerName": provider, "serviceDefinition": def, "version": instance["version"], "metadata": instance["metadata"], "operations": sortedKeys(object(props["operations"]))})
			}
		}
		return map[string]any{"cloud": f.app.Config.Cloud + "|" + f.app.Config.Organization, "results": results}, nil
	}
	if m["type"] != "icn-request" {
		return nil, errors.New("unknown relay request")
	}
	def, provider := mapString(m["serviceDefinition"]), mapString(m["providerName"])
	instances, err := f.instances(def)
	if err != nil {
		return nil, err
	}
	var instance, props map[string]any
	for _, raw := range instances {
		candidate := object(raw)
		if object(candidate["provider"])["name"] == provider {
			instance = candidate
			props = httpsProperties(candidate)
			if props != nil {
				break
			}
		}
	}
	if props == nil {
		return nil, errors.New("provider not found")
	}
	offered := object(props["operations"])
	ops := stringSlice(m["operations"])
	if len(ops) == 0 {
		ops = sortedKeys(offered)
	}
	if len(ops) == 0 {
		return nil, errors.New("provider offers no operation contracts")
	}
	negotiated := map[string]any{}
	for _, op := range ops {
		v, ok := offered[op]
		if !ok {
			return nil, errors.New("operation not offered")
		}
		negotiated[op] = v
	}
	if !f.authorized(provider, consumer, cloud, def, ops) {
		return nil, errors.New("not authorized by provider cloud")
	}
	addresses := stringSlice(props["accessAddresses"])
	if len(addresses) == 0 {
		return nil, errors.New("provider has no address")
	}
	session, err := f.jsonCall("POST", env("GATETUNNEL_URL", "https://gatetunnel:8453")+"/gatetunnel/intercloud/provider", map[string]any{"consumer": consumer, "consumerCloud": cloud, "provider": provider, "serviceDefinition": def, "peer": f.peerCN("GateTunnel", parts[1]), "target": map[string]any{"address": addresses[0], "port": props["accessPort"], "basePath": props["basePath"], "operations": negotiated}})
	if err != nil {
		return nil, err
	}
	return map[string]any{"accepted": true, "sessionId": session["sessionId"], "providerName": provider, "serviceDefinition": def, "version": instance["version"], "metadata": instance["metadata"], "basePath": props["basePath"], "operations": negotiated}, nil
}

func (f *Federation) GatekeeperHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	if !containsExact([]string{"LocalCloudManager", "Sysop", "DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "Gatekeeper"}, owner) {
		apiError(w, 403, "not a Gatekeeper client", r.URL.Path)
		return
	}
	if strings.Contains(r.URL.Path, "/mgmt/") {
		f.management(w, r, owner)
		return
	}
	var payload map[string]any
	if err := decode(r, &payload); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	consumer := mapString(payload["consumerSystem"])
	if consumer == "" {
		consumer = owner
	}
	if consumer != owner && !containsExact([]string{"DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "LocalCloudManager", "Sysop"}, owner) {
		apiError(w, 403, "caller cannot act for another consumer", r.URL.Path)
		return
	}
	if r.Method == "POST" && (r.URL.Path == "/gatekeeper/init_gsd" || r.URL.Path == "/gatekeeper/init_multi_gsd") {
		req := object(payload["serviceRequirement"])
		if len(req) == 0 {
			req = object(payload["requestedService"])
		}
		if mapString(req["serviceDefinition"]) == "" {
			apiError(w, 400, "serviceRequirement.serviceDefinition is required", r.URL.Path)
			return
		}
		targets, _ := payload["targetClouds"].([]any)
		if len(targets) == 0 {
			for _, cloud := range f.neighbors() {
				targets = append(targets, cloud)
			}
		}
		results := []any{}
		failed := 0
		for _, target := range targets {
			reply, err := f.request(targetName(target), map[string]any{"type": "gsd-request", "consumer": consumer, "serviceRequirement": req})
			if err != nil {
				failed++
				continue
			}
			entries, _ := reply["results"].([]any)
			for _, entry := range entries {
				item := object(entry)
				item["cloud"] = reply["cloud"]
				results = append(results, item)
			}
		}
		jsonOut(w, 200, map[string]any{"results": results, "unsuccessfulRequests": failed, "queriedClouds": len(targets)})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/gatekeeper/init_icn" {
		target := payload["targetCloud"]
		if target == nil {
			target = payload["providerCloud"]
		}
		cloud := targetName(target)
		if cloud == "" || mapString(payload["providerName"]) == "" || mapString(payload["serviceDefinition"]) == "" {
			apiError(w, 400, "targetCloud, providerName and serviceDefinition are required", r.URL.Path)
			return
		}
		reply, err := f.request(cloud, map[string]any{"type": "icn-request", "consumer": consumer, "providerName": payload["providerName"], "serviceDefinition": payload["serviceDefinition"], "operations": payload["operations"]})
		if err != nil {
			apiError(w, 502, err.Error(), r.URL.Path)
			return
		}
		if reply["accepted"] != true {
			jsonOut(w, 200, map[string]any{"negotiated": false, "targetCloud": target, "reason": reply["reason"], "error": reply["error"]})
			return
		}
		if reply["keyExchange"] != nil {
			apiError(w, 502, "peer requires AH-GT-1; legacy-mtls profile cannot downgrade it", r.URL.Path)
			return
		}
		providerCloud := cloud + "|" + f.app.Config.Organization
		tunnel, err := f.jsonCall("POST", env("GATETUNNEL_URL", "https://gatetunnel:8453")+"/gatetunnel/intercloud/consumer", map[string]any{"sessionId": reply["sessionId"], "consumer": consumer, "providerCloud": providerCloud, "provider": reply["providerName"], "serviceDefinition": reply["serviceDefinition"], "peer": f.peerCN("GateTunnel", cloud)})
		if err != nil {
			apiError(w, 502, err.Error(), r.URL.Path)
			return
		}
		jsonOut(w, 200, map[string]any{"negotiated": true, "providerCloud": providerCloud, "providerName": reply["providerName"], "serviceDefinition": reply["serviceDefinition"], "version": reply["version"], "metadata": reply["metadata"], "sessionId": reply["sessionId"], "interface": map[string]any{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": map[string]any{"accessAddresses": []any{tunnel["address"]}, "accessPort": tunnel["port"], "basePath": reply["basePath"], "operations": reply["operations"]}}})
		return
	}
	apiError(w, 404, "unknown Gatekeeper operation", r.URL.Path)
}
func targetName(v any) string {
	if s, ok := v.(string); ok {
		return strings.Split(s, "|")[0]
	}
	return mapString(object(v)["name"])
}
func containsExact(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
func (f *Federation) neighbors() []string {
	set := map[string]bool{}
	for _, n := range csv(env("NEIGHBOR_CLOUDS", "")) {
		set[n] = true
	}
	f.app.Store.mu.RLock()
	for _, v := range f.app.Store.Data.Resources {
		if v.Kind == "federation-cloud" && v.Payload["operator"] == f.app.Config.Organization {
			set[mapString(v.Payload["name"])] = true
		}
	}
	f.app.Store.mu.RUnlock()
	out := sortedKeys(set)
	return out
}
func (f *Federation) management(w http.ResponseWriter, r *http.Request, owner string) {
	if !containsExact([]string{"LocalCloudManager", "Sysop"}, owner) {
		apiError(w, 403, "management denied", r.URL.Path)
		return
	}
	kind := "federation-cloud"
	if strings.Contains(r.URL.Path, "/relays") {
		kind = "federation-relay"
	}
	if r.Method == "GET" {
		entries := []any{}
		f.app.Store.mu.RLock()
		for _, v := range f.app.Store.Data.Resources {
			if v.Kind == kind {
				entries = append(entries, v.Payload)
			}
		}
		f.app.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(entries))
		return
	}
	if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/gatekeeper/mgmt/clouds/") {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/gatekeeper/mgmt/clouds/"), "/")
		if len(parts) != 2 {
			apiError(w, 400, "operator and name required", r.URL.Path)
			return
		}
		f.app.Store.mu.Lock()
		delete(f.app.Store.Data.Resources, kind+"|"+parts[0]+"|"+parts[1])
		err := f.app.Store.SaveLocked()
		f.app.Store.mu.Unlock()
		if err != nil {
			apiError(w, 500, "save failed", r.URL.Path)
			return
		}
		jsonOut(w, 200, map[string]any{"removed": true})
		return
	}
	if r.Method != "POST" {
		apiError(w, 405, "method not allowed", r.URL.Path)
		return
	}
	var raw any
	if err := decode(r, &raw); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	values, ok := raw.([]any)
	if !ok {
		if list, ok := object(raw)["list"].([]any); ok {
			values = list
		} else {
			values = []any{raw}
		}
	}
	for _, v := range values {
		m := object(v)
		name := mapString(m["name"])
		if name == "" || strings.ContainsAny(name, "./|+#") {
			apiError(w, 400, "valid name required", r.URL.Path)
			return
		}
		if kind == "federation-cloud" && m["operator"] != f.app.Config.Organization {
			apiError(w, 400, "only organization peers are supported", r.URL.Path)
			return
		}
	}
	f.app.Store.mu.Lock()
	for _, v := range values {
		m := object(v)
		id := kind + "|" + mapString(m["operator"]) + "|" + mapString(m["name"])
		f.app.Store.Data.Resources[id] = Resource{ID: id, Kind: kind, Owner: owner, Payload: m, CreatedAt: now(), UpdatedAt: now()}
	}
	err := f.app.Store.SaveLocked()
	f.app.Store.mu.Unlock()
	if err != nil {
		apiError(w, 500, "save failed", r.URL.Path)
		return
	}
	jsonOut(w, 201, listResponse(values))
}

func operationAllowed(method, raw, base string, operations map[string]any) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || !strings.HasPrefix(u.Path, "/") || strings.ContainsAny(u.Path, "\\\x00") || strings.Contains(u.Path, "//") {
		return false
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	lower := strings.ToLower(u.EscapedPath())
	for _, encoded := range []string{"%2f", "%5c", "%2e", "%00", "%25"} {
		if strings.Contains(lower, encoded) {
			return false
		}
	}
	for _, value := range operations {
		op := object(value)
		if strings.ToUpper(mapString(op["method"])) != method {
			continue
		}
		prefix := strings.TrimRight(base, "/") + "/" + strings.Trim(mapString(op["path"]), "/")
		prefix = strings.TrimRight(prefix, "/")
		if prefix == "" {
			prefix = "/"
		}
		requestParts, templateParts := strings.Split(strings.Trim(u.Path, "/"), "/"), strings.Split(strings.Trim(prefix, "/"), "/")
		if len(requestParts) < len(templateParts) {
			continue
		}
		matched := true
		for i, part := range templateParts {
			if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") && len(part) > 2 {
				if requestParts[i] == "" {
					matched = false
				}
				continue
			}
			if requestParts[i] != part {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}
func (f *Federation) newSession(payload map[string]any) (*tunnelSession, error) {
	s := &tunnelSession{ID: mapString(payload["sessionId"]), Consumer: mapString(payload["consumer"]), ConsumerCloud: mapString(payload["consumerCloud"]), Provider: mapString(payload["provider"]), ProviderCloud: mapString(payload["providerCloud"]), Definition: mapString(payload["serviceDefinition"]), Peer: mapString(payload["peer"]), Target: object(payload["target"]), Created: time.Now(), LastUsed: time.Now()}
	if s.Consumer == "" || s.Provider == "" || s.Definition == "" || !f.trustedPeer(s.Peer) {
		return nil, errors.New("consumer, provider, serviceDefinition and a trusted peer are required")
	}
	if s.ID == "" {
		s.ID = randomID()
	}
	return s, nil
}
func (f *Federation) TunnelHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	path := strings.Replace(r.URL.Path, "/gateway/", "/gatetunnel/", 1)
	if f.tunnelControlHTTP(w, r, owner, path) {
		return
	}
	if path == "/gatetunnel/mgmt/sessions" && r.Method == "GET" {
		if !containsExact([]string{"LocalCloudManager", "Sysop"}, owner) {
			apiError(w, 403, "management denied", path)
			return
		}
		status := f.Status()
		rows := f.controlSessions()
		live, _ := object(status["interCloud"])["sessions"].([]any)
		rows = append(rows, live...)
		jsonOut(w, 200, map[string]any{"entries": rows, "count": len(rows)})
		return
	}
	if r.Method != "POST" || (path != "/gatetunnel/intercloud/provider" && path != "/gatetunnel/intercloud/consumer") {
		apiError(w, 501, "this Go transport currently implements the deployed inter-cloud relay contract, not AMQP queue control", path)
		return
	}
	if owner != "Gatekeeper" {
		apiError(w, 403, "only the local Gatekeeper may open sessions", path)
		return
	}
	var payload map[string]any
	if err := decode(r, &payload); err != nil {
		apiError(w, 400, err.Error(), path)
		return
	}
	if payload["keyExchange"] != nil {
		apiError(w, 400, "AH-GT-1 cannot be downgraded to legacy-mtls", path)
		return
	}
	s, err := f.newSession(payload)
	if err != nil {
		apiError(w, 400, err.Error(), path)
		return
	}
	if strings.HasSuffix(path, "/provider") {
		if s.ConsumerCloud != strings.Split(s.Peer, ".")[1]+"|"+f.app.Config.Organization || len(object(s.Target["operations"])) == 0 {
			apiError(w, 400, "consumerCloud and negotiated operation contracts are required", path)
			return
		}
		if !f.validateTarget(s) {
			apiError(w, 403, "target is not the registered HTTPS provider interface", path)
			return
		}
		f.mu.Lock()
		if len(f.providers) >= 256 {
			f.mu.Unlock()
			apiError(w, 503, "provider session limit reached", path)
			return
		}
		for id, old := range f.providers {
			if old.Consumer == s.Consumer && old.ConsumerCloud == s.ConsumerCloud && old.Provider == s.Provider && old.Definition == s.Definition {
				delete(f.providers, id)
			}
		}
		f.providers[s.ID] = s
		f.mu.Unlock()
		jsonOut(w, 201, map[string]any{"sessionId": s.ID})
		return
	}
	if s.ProviderCloud != strings.Split(s.Peer, ".")[1]+"|"+f.app.Config.Organization {
		apiError(w, 400, "providerCloud does not match peer", path)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, old := range f.consumers {
		if old.Consumer == s.Consumer && old.ProviderCloud == s.ProviderCloud && old.Provider == s.Provider && old.Definition == s.Definition {
			if old.Server != nil {
				_ = old.Server.Close()
			}
			delete(f.consumers, id)
		}
	}
	used := map[int]bool{}
	for _, v := range f.consumers {
		used[v.Port] = true
	}
	min, _ := strconv.Atoi(env("INTERCLOUD_MIN_PORT", "8200"))
	max, _ := strconv.Atoi(env("INTERCLOUD_MAX_PORT", "8299"))
	var listener net.Listener
	for port := min; port <= max; port++ {
		if used[port] {
			continue
		}
		listener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			s.Port = port
			break
		}
	}
	if listener == nil {
		apiError(w, 503, "no tunnel ports available", path)
		return
	}
	s.ConsumerCloud = f.app.Config.Cloud + "|" + f.app.Config.Organization
	s.Server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.forward(s, w, r) }), TLSConfig: f.app.tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second}
	f.consumers[s.ID] = s
	go func() {
		if err := s.Server.ServeTLS(listener, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("tunnel listener failed: %v", err)
		}
	}()
	jsonOut(w, 201, map[string]any{"address": env("ADVERTISED_ADDRESS", "gatetunnel"), "port": s.Port, "sessionId": s.ID})
}
func (f *Federation) validateTarget(s *tunnelSession) bool {
	instances, err := f.instances(s.Definition)
	if err != nil {
		return false
	}
	for _, raw := range instances {
		instance := object(raw)
		if object(instance["provider"])["name"] != s.Provider {
			continue
		}
		props := httpsProperties(instance)
		if props == nil {
			continue
		}
		addresses := stringSlice(props["accessAddresses"])
		if !containsExact(addresses, mapString(s.Target["address"])) || fmt.Sprint(props["accessPort"]) != fmt.Sprint(s.Target["port"]) || props["basePath"] != s.Target["basePath"] {
			continue
		}
		offered := object(props["operations"])
		valid := true
		for name, op := range object(s.Target["operations"]) {
			a, _ := json.Marshal(op)
			b, _ := json.Marshal(offered[name])
			if !bytes.Equal(a, b) {
				valid = false
			}
		}
		if valid {
			return true
		}
	}
	return false
}
func (f *Federation) forward(s *tunnelSession, w http.ResponseWriter, r *http.Request) {
	owner, err := f.app.requester(r)
	if err != nil || owner != s.Consumer {
		apiError(w, 401, "not the negotiated consumer", r.URL.Path)
		return
	}
	f.mu.Lock()
	active := f.consumers[s.ID] == s && time.Since(s.Created) <= 12*time.Hour && time.Since(s.LastUsed) <= time.Hour
	f.mu.Unlock()
	if !active {
		apiError(w, 401, "session expired; orchestrate again", r.URL.Path)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		apiError(w, 413, "request too large", r.URL.Path)
		return
	}
	reply, err := f.request(strings.Split(s.Peer, ".")[1], map[string]any{"type": "http-request", "sessionId": s.ID, "method": r.Method, "path": r.URL.RequestURI(), "contentType": r.Header.Get("Content-Type"), "body": base64.StdEncoding.EncodeToString(body)})
	if err != nil {
		apiError(w, 502, err.Error(), r.URL.Path)
		return
	}
	data, err := base64.StdEncoding.DecodeString(mapString(reply["body"]))
	status, ok := number(reply["status"])
	if err != nil || !ok || status < 100 || status > 599 {
		apiError(w, 502, "invalid peer response", r.URL.Path)
		return
	}
	f.mu.Lock()
	s.Requests++
	s.LastUsed = time.Now()
	f.mu.Unlock()
	w.Header().Set("Content-Type", mapString(reply["contentType"]))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(int(status))
	_, _ = w.Write(data)
}
func (f *Federation) handleTunnel(peer string, m map[string]any) (map[string]any, error) {
	if m["type"] != "http-request" {
		return nil, errors.New("unknown tunnel request")
	}
	if m["ciphertext"] != nil {
		return nil, errors.New("AH-GT-1 is not supported by the configured legacy-mtls profile")
	}
	f.mu.Lock()
	s := f.providers[mapString(m["sessionId"])]
	valid := s != nil && s.Peer == peer && time.Since(s.Created) <= 12*time.Hour && time.Since(s.LastUsed) <= time.Hour
	f.mu.Unlock()
	if !valid {
		return nil, errors.New("unknown, expired or wrong-peer session")
	}
	method, path := mapString(m["method"]), mapString(m["path"])
	answer := func(code int, data []byte, contentType string) map[string]any {
		return map[string]any{"status": code, "body": base64.StdEncoding.EncodeToString(data), "contentType": contentType}
	}
	if !operationAllowed(method, path, mapString(s.Target["basePath"]), object(s.Target["operations"])) {
		return answer(403, []byte(`{"error":"operation outside negotiated session"}`), "application/json"), nil
	}
	body, err := base64.StdEncoding.DecodeString(mapString(m["body"]))
	if err != nil || len(body) > 1<<20 {
		return nil, errors.New("invalid or oversized body")
	}
	address := mapString(s.Target["address"])
	if strings.ContainsAny(address, "/@?#") {
		return nil, errors.New("invalid target address")
	}
	port, nerr := number(s.Target["port"])
	if !nerr || port < 1 || port > 65535 {
		return nil, errors.New("invalid target port")
	}
	token, err := f.app.ownToken()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(""+method, "https://"+net.JoinHostPort(address, strconv.Itoa(int(port)))+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//"+token)
	req.Header.Set("Content-Type", mapString(m["contentType"]))
	req.Header.Set("X-Arrowhead-Remote-Consumer", s.Consumer+"|"+s.ConsumerCloud)
	ctx, cancel := context.WithTimeout(req.Context(), 15*time.Second)
	defer cancel()
	res, err := f.app.client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, errors.New("provider call failed")
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return nil, errors.New("provider response too large")
	}
	f.mu.Lock()
	s.Requests++
	s.LastUsed = time.Now()
	f.mu.Unlock()
	return answer(res.StatusCode, data, res.Header.Get("Content-Type")), nil
}
