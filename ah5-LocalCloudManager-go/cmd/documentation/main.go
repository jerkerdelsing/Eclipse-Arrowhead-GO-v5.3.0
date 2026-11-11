// SPDX-License-Identifier: EPL-2.0
// Generate the Arrowhead design/service/interface set and source provenance.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type route struct{ Method, Path, Access, Behavior string }

var routes = []route{
	{"GET", "/health", "transport", "Runtime configuration, not readiness proof"},
	{"GET", "/ and /ui", "transport", "Static embedded index"},
	{"GET", "/app.js and /assets/app.js", "transport", "Embedded JavaScript"},
	{"GET", "/styles.css and /assets/styles.css", "transport", "Embedded CSS"},
	{"GET", "/api/session", "console policy", "authenticated/configured booleans"},
	{"POST", "/api/session", "console policy", "Password login; 204 and cookie"},
	{"DELETE", "/api/session", "console policy", "Invalidate cookie/session"},
	{"GET", "/api/overview", "session", "Inventory/runtime aggregation; synthetic flags noted"},
	{"GET", "/api/service-registry-management", "session", "Grouped devices/systems/services/runtime"},
	{"GET", "/api/datamanager", "session", "Flatten historian; limit default240, max1000"},
	{"GET", "/api/consumers", "session", "Service and simple-store consumer view"},
	{"GET", "/api/intercloud", "session", "Static unavailable placeholder"},
	{"GET", "/api/sysmonitor", "session", "Inherited observation adapter; optional system query"},
	{"GET", "/api/sysmonitor/subscriptions", "session", "Read subscription adapter; synthetic intake flags"},
	{"PUT, DELETE", "/api/sysmonitor/subscriptions/{providerSystem}", "session + confirm", "Acknowledgement only; NO provider write"},
	{"GET", "/api/plantdescriptions", "session", "Plant records and registry catalogue"},
	{"POST", "/api/plantdescriptions", "session + confirm", "Create through provider adapter"},
	{"PUT, PATCH, DELETE", "/api/plantdescriptions/{id}", "session + confirm", "Provider replace/update/remove"},
	{"GET", "/api/orchestration/rules", "session", "Simple store plus producer/consumer catalogue"},
	{"POST", "/api/orchestration/rules", "session + confirm", "Validate consumer/instance/priority then create"},
	{"DELETE", "/api/orchestration/rules/{id}", "session + confirm", "Remove via simple-store adapter"},
	{"GET", "/api/logs", "session", "service query; tail default150, max500"},
	{"POST", "/api/containers/{service}/{action}", "session + confirm", "Static allowlist, project filter; start/stop/restart"},
	{"GET", "/localcloud/management/status", "Arrowhead management", "Legacy status response"},
	{"GET", "/localcloud/management/systems", "Arrowhead management", "Registry systems query"},
	{"GET", "/localcloud/management/services", "Arrowhead management", "Registry instances query"},
	{"GET", "/localcloud/monitor/echo", "Arrowhead identity", "Text Got it!; registry metadata differs"},
}

func esc(s string) string {
	r := strings.NewReplacer("\\", "\\textbackslash{}", "&", "\\&", "%", "\\%", "_", "\\_", "#", "\\#", "$", "\\$", "{", "\\{", "}", "\\}")
	return r.Replace(s)
}
func prose(s string) string {
	var out strings.Builder
	for i, part := range strings.Split(strings.ReplaceAll(s, "**", ""), "`") {
		if i%2 == 0 {
			out.WriteString(esc(part))
		} else {
			out.WriteString("\\path|" + part + "|")
		}
	}
	return out.String()
}
func preamble(title, kind, version string) string {
	return fmt.Sprintf(`\documentclass[a4paper]{arrowhead}
\usepackage[T1]{fontenc}
\usepackage{longtable,booktabs,xurl,enumitem}
\setlength{\emergencystretch}{3em}
\setlength{\parindent}{0pt}\setlength{\parskip}{5pt}
\setlist{nosep,leftmargin=*}
\begin{document}
\ArrowheadTitle{%s (Go)}\ArrowheadType{%s}\ArrowheadTypeShort{Go}
\ArrowheadVersion{%s}\ArrowheadDate{2026-10-17}
\ArrowheadAuthor{Eclipse Arrowhead migration project}\ArrowheadStatus{DEVELOPMENT}
\ArrowheadContact{Project maintainers}\ArrowheadFooter{Eclipse Arrowhead -- Go LocalCloudManager -- EPL-2.0}
\ArrowheadSetup
`, esc(title), esc(kind), version)
}
func section(title, text string) string {
	return "\\section{" + esc(title) + "}\n" + prose(text) + "\n"
}
func paragraphs(title, text string) string {
	var out strings.Builder
	out.WriteString("\\section{" + esc(title) + "}\n")
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			out.WriteString(prose(line) + "\\par\n")
		}
	}
	return out.String()
}
func routeTable() string {
	var out strings.Builder
	out.WriteString("\\begin{longtable}{p{0.12\\textwidth}p{0.45\\textwidth}p{0.31\\textwidth}}\\toprule\nMethod & Actual handler path & Access / behavior\\\\\\midrule\\endhead\n")
	for _, r := range routes {
		out.WriteString(fmt.Sprintf("%s & \\path|%s| & %s. %s\\\\\n", esc(r.Method), r.Path, esc(r.Access), esc(r.Behavior)))
	}
	out.WriteString("\\bottomrule\\end{longtable}\n")
	return out.String()
}
func write(path, text string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(text), 0644)
}
func hashes(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "bin" || d.Name() == "build" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.Contains(path, string(filepath.Separator)+"ui"+string(filepath.Separator)) && d.Name() != "go.mod" && d.Name() != "go.sum" {
			return nil
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		sum := sha256.Sum256(b)
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return out, err
}
func run() error {
	reference := flag.String("reference", "../../Arrowhead-test-cloud-go/native-go", "Original local deployment source (read only)")
	flag.Parse()
	output := "../documentation/LocalCloudManager/v5.2.2"
	compatBytes, err := os.ReadFile("COMPATIBILITY.md")
	if err != nil {
		return err
	}
	compat := string(compatBytes)
	overview := section("System overview", "LocalCloudManager is the operator-facing Go adapter for an Arrowhead local cloud. This package relocates the latest located local source into `ah5-support-go/LocalCloudManager`, with a dedicated launcher, bundled shared-runtime dependencies and embedded dashboard assets. The target system version is 5.2.2; produced service versions are 1.0.0. This relocation does not establish complete Java interchangeability or modify a deployed cloud.") +
		section("System boundary and stakeholders", "An operator browser uses the console UI and localCloudManagement API. The adapter consumes ServiceRegistry, Authentication, Simple Store Service Orchestration, DataManager, SysMonitor and PlantDescriptionEngine. It reads Docker container metadata/logs and performs limited lifecycle actions through a Unix socket. Native Go business code does not invoke a Java, Rust or Node.js server.") +
		section("Produced services", "`localCloudManagement` at `/api` is the browser-facing session API. Historical `monitor` at `/localcloud/monitor` provides echo and retains the source's legacy registration name. Optional `sysMonitor` is native AMQPS telemetry and is enabled only in secure mode with `SYSMONITOR_ENABLED=true`. Legacy monitor naming is not a recommendation for new telemetry contracts.") +
		section("Consumed services and prerequisites", "Provision a distinct LocalCloudManager sy certificate, matching private key, trusted CA bundle, Authentication identity/password, and provider grants/management whitelist. Configure explicit HTTPS URLs for every used provider: several inherited defaults are HTTP and fail in secure mode. Docker access requires the intended Compose project and isolated socket access. No CA private key is needed or included.") +
		section("Deployment and variants", "Exactly one manager implementation should serve a cloud. The revised SysML model records Go's canonical source, the existing Java-cloud Node.js adapter, and the Rust source as distinct variants; it does not assert tested substitution. Default standalone port8480 uses mutual TLS and serves UI/API on the same listener. Historical API9480/UI9490 mappings belong to deployment configuration, not this relocation. Existing native-go deployment source is retained unchanged to preserve shared-runtime build contexts.")
	design := section("Architecture", "The operator reaches the static dashboard and console API on the Go HTTP server. API handlers use the adapter's own identity for HTTPS provider calls. Runtime inspection/control uses a Unix-socket Docker client. Optional telemetry is published directly to AMQP. The package contains the original shared Go runtime because TLS/client/model/registration helpers are interdependent; the dedicated executable rejects other role selections.") +
		section("Components", "`cmd/localcloudmanager/main.go`: role-constrained launcher. `internal/cloud/localcloudmanager.go`: sessions, API aggregation, provider adapters, Docker operations. `assets.go` and `ui/`: compile-time embedded UI, retaining explicit UI_ROOT and legacy on-disk fallbacks. `app.go`: environment, server, registration and provider-call retry. `security.go`: certificates, CRL and identity. `monitoring.go`: AMQPS publisher. `model.go`: inherited JSON state. Other shared files remain compile-time dependencies, not newly deployed support systems.") +
		section("Request sequence and trust boundaries", "Transport mTLS is enforced when secure mode is selected. Static assets and health need no operator session. For `/api/`, Host/Origin policy and configured console password are checked, session requests are handled, then a valid operator cookie is required. Mutations additionally require `X-Arrowhead-Action: confirm`. These handlers run before the shared Arrowhead token/management dispatch; a bearer token does not replace a browser session. Provider calls obtain the manager's own token and refresh once after401. Network effects and local state are not a distributed transaction.") +
		section("State and recovery", "Console sessions and the last60 overview samples live in process memory and are lost on restart. Shared JSON state uses a temporary sibling file and rename, but no new fsync/process-lock guarantees are introduced. Registration retries every20seconds. Displayed registered/naming flags are synthetic and not evidence of successful registration. Provider/Docker failures appear in collected responses or502. Do not share active cloud state files with this package.") +
		section("Security and configuration", "Authentication server CN/profile are explicitly pinned before credentials; other provider peers have CA/SAN validation without universal expected-CN pinning. Optional CRLs are checked for new connections. Console cookies are HttpOnly/SameSite=Strict but not Secure or port-isolated; Origin checks do not compare exact ports. Lifecycle uses the static systemToCompose allowlist (MANAGED_SERVICES is not consumed); log reads are project-scoped, not restricted to that allowlist. A raw Docker socket is a privileged trust boundary; deployment isolation or a least-privilege proxy remains necessary. See README.md for every environment variable and COMPATIBILITY.md for release blockers.")
	managementSD := section("Service overview", "Definition `localCloudManagement`, version1.0.0, producer LocalCloudManager, base `/api`. Aggregates registry/runtime, historian, consumer, monitoring, plant and orchestration information and supports operator-controlled mutations. The service uses the manager's operator session rather than accepting a browser's identity token as equivalent authentication.") +
		section("Semantics and delimitations", "Read operations include overview, service-registry-management, datamanager, consumers, intercloud, sysmonitor, subscriptions, plantdescriptions, orchestration rules and logs. Mutations include rules, plant descriptions, runtime lifecycle and subscription endpoints. Subscription mutation is currently a NO-OP acknowledgement; intercloud is a placeholder and several status fields are synthetic. The actual methods and nested routes are in the HTTPS IDD. The inherited registration helper incorrectly advertises POST/name mappings; registry metadata must not substitute for the handler contract.")
	managementIDD := section("HTTPS interface overview", "Target secure interface `generic_https`, policy CERT_AUTH at transport; default standalone origin is `https://<provisioned-host>:8480`. The UI and API share the listener. Configure valid SANs and reverse-proxy client certificates if a proxy is used. Requests/responses are JSON except assets, echo and204login. Documented routes are the actual handlers; source registration metadata has known method/path mismatches. Tables use grouped methods or aliases where indicated.") + routeTable() + "\\clearpage\n" +
		paragraphs("Session and mutation DTOs", "`POST /api/session` body: `{\"password\":\"...\"}`. Success204with Set-Cookie `ah_console`, HttpOnly, SameSite=Strict, Path=/, Max-Age default28800; no Secure flag. `GET /api/session` responds authenticated/configured; DELETE invalidates and expires the cookie. Missing hash503, wrong password401, lockout429with Retry-After; lockout follows five failures in five minutes and lasts one minute. Host or Origin denial403.\nAll `/api/` requests require allowed Host/Origin; all except session routes require a session. Mutation confirmation is exactly `X-Arrowhead-Action: confirm`; absent confirmation428. This is not cryptographic replay protection or origin-port isolation.\nRule creation body requires consumer, serviceInstanceId and positive integer priority. The adapter verifies producer availability and compatible consumer from registry data before forwarding. Successful create201; remove200with id/removed/at. Provider failures generally502with an error string; malformed rule JSON400.\nPlant mutations forward JSON to the inherited provider path; create201, updates200, delete200with removed id. Subscription writes respond providerSystem/updated/removed but do not forward any change. Lifecycle responds202with service/action/accepted/at, and only start/stop/restart on a static allowlisted project container is accepted.") +
		paragraphs("Read response DTOs", "Overview includes collectedAt, cloud, summary, devices, systems, services, registryManagement, naming, infrastructure, orchestrations, containers, history, registration and errors. Grouping includes devices/runtimeOnly and registered/deployed counts. Some flags and empty collections are synthetic, not verified state.\nData view uses limit (default240,max1000), collectedAt/count/latest/entries/series; entries are flattened inherited historian data. Consumers returns localCloud/errors/rows with provider/definition/authorization/orchestration views; cloud labels are partly hard-coded TestCloud.\nSysMonitor view includes collectedAt, retentionDays, storedObservations, systems, selectedSystem and observations; the optional query is system. Subscription read returns defaultSubscription/providers/subscriptions/intake, with synthetic connected/providerFound values. Plant read returns entries/systems/services/registryError.\nLogs use service and tail query (default150,max500), returning service/lines/collectedAt. Runtime rows include id/name/service/displayName/image/state/status/health/created/managed. Logs may include any container returned by the Compose project filter, even when lifecycle management is disallowed.")
	monitorSD := section("Legacy echo service", "The source registers `monitor`, version1.0.0, base `/localcloud/monitor`, operation echo. This is historical liveness compatibility, not canonical telemetry. A successful echo proves only the current request path/identity, not provider readiness or registration. The registration helper currently advertises POST while the documented intended handler request is GET; the general echo suffix handler is not method-specific.")
	monitorIDD := section("Legacy HTTPS echo", "Request `GET /localcloud/monitor/echo`, no body. Secure mode requires a verified local certificate and valid bound Arrowhead identity token. Response200text `Got it!`. Authentication failures401. No operator-console cookie is substituted for this legacy Arrowhead identity check. The shared handler accepts echo suffixes broadly; this is a compatibility route, not a strict operation inventory or canonical sysMonitor interface.")
	telemetrySD := section("Service overview", "Definition `sysMonitor`, version1.0.0, producer LocalCloudManager, conditional on secure mode and SYSMONITOR_ENABLED=true. Native persistent publisher-confirmed observations are emitted for echo, power and status. This is distinct from historical monitor echo. Consumers subscribe through their authorized SysMonitor/broker infrastructure; the publisher does not expose a browser subscription API for this service.") +
		section("Semantics and reliability", "Telemetry reports the running process and generated line-power/status values, not physical device measurements. Publisher sequence increases within a process; observation IDs include system/type/time/sequence. A30second ticker and reconnect/retry loop are used. Publisher confirms prove broker acceptance, not durable downstream processing or exactly-once delivery. There is no durable local outbox and no new real-broker qualification in this relocation.")
	telemetryIDD := section("AMQPS binding", "AMQP0-9-1 overTLS, interface `generic_amqps`, policy CERT_AUTH. Broker AMQP_HOST/AMQP_PORT defaultamqp-broker:5671; SASL EXTERNAL with LocalCloudManager service certificate. Exchange `arrowhead`, routing `<Cloud>.sysmonitor.LocalCloudManager.LocalCloudManager.<observationType>`. Operations/types `echo`, `power`, `status`; content type application/json, delivery mode persistent, publisher confirm with a10second wait bound. Configure broker SANs, trust, exchange and ACLs independently.") +
		paragraphs("Observation schema", "Envelope fields: schemaVersion1.0, observationId, providerSystem, serviceInstance, observationType, sourceTime (UTC-Z), sequence, value, quality, metadata. metadata contains publisherMode=native and implementation=go. Non-echo observations include unit1.\nEcho value: status=alive, uptimeSeconds, detail. Power: supplyType=line, state=available. Status: state=running, health=healthy, serviceCount. These values do not establish provider readiness or physical supply state.\nRegistry metadata contract SysMonitor-AMQP-IDD-5.2.2, schemaVersion1.0, publisherMode native, observationTypes array and delivery persistent/publisher-confirmed. baseRoutingKey is `cloud.sysmonitor.LocalCloudManager.LocalCloudManager`. No plaintext AMQP fallback is provided by this publisher.")
	var warnings strings.Builder
	warnings.WriteString("\\section{Compatibility and release gates}\n")
	for _, line := range strings.Split(compat, "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			warnings.WriteString(prose(line) + "\\par\\medskip\n")
		}
	}
	references := section("References and verification", "Authoritative moved code: LocalCloudManager/internal/cloud and embedded ui sources. Exact original/relocated SHA256 hashes are in docs/source-manifest.json. docs/legacy preserves the earlier local Markdown/SysML, not an endorsement of its parity claims. The revised SysML variability model is descriptive and has not been checked by a SysML parser. Executed checks and qualification limits are recorded in VERIFICATION.md. Source movement does not deploy or alter running clouds.")
	docs := []struct{ name, kind, version, body string }{
		{"SysD", "System Description", "5.2.2", overview + warnings.String() + references},
		{"SysDD", "System Design Description", "5.2.2", design + warnings.String() + references},
		{"localCloudManagement-SD", "Service Description", "1.0.0", managementSD + references},
		{"localCloudManagement-HTTPS-IDD", "Interface Design Description", "1.0.0", managementIDD + warnings.String() + references},
		{"monitor-SD", "Service Description", "1.0.0", monitorSD + references},
		{"monitor-HTTPS-IDD", "Interface Design Description", "1.0.0", monitorIDD + references},
		{"sysMonitor-SD", "Service Description", "1.0.0", telemetrySD + references},
		{"sysMonitor-AMQP-IDD", "Interface Design Description", "1.0.0", telemetryIDD + references},
	}
	for _, d := range docs {
		if err = write(filepath.Join(output, "LocalCloudManager-Go-v5.2.2-"+d.name+".tex"), preamble("LocalCloudManager / "+d.name, d.kind, d.version)+d.body+"\\end{document}\n"); err != nil {
			return err
		}
	}
	master := preamble("LocalCloudManager", "System, Service and Interface Catalogue", "5.2.2") + "\\addtocontents{toc}{\\protect\\setcounter{tocdepth}{1}}\n\\begin{center}\\vspace*{8mm}{\\LARGE LocalCloudManager in Go}\\par\\vspace{4mm}{\\large Relocation, design, service and interface catalogue}\\end{center}\n\\begin{abstract}Canonical source relocated into ah5-support-go with standalone build, embedded UI and source-provenance records. This catalogue documents actual behavior and inherited gaps; it does not declare Java interchangeability or a new cloud deployment.\\end{abstract}\n\\ArrowheadBox{Qualification boundary.}{Subscription writes are currently acknowledgements only; intercloud and several status fields are placeholders. Browser-origin isolation and Docker privileges need review. Do not treat source relocation as security hardening.}\n\\clearpage\\tableofcontents\\clearpage\n" + overview + "\\clearpage\n" + design + "\\clearpage\n" + managementSD + "\\clearpage\n" + managementIDD + "\\clearpage\n" + monitorSD + monitorIDD + "\\clearpage\n" + telemetrySD + telemetryIDD + "\\clearpage\n" + warnings.String() + references + "\\end{document}\n"
	if err = write(filepath.Join(output, "LocalCloudManager-Go-Catalogue.tex"), master); err != nil {
		return err
	}
	before, err := hashes(*reference)
	if err != nil {
		return err
	}
	after, err := hashes(".")
	if err != nil {
		return err
	}
	manifest := map[string]any{"referenceRoot": *reference, "referenceSHA256": before, "relocatedSHA256": after, "notice": "Canonical relocation; deployment copy retained; no live secrets/state copied; registration metadata differs from handlers", "actualHTTPRoutes": routes}
	b, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	if err = write("docs/source-manifest.json", string(b)+"\n"); err != nil {
		return err
	}
	fmt.Printf("Generated 8 Arrowhead SysD/SysDD/SD/IDD documents plus catalogue; %d grouped route rows; source hashes recorded\n", len(routes))
	return nil
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
