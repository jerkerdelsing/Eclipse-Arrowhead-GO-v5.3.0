// SPDX-License-Identifier: EPL-2.0
// Generates Arrowhead-style SysD, SysDD, SD and HTTPS IDD sources and traceability.
package main

import (
	"arrowhead/ah5-support-go/configuration/internal/core"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type route struct {
	Method, Path, Source, SHA256 string
	Present                      bool
}
type inventory struct {
	Name, Folder, Purpose string
	SourceFiles           map[string]string
	Routes                []route
	Unresolved            []string
	GoRoutes              []core.Route
	Services              []core.Service
	Limitations           []string
}

var folders = map[string]string{"AIGym": "AI-gym", "Choreographer": "Choreography"}
var limits = map[string][]string{
	"DeviceQoSEvaluator":     {"Uses explicit DeviceMeasurementAgent input. The complete Java SNMP/OID discovery, augmentation and scaling engine is not ported; scores are weighted window means with missing-data rejection."},
	"Choreographer":          {"Local synchronous orchestration and executor start/callback flow are implemented. Async orchestration callbacks return 501. Java executor dependency negotiation, optimal selection, session notifications and remote abort propagation are incomplete."},
	"TranslationManager":     {"Port of the Java TranslatorBridgeEngine (2026-10-24): interface translators (interfaceBridgeManagement) and data model translators (dataModelTranslation, or dataModelTranslatorFactoryControl factories) are discovered in the ServiceRegistry by their metadata; check-targets, initialize-bridge and abort-bridge follow the Java driver contracts; bridge statuses, transitions, reports and the 8-hour discovery cleanup are the Java ones.", "Translators are called over mutual TLS with the identity token; translators whose interfaceBridgeManagement interface uses a TOKEN_AUTH policy are not selected, and custom translator configuration (a TODO in the Java reference) is not sent.", "Default matchmaking takes the first acceptable translator; the Java matchmaker beans are not pluggable."},
	"Onboarding":             {"Enrollment records use JSON, not the Java database. System/identity/registry operations form a partial compensating saga, not a distributed transaction. Complete renewal, crash recovery, withdrawal of approved systems and prerequisite-service discovery require further work."},
	"PlantDescriptionEngine": {"Topology/include composition, named and metadata matching, periodic alarms, and atomic PDE-to-DSO snapshot synchronization are implemented. Missing producers retain managed empty scopes; nonnegative priorities rank eligible providers. Java SQL import, complete DTO normalization and production qualification remain outside this extension."},
	"DataManager":            {"Historian packs are persisted locally. Proxy resolves registered HTTPS get-data/put-data operations and uses its own identity. Complete SenML normalization, signalCount semantics, Java provider-configuration and MQTT ingestion are not ported."},
	"EventHandler":           {"HTTPS callbacks use a persistent bounded outbox and at most three attempts. MQTT notifications, complete Java executor/backoff settings and distributed exactly-once guarantees are absent."},
	"Gatekeeper":             {"Reuses the existing native Go legacy-mTLS relay engine, adapted to pinned clients. AH-GT-1 end-to-end encryption is absent. Broker ACLs and trusted neighbour provisioning remain required; no live federation is exercised by this delivery."},
	"GateTunnel":             {"Legacy-mTLS relay sessions are supported; control-session records are not a second AMQP tunnel data plane. AH-GT-1 encrypted requests are rejected. Consumer listeners are volatile and renegotiated after restart."},
	"SysMonitor":             {"AMQPS intake and MQTT QoS1 outbox forwarding are implemented. MQTT uses Paho 3.1.1 rather than Java MQTTv5. Full live-broker/UI parity and imported Java history have not been certified. The default subscription is none until configured."},
	"CertificateAuthority":   {"CSR and CRL operations use a separately provisioned CA key; no CA key is generated/copied by this port. CRL export does not prove enforcement by every relying party. Java SQL import, automatic CRL file publication, HSM/OCSP/HA are absent."},
	"TimeManager":            {"SNTP checks report offset/trust without changing the host clock. Full Java time-source caching, source-selection and trust policy are not ported."},
	"Configuration":          {"JSON persistence replaces JPA/SQL. Proxy currently serves the local configuration store instead of Java external-provider fallback."},
	"Blacklist":              {"Time-bounded active/revoked records persist in JSON. Complete Java normalization, historical reactivation and query mode edge cases need golden-contract tests."},
	"AIGym":                  {"Local extension, not an upstream mandatory Arrowhead 5.2.2 support system. Native k-nearest-neighbour behavior and persisted samples are implemented; all Java observation publishing semantics are not ported."},
}

func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
func hashFile(path string) string {
	b, e := os.ReadFile(path)
	if e != nil {
		fail(e)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func eval(expr string, constants map[string]string) (string, bool) {
	var out strings.Builder
	for _, part := range strings.Split(expr, " + ") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`) {
			var s string
			if json.Unmarshal([]byte(p), &s) != nil {
				return "", false
			}
			out.WriteString(s)
		} else {
			value, ok := constants[p]
			if !ok {
				return "", false
			}
			out.WriteString(value)
		}
	}
	return out.String(), true
}
func constants(roots ...string) map[string]string {
	pending, values := map[string]string{}, map[string]string{}
	declaration := regexp.MustCompile(`public static final String\s+(\w+)\s*=\s*([^;]+);`)
	for _, root := range roots {
		e := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "target" || strings.HasPrefix(d.Name(), "_super") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, "Constants.java") {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			class := strings.TrimSuffix(d.Name(), ".java")
			for _, m := range declaration.FindAllStringSubmatch(string(b), -1) {
				parts := strings.Split(m[2], " + ")
				for i, p := range parts {
					p = strings.TrimSpace(p)
					if !strings.HasPrefix(p, `"`) && !strings.Contains(p, ".") {
						parts[i] = class + "." + p
					}
				}
				pending[class+"."+m[1]] = strings.Join(parts, " + ")
			}
			return nil
		})
		if e != nil {
			fail(e)
		}
	}
	for i := 0; i < 40; i++ {
		changed := false
		for k, expr := range pending {
			if v, ok := eval(expr, values); ok {
				values[k] = v
				delete(pending, k)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return values
}
func collect(source, common string) []inventory {
	values := constants(source, common)
	result := []inventory{}
	classBase := regexp.MustCompile(`@RequestMapping\((?:value\s*=\s*|path\s*=\s*)?([^,)]+)`)
	mapping := regexp.MustCompile(`@(Get|Post|Put|Patch|Delete)Mapping\((?:path\s*=\s*|value\s*=\s*)?([^,)]+)`)
	for name, sys := range core.Systems {
		if name == "TestTranslation" {
			continue // test system without a Java reference (own documentation under documentation/TestTranslation)
		}
		folder := folders[name]
		if folder == "" {
			folder = name
		}
		item := inventory{Name: name, Folder: folder, Purpose: sys.Purpose, SourceFiles: map[string]string{}, Routes: []route{}, Unresolved: []string{}, Limitations: limits[name]}
		s, e := core.OpenStore("")
		if e != nil {
			fail(e)
		}
		app, e := core.New(core.Config{Role: name, Name: name, AuthorizationPolicy: "enforce"}, s, nil)
		if e != nil {
			fail(e)
		}
		item.GoRoutes = app.Routes
		item.Services = app.Services()
		available := map[string]bool{}
		for _, r := range app.Routes {
			available[r.Method+" "+r.Path] = true
		}
		root := filepath.Join(source, folder)
		e = filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == "target" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".java") {
				return nil
			}
			rel, _ := filepath.Rel(source, path)
			item.SourceFiles[rel] = hashFile(path)
			if !strings.HasSuffix(path, "API.java") && !strings.HasSuffix(path, "Controller.java") {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			base := ""
			if m := classBase.FindSubmatch(b); len(m) > 1 {
				var ok bool
				base, ok = eval(string(m[1]), values)
				if !ok {
					item.Unresolved = append(item.Unresolved, string(m[1]))
					return nil
				}
			}
			for _, m := range mapping.FindAllSubmatch(b, -1) {
				suffix, ok := eval(string(m[2]), values)
				if !ok {
					item.Unresolved = append(item.Unresolved, string(m[2]))
					continue
				}
				method := strings.ToUpper(string(m[1]))
				item.Routes = append(item.Routes, route{method, base + suffix, rel, item.SourceFiles[rel], available[method+" "+base+suffix]})
			}
			return nil
		})
		if e != nil {
			fail(e)
		}
		if name == "CertificateAuthority" || name == "Gatekeeper" || name == "GateTunnel" || name == "SysMonitor" {
			e := filepath.WalkDir(filepath.Join(source, "JavaSupportRuntime", "src"), func(path string, d os.DirEntry, e error) error {
				if e != nil {
					return e
				}
				if !d.IsDir() && strings.HasSuffix(path, ".java") {
					rel, _ := filepath.Rel(source, path)
					item.SourceFiles[rel] = hashFile(path)
				}
				return nil
			})
			if e != nil {
				fail(e)
			}
			item.Limitations = append(item.Limitations, "The source reference uses a shared non-Spring HTTP dispatcher. Its route coverage is not inferred from Go route presence; manual JavaSupportRuntime review is required.")
		}
		sort.Slice(item.Routes, func(i, j int) bool {
			return item.Routes[i].Path+item.Routes[i].Method < item.Routes[j].Path+item.Routes[j].Method
		})
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
func escape(s string) string {
	return strings.NewReplacer(`\`, `\textbackslash{}`, "_", `\_`, "%", `\%`, "&", `\&`, "#", `\#`, "{", `\{`, "}", `\}`, "$", `\$`).Replace(s)
}
func preamble(title, typ, short string) string {
	if short == "SD" {
		if _, service, ok := strings.Cut(title, " / "); ok {
			title = service + " (Go)"
		}
	}
	return fmt.Sprintf("\\documentclass[a4paper]{arrowhead}\n\\usepackage[T1]{fontenc}\n\\usepackage{longtable,booktabs,xurl}\n\\setlength{\\emergencystretch}{3em}\n\\setlength{\\parindent}{0pt}\n\\setlength{\\parskip}{5pt}\n\\begin{document}\n\\ArrowheadTitle{%s}\n\\ArrowheadType{%s}\n\\ArrowheadTypeShort{%s}\n\\ArrowheadVersion{5.2.2}\n\\ArrowheadDate{2026-10-16}\n\\ArrowheadAuthor{Implementation working draft}\n\\ArrowheadStatus{DEVELOPMENT}\n\\ArrowheadContact{Repository maintainers}\n\\ArrowheadFooter{Eclipse Arrowhead -- native Go support implementations}\n\\ArrowheadSetup\n", escape(title), typ, short)
}
func limitations(item inventory) string {
	var b strings.Builder
	b.WriteString("\\subsection{Important delimitations}\nThis implementation is a development profile, not a certified interchangeable Java replacement. All systems use private JSON snapshots rather than the Java databases. MQTT application APIs, exhaustive DTO normalization and error parity, automatic data migration and production qualification remain outstanding.\n\\begin{itemize}\n")
	for _, s := range item.Limitations {
		fmt.Fprintf(&b, "\\item %s\n", escape(s))
	}
	b.WriteString("\\end{itemize}\n")
	return b.String()
}
func overview(item inventory) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\\section{%s}\n\\subsection{System overview}\n%s. The native Go executable selects this system independently; no Java or Python process implements its operations. Shared source is in \\path{internal/core}; federation code is in \\path{internal/relay}.\n", escape(item.Name), escape(item.Purpose))
	b.WriteString("\\subsection{Produced and consumed services}\nProduced HTTPS services: ")
	for i, s := range item.Services {
		if i > 0 {
			b.WriteString(", \\allowbreak ")
		}
		fmt.Fprintf(&b, "\\path{%s}", s.Definition)
	}
	version := "1.0.0"
	if item.Name == "Gatekeeper" || item.Name == "GateTunnel" {
		version = "5.2.2"
	}
	b.WriteString(".\nHTTPS service version " + version + ". Optional native AMQPS telemetry produces \\texttt{sysMonitor}; SysMonitor additionally publishes \\texttt{sysMonitorData} over MQTT/TLS. Consumed authorities include ServiceRegistry, Authentication and ConsumerAuthorization; optional dependencies are explicit pinned HTTPS origins.\n")
	b.WriteString(limitations(item))
	b.WriteString("\\subsection{Security and persistence}\nMutual TLS verifies the configured cloud trust anchors. Application identity tokens must match the client certificate. Authorities are pinned by system CN/profile before credentials are sent. Management requires a verified sysop identity or an explicit broad management whitelist. The default service authorization policy is enforce; identity-only mode must be explicitly selected. No insecure listener or declared-identity mode is implemented. Each executable owns one locked state file, written through fsync and atomic rename. Cross-system operations are not distributed transactions.\n")
	return b.String()
}
func routeTable(item inventory) string {
	var b strings.Builder
	b.WriteString("\\subsection{HTTPS interface operations}\nThe listener is HTTPS with JSON by default; raw configuration and CRL responses use their declared media types. A request body is capped at 1 MiB. The table records implemented routes, not a claim of complete behavioral conformance.\n\\begin{longtable}{p{0.12\\textwidth}p{0.63\\textwidth}p{0.18\\textwidth}}\\toprule\nMethod & Path & Access\\\\\\midrule\\endhead\n")
	for _, r := range item.GoRoutes {
		fmt.Fprintf(&b, "\\texttt{%s} & \\path{%s} & %s\\\\\n", r.Method, r.Path, escape(r.Access))
	}
	b.WriteString("\\bottomrule\\end{longtable}\n")
	return b.String()
}
func write(path, content string) {
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		fail(e)
	}
	if e := os.WriteFile(path, []byte(content), 0644); e != nil {
		fail(e)
	}
}
func main() {
	source := flag.String("source", "../ah5-support-java-spring", "reference source")
	common := flag.String("common", "../ah5-common-java-spring", "shared reference")
	out := flag.String("out", "documentation", "output directory")
	flag.Parse()
	items := collect(*source, *common)
	commonFiles := map[string]string{}
	e := filepath.WalkDir(*common, func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == "target" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".java") {
			rel, _ := filepath.Rel(*common, path)
			commonFiles[rel] = hashFile(path)
		}
		return nil
	})
	if e != nil {
		fail(e)
	}
	j, e := json.MarshalIndent(map[string]any{"notice": "Development profile. Route presence is not semantic parity. Source hashes include local reference changes. No deployment is performed.", "sourceRoot": *source, "commonRoot": *common, "commonSourceFiles": commonFiles, "systems": items}, "", "  ")
	if e != nil {
		fail(e)
	}
	write(filepath.Join(*out, "contracts.json"), string(j)+"\n")
	master := preamble("Go support systems", "System Design and Interface Catalogue", "SysDD / IDD")
	master += "\\begin{center}\\vspace*{8mm}{\\LARGE Arrowhead support systems in Go}\\par\\vspace{4mm}{\\large Native implementation and interface catalogue}\\end{center}\n\\begin{abstract}This catalogue covers the fifteen active support systems in the local Java reference, including AIGym as a local extension. It records the delivered Go design, service interfaces, security boundaries and explicit remaining work. It is a development document; it does not assert full Java interchangeability or that any running cloud has changed.\\end{abstract}\n\\ArrowheadBox{Release boundary.}{Do not replace a Java deployment solely because an HTTP route exists. Review each system's delimitations and the verification report; required advanced integrations and data migrations remain release gates.}\n\\newpage\\tableofcontents\\newpage\n"
	for _, item := range items {
		master += overview(item) + "\\clearpage\n" + routeTable(item) + "\\clearpage\n"
		dir := filepath.Join(*out, item.Name)
		body := overview(item)
		write(filepath.Join(dir, item.Name+"-SysD.tex"), preamble(item.Name+" (Go)", "System Description", "SysD")+body+"\\section{References}\nLocal Java reference: \\path{"+item.Folder+"/}. Source hashes and extracted routes are recorded in \\path{contracts.json}.\\end{document}\n")
		write(filepath.Join(dir, item.Name+"-SysDD.tex"), preamble(item.Name+" (Go)", "System Design Description", "SysDD")+body+"\\section{Implementation}\nGo 1.26 or newer builds the native binary. State is serialized as private JSON documents; updates clone state, validate, persist and then publish. Server timeouts and bounded message sizes constrain resource use. Persistent outboxes are at-least-once and cannot provide distributed exactly-once delivery. Detailed source, configuration and test instructions are in the repository README and verification report.\n"+routeTable(item)+"\\end{document}\n")
		write(filepath.Join(dir, item.Name+"-HTTPS-IDD.tex"), preamble(item.Name+" HTTPS / Go", "Interface Design Description", "IDD")+"\\section{Interface overview}\nHTTPS, mandatory mutual TLS, Arrowhead identity-token header and JSON request/response documents. General management is sysop/whitelist protected; enrollment endpoints use approved certificate fingerprints and profile/serial checks instead of ordinary identity tokens. Error responses contain errorMessage, errorCode, origin and timestamp. Exact DTO and status/error parity is not certified.\n"+routeTable(item)+limitations(item)+"\\end{document}\n")
		for _, s := range item.Services {
			version := "1.0.0"
			if item.Name == "Gatekeeper" || item.Name == "GateTunnel" {
				version = "5.2.2"
			}
			sd := preamble(s.Definition+" (Go)", "Service Description", "SD") + "\\section{Service overview}\nDefinition: \\path{" + s.Definition + "}, version " + version + ". Produced by \\texttt{" + escape(item.Name) + "}; HTTPS uses \\texttt{generic\\_https} and \\texttt{CERT\\_AUTH}. Consumption authorization and management restrictions are additionally enforced at the application layer. Base path: \\path{" + s.BasePath + "}.\n\\section{Operations}\n\\begin{description}\n"
			ops := []string{}
			for op := range s.Operations {
				ops = append(ops, op)
			}
			sort.Strings(ops)
			for _, op := range ops {
				m := s.Operations[op]
				sd += "\\item[" + escape(op) + "] \\texttt{" + escape(m["method"].(string)) + "} \\path{" + m["path"].(string) + "}.\n"
			}
			sd += "\\end{description}\n" + limitations(item) + "\\section{Interface contract}\nSee the system HTTPS IDD and the Java source inventory for DTO fields and reference traceability. Successful local tests do not establish all Java behavioral or failure semantics.\\end{document}\n"
			write(filepath.Join(dir, item.Name+"-"+s.Definition+"-SD.tex"), sd)
		}
	}
	master += "\\section{Verification and release gates}\nBuild and static checks must cover all fifteen executables. Race-checked tests use isolated PKI and temporary state. Java-versus-Go golden contracts, real broker interoperability, database import and rollback, federation peers and LocalCloudManager readiness require separate evidence. No generated document labels these implementations production-ready.\\end{document}\n"
	write(filepath.Join(*out, "Go-Support-Systems.tex"), master)
	missing := 0
	for _, item := range items {
		for _, r := range item.Routes {
			if !r.Present {
				missing++
				fmt.Fprintf(os.Stderr, "Missing %s %s %s\n", item.Name, r.Method, r.Path)
			}
		}
		for _, s := range item.Unresolved {
			missing++
			fmt.Fprintf(os.Stderr, "Unresolved %s %s\n", item.Name, s)
		}
	}
	fmt.Printf("Generated Arrowhead SysD/SysDD/SD/IDD sources for %d systems; %d missing/unresolved Spring routes.\n", len(items), missing)
	if missing > 0 {
		os.Exit(1)
	}
}
