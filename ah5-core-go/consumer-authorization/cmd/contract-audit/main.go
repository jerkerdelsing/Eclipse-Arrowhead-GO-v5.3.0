// SPDX-License-Identifier: EPL-2.0
// Generates a source-traceability report, not a semantic conformance certificate.
package main

import (
	"arrowhead/ah5-core-go/consumer-authorization/internal/core"
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
	Method         string `json:"method"`
	Path           string `json:"path"`
	Source         string `json:"source"`
	SHA256         string `json:"sourceSHA256"`
	GoRoutePresent bool   `json:"goRoutePresent"`
}
type report struct {
	Role       string   `json:"role"`
	Routes     []route  `json:"javaHTTPRoutes"`
	Unresolved []string `json:"unresolvedExpressions"`
}

var declaration = regexp.MustCompile(`public static final String\s+(\w+)\s*=\s*([^;]+);`)

func eval(s string, values map[string]string) (string, bool) {
	var result strings.Builder
	for _, part := range strings.Split(s, " + ") {
		p := strings.TrimSpace(part)
		if strings.HasPrefix(p, `"`) && strings.HasSuffix(p, `"`) {
			var v string
			if json.Unmarshal([]byte(p), &v) != nil {
				return "", false
			}
			result.WriteString(v)
		} else {
			v, ok := values[p]
			if !ok {
				return "", false
			}
			result.WriteString(v)
		}
	}
	return result.String(), true
}
func main() {
	java := flag.String("java", "../ah5-core-java-spring", "Java source root")
	common := flag.String("common", "../ah5-common-java-spring", "shared Java source root")
	output := flag.String("out", "", "optional generated JSON output path")
	flag.Parse()
	constants := map[string]string{}
	unresolved := map[string]string{}
	for _, root := range []string{*java, *common} {
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == "target" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(d.Name(), "Constants.java") {
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
				unresolved[class+"."+m[1]] = strings.Join(parts, " + ")
			}
			return nil
		})
		if err != nil {
			fail(err)
		}
	}
	for i := 0; i < 30; i++ {
		changed := false
		for k, expr := range unresolved {
			if v, ok := eval(expr, constants); ok {
				constants[k] = v
				delete(unresolved, k)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	request := regexp.MustCompile(`@RequestMapping\(([^\n]+)\)`)
	mapping := regexp.MustCompile(`@(Get|Post|Put|Delete)Mapping\(path\s*=\s*([^,)]+)`)
	reports := []report{}
	for _, role := range []string{"authentication", "consumer-authorization", "serviceorchestration-dynamic", "serviceorchestration-simple"} {
		s, e := core.OpenStore("")
		if e != nil {
			fail(e)
		}
		a, e := core.New(core.Config{Role: role}, s, nil)
		if e != nil {
			fail(e)
		}
		available := map[string]bool{}
		for _, r := range a.Routes {
			available[r.Method+" "+r.Path] = true
		}
		rep := report{Role: role, Routes: []route{}, Unresolved: []string{}}
		e = filepath.WalkDir(filepath.Join(*java, role, "src/main/java"), func(path string, d os.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() || !strings.Contains(filepath.ToSlash(path), "/api/http/") || !strings.HasSuffix(path, "API.java") {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			baseExpr := request.FindSubmatch(b)
			if len(baseExpr) < 2 {
				return nil
			}
			base, ok := eval(string(baseExpr[1]), constants)
			if !ok {
				rep.Unresolved = append(rep.Unresolved, string(baseExpr[1]))
				return nil
			}
			sum := sha256.Sum256(b)
			rel, _ := filepath.Rel(*java, path)
			for _, m := range mapping.FindAllSubmatch(b, -1) {
				suffix, ok := eval(string(m[2]), constants)
				if !ok {
					rep.Unresolved = append(rep.Unresolved, string(m[2]))
					continue
				}
				method := strings.ToUpper(string(m[1]))
				rep.Routes = append(rep.Routes, route{method, base + suffix, rel, hex.EncodeToString(sum[:]), available[method+" "+base+suffix]})
			}
			return nil
		})
		if e != nil {
			fail(e)
		}
		sort.Slice(rep.Routes, func(i, j int) bool {
			return rep.Routes[i].Path+rep.Routes[i].Method < rep.Routes[j].Path+rep.Routes[j].Method
		})
		reports = append(reports, rep)
	}
	b, e := json.MarshalIndent(map[string]any{"notice": "Route presence only. Does not establish DTO, security, persistence, MQTT or behavioral equivalence. ServiceRegistry is a separately tested pre-existing module.", "systems": reports}, "", "  ")
	if e != nil {
		fail(e)
	}
	b = append(b, '\n')
	if *output != "" {
		if e = os.WriteFile(*output, b, 0644); e != nil {
			fail(e)
		}
	} else {
		fmt.Print(string(b))
	}
	missing := 0
	for _, r := range reports {
		for _, v := range r.Routes {
			if !v.GoRoutePresent {
				missing++
			}
		}
		missing += len(r.Unresolved)
	}
	if missing > 0 {
		fmt.Fprintf(os.Stderr, "%d missing or unresolved HTTP routes\n", missing)
		os.Exit(1)
	}
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(2) }
