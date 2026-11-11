// Command localcloudconfigurator fills an Arrowhead 5.2.2 local cloud with the support and application systems an
// operator picks. Subcommands:
//
//	serve     HTTP API and operator UI; submits deployment plans to ColonyOS
//	executor  ColonyOS executor on the cloud host; carries out the plan steps
//	keygen    create the ColonyOS stack's secret files
//	register  create the colony and register/approve the API and executor identities
//	apply     ask a running API for a deployment and wait for its result (CLI and smoke test)
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/api"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/colony"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/planner"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/runner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: localcloudconfigurator serve|executor|keygen|register|apply [flags]")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "executor":
		err = executor(args)
	case "keygen":
		err = keygen(args)
	case "register":
		err = register(args)
	case "apply":
		err = apply(args)
	default:
		err = fmt.Errorf("unknown subcommand %q", cmd)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fs.String("listen", DefaultListen, "listen address")
	port := fs.Int("server.port", 0, "listening port; overrides SERVER_PORT and the port of -listen")
	cat := fs.String("catalog", "catalogs/gocloud.json", "cloud catalog")
	tokenFile := fs.String("token-file", os.Getenv("LCC_API_TOKEN_FILE"), "operator token file")
	_ = fs.Parse(args)
	addr, err := ResolveListen(*listen, os.Getenv("SERVER_PORT"), *port)
	if err != nil {
		return err
	}
	listen = &addr
	c, err := catalog.Load(*cat)
	if err != nil {
		return err
	}
	token, err := readSecret(*tokenFile)
	if err != nil {
		return fmt.Errorf("operator token: %w", err)
	}
	cfg, err := colony.ConfigFromEnv()
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: *listen, Handler: (&api.Server{Catalog: c, Backend: colony.New(cfg), Token: token}).Handler(),
		ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signalContext()
	defer stop()
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	log.Printf("LocalCloudConfigurator for %s on %s", c.Cloud, *listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func executor(args []string) error {
	fs := flag.NewFlagSet("executor", flag.ExitOnError)
	cat := fs.String("catalog", "catalogs/gocloud.json", "cloud catalog")
	dir := fs.String("cloud-dir", "", "local cloud directory (holds compose.yaml and scripts/)")
	_ = fs.Parse(args)
	c, err := catalog.Load(*cat)
	if err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("-cloud-dir is required")
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(abs, "compose.yaml")); err != nil {
		return fmt.Errorf("cloud dir: %w", err)
	}
	cfg, err := colony.ConfigFromEnv()
	if err != nil {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	log.Printf("cloud executor for %s (%s) in %s", c.Cloud, c.ExecutorType, abs)
	return colony.New(cfg).Serve(ctx, &runner.Runner{Catalog: c, CloudDir: abs, Cmd: runner.ExecCommander{}}, log.Printf)
}

// Secret file names in the stack's secrets directory.
var secretFiles = map[string]string{
	"COLONIES_SERVER_PRVKEY": "colonies_server_prvkey",
	"COLONIES_SERVER_ID":     "colonies_server_id",
	"COLONIES_COLONY_PRVKEY": "colonies_colony_prvkey",
	"LCC_API_PRVKEY":         "lcc_api_prvkey",
	"LCC_EXECUTOR_PRVKEY":    "lcc_executor_prvkey",
	"COLONIES_DB_PASSWORD":   "colonies_db_password",
	"LCC_API_TOKEN":          "lcc_api_token",
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("dir", "deploy/colonyos/secrets", "secrets directory")
	force := fs.Bool("force", false, "replace existing secrets")
	_ = fs.Parse(args)
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(*dir, "lcc_api_token")); err == nil && !*force {
		fmt.Println("secrets exist; keeping them (use -force to replace)")
		return nil
	}
	vals, err := colony.GenerateSecrets()
	if err != nil {
		return err
	}
	for k, f := range secretFiles {
		if err := os.WriteFile(filepath.Join(*dir, f), []byte(vals[k]+"\n"), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %d secret files to %s\n", len(secretFiles), *dir)
	return nil
}

func register(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	dir := fs.String("dir", "deploy/colonyos/secrets", "secrets directory")
	cat := fs.String("catalog", "catalogs/gocloud.json", "cloud catalog")
	host := fs.String("host", "127.0.0.1", "ColonyOS server host")
	port := fs.Int("port", 50080, "ColonyOS server port")
	colonyName := fs.String("colony", "arrowhead", "colony name")
	execName := fs.String("executor-name", "", "cloud executor name (default <cloud>-executor)")
	_ = fs.Parse(args)
	c, err := catalog.Load(*cat)
	if err != nil {
		return err
	}
	read := func(k string) string {
		v, err2 := readSecret(filepath.Join(*dir, secretFiles[k]))
		if err2 != nil && err == nil {
			err = err2
		}
		return v
	}
	r := colony.Registration{Host: *host, Port: *port, ColonyName: *colonyName,
		ServerPrvKey: read("COLONIES_SERVER_PRVKEY"), ColonyPrvKey: read("COLONIES_COLONY_PRVKEY"),
		APIPrvKey: read("LCC_API_PRVKEY"), ExecutorPrvKey: read("LCC_EXECUTOR_PRVKEY"),
		ExecutorType: c.ExecutorType, ExecutorName: *execName}
	if err != nil {
		return err
	}
	if r.ExecutorName == "" {
		r.ExecutorName = strings.ToLower(c.Cloud) + "-executor"
	}
	if err := colony.Register(r); err != nil {
		return err
	}
	fmt.Printf("colony %s ready; executors lcc-api and %s approved\n", r.ColonyName, r.ExecutorName)
	return nil
}

func apply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	url := fs.String("url", "http://127.0.0.1:8095", "API base URL")
	tokenFile := fs.String("token-file", "deploy/colonyos/secrets/lcc_api_token", "operator token file")
	systems := fs.String("systems", "", "comma-separated systems that should run")
	remove := fs.String("remove", "", "comma-separated systems to stop")
	smoke := fs.Bool("smoke", false, "run the catalog smoke tests")
	reapply := fs.Bool("reapply", false, "re-run provisioning and policy scripts")
	timeout := fs.Duration("timeout", 30*time.Minute, "overall wait")
	_ = fs.Parse(args)
	token, err := readSecret(*tokenFile)
	if err != nil {
		return err
	}
	req := planner.Request{Systems: split(*systems), Remove: split(*remove), Smoke: *smoke, Reapply: *reapply}
	var res struct {
		ID   string        `json:"id"`
		Plan *planner.Plan `json:"plan"`
	}
	if err := httpJSON("POST", *url+"/api/deployments", token, req, &res); err != nil {
		return err
	}
	for i, s := range res.Plan.Steps {
		fmt.Printf("  %2d. %-9s %s\n", i+1, s.Kind, s.Target)
	}
	for _, n := range res.Plan.Notes {
		fmt.Println("  note:", n)
	}
	if res.ID == "" {
		fmt.Println("nothing to deploy")
		return nil
	}
	fmt.Println("workflow", res.ID)
	deadline := time.Now().Add(*timeout)
	seen := map[string]string{}
	for time.Now().Before(deadline) {
		var d colony.Deployment
		if err := httpJSON("GET", *url+"/api/deployments/"+res.ID, token, nil, &d); err != nil {
			return err
		}
		for _, s := range d.Steps {
			if seen[s.Node] != s.State {
				seen[s.Node] = s.State
				fmt.Printf("  %-45s %s %s\n", s.Node, s.State, strings.Join(s.Errors, "; "))
			}
		}
		switch d.State {
		case "success":
			fmt.Println("deployment succeeded")
			return nil
		case "failed":
			return errors.New("deployment failed")
		}
		time.Sleep(2 * time.Second)
	}
	return errors.New("deployment timed out")
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func httpJSON(method, url, token string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s %s: %s: %s", method, url, resp.Status, strings.TrimSpace(string(data)))
	}
	return json.Unmarshal(data, out)
}
