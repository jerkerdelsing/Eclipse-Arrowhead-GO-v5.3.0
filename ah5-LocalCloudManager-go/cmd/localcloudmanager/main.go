// SPDX-License-Identifier: EPL-2.0
package main

import (
	"arrowhead/ah5-support-go/localcloudmanager/internal/cloud"
	"fmt"
	"log"
	"os"
	"strings"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "--help" || os.Args[1] == "-h") {
		fmt.Println("LocalCloudManager: native Go operator console. Configure through environment variables; see README.md. Default system listener :8480 (mutual TLS); override with --server.port N or SERVER_PORT=N.")
		return
	}
	if role := os.Getenv("ARROWHEAD_ROLE"); role != "" && role != "localcloudmanager" {
		log.Fatal("This executable only runs the localcloudmanager role")
	}
	// Endpoint principles: listening port = --server.port > SERVER_PORT > PORT > default 8480.
	args := os.Args[1:]
	if len(args) == 1 && strings.HasPrefix(strings.TrimLeft(args[0], "-"), "server.port=") {
		args = []string{args[0][:strings.Index(args[0], "=")], args[0][strings.Index(args[0], "=")+1:]}
	}
	if len(args) == 2 && (args[0] == "--server.port" || args[0] == "-server.port") {
		if err := os.Setenv("SERVER_PORT", args[1]); err != nil {
			log.Fatal(err)
		}
		args = nil
	}
	if len(args) > 0 {
		log.Fatal("Unknown argument; use --help")
	}
	if err := os.Setenv("ARROWHEAD_ROLE", "localcloudmanager"); err != nil {
		log.Fatal(err)
	}
	app, err := cloud.NewFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	if err = app.Run(); err != nil {
		log.Fatal(err)
	}
}
