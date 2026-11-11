// SPDX-License-Identifier: EPL-2.0
package core

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Endpoint principles (2026-11-09): every system has
//  1. a configured listening port, where it accepts connections, and
//  2. a predefined default, so that a first deployment works without extra configuration.
//
// Effective listening address, highest precedence first:
//
//	-server.port / --server.port N   command-line flag (port only, host kept)
//	SERVER_PORT=N                    environment variable (port only, host kept)
//	"listen": "host:port"            configuration file
//	DefaultListenHost:DefaultPorts   built-in default
//
// The names match Spring Boot (server.port, SERVER_PORT, --server.port) used by the Java implementation, and the
// default ports are the Arrowhead 5 defaults of the Java packaging. advertisePort is not changed: it is the port
// published to the ServiceRegistry and may differ (e.g. a Docker host port).

// PortEnv is the environment variable that overrides the configured listening port.
const PortEnv = "SERVER_PORT"

// PortFlag is the command-line flag that overrides SERVER_PORT and the configured listening port.
const PortFlag = "server.port"

// DefaultListenHost is the built-in listen host; deployments that need remote access configure "listen".
const DefaultListenHost = "127.0.0.1"

// DefaultPorts holds the built-in listening port of every core and support role.
var DefaultPorts = map[string]int{
	// Core systems (role identifiers of ah5-core-go).
	"serviceorchestration-dynamic": 8441,
	"serviceorchestration-simple":  8442,
	"serviceregistry":              8443,
	"authentication":               8444,
	"consumer-authorization":       8445,
	// Support systems (system names).
	"PlantDescriptionEngine": 8432,
	"Onboarding":             8435,
	"CertificateAuthority":   8448,
	"Gatekeeper":             8449,
	"GateTunnel":             8453,
	"EventHandler":           8455,
	"Choreographer":          8457,
	"Configuration":          8459,
	"DataManager":            8461,
	"TimeManager":            8463,
	"Blacklist":              8464,
	"TranslationManager":     8465,
	"DeviceQoSEvaluator":     8472,
	"SysMonitor":             8475,
	"AIGym":                  8478,
	"TestTranslation":        8552, // Go-only test system; no Java counterpart
}

// DefaultListen returns the built-in listen address of a role.
func DefaultListen(role string) (string, error) {
	port, ok := DefaultPorts[role]
	if !ok {
		return "", fmt.Errorf("no default listening port for role %q", role)
	}
	return net.JoinHostPort(DefaultListenHost, strconv.Itoa(port)), nil
}

// ParsePort validates a TCP port number given as text.
func ParsePort(s string) (int, error) {
	p, e := strconv.Atoi(strings.TrimSpace(s))
	if e != nil || p < 1 || p > 65535 {
		return 0, errors.New("listening port must be an integer in 1..65535")
	}
	return p, nil
}

// ApplyPort replaces the port of c.Listen, keeping its host. A port of 0 leaves the configuration unchanged.
func ApplyPort(c *Config, port int) error {
	if port == 0 {
		return nil
	}
	if port < 1 || port > 65535 {
		return errors.New("listening port must be an integer in 1..65535")
	}
	host, _, e := net.SplitHostPort(c.Listen)
	if e != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.Listen, e)
	}
	c.Listen = net.JoinHostPort(host, strconv.Itoa(port))
	return nil
}

// resolveListen applies the built-in default and the SERVER_PORT override; LoadConfig calls it.
func resolveListen(c *Config, role string) error {
	if c.Listen == "" {
		def, e := DefaultListen(role)
		if e != nil {
			return e
		}
		c.Listen = def
	}
	if _, _, e := net.SplitHostPort(c.Listen); e != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.Listen, e)
	}
	if v := os.Getenv(PortEnv); v != "" {
		p, e := ParsePort(v)
		if e != nil {
			return fmt.Errorf("%s: %w", PortEnv, e)
		}
		return ApplyPort(c, p)
	}
	return nil
}
