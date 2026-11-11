// SPDX-License-Identifier: EPL-2.0
package main

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Endpoint principles: a configured listening port and a predefined default.
// serve listens at, highest precedence first: -server.port N, SERVER_PORT=N (port only, host of -listen kept),
// -listen host:port, DefaultListen.
const DefaultListen = "127.0.0.1:8095"

// ResolveListen applies the SERVER_PORT value (env, may be empty) and the -server.port flag (0 = absent) to listen.
func ResolveListen(listen, env string, flagPort int) (string, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("invalid -listen %q: %w", listen, err)
	}
	port := 0
	if strings.TrimSpace(env) != "" {
		if port, err = strconv.Atoi(strings.TrimSpace(env)); err != nil || port < 1 || port > 65535 {
			return "", errors.New("SERVER_PORT: listening port must be an integer in 1..65535")
		}
	}
	if flagPort != 0 {
		if flagPort < 1 || flagPort > 65535 {
			return "", errors.New("-server.port: listening port must be an integer in 1..65535")
		}
		port = flagPort
	}
	if port == 0 {
		return listen, nil
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
