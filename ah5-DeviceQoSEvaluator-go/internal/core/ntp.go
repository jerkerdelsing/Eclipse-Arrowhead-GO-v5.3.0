// SPDX-License-Identifier: EPL-2.0
package core

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http"
	"strings"
	"time"
)

func (a *App) timeTrust(r *http.Request) Document {
	out := Document{"trusted": false, "offsetMs": nil, "server": nil, "checkedAt": nil}
	if a.Config.NTPServer == "" {
		return out
	}
	server := a.Config.NTPServer
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "123")
	}
	out["server"] = server
	out["checkedAt"] = now()
	conn, e := net.DialTimeout("udp", server, time.Second)
	if e != nil {
		return out
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	packet := make([]byte, 48)
	packet[0] = 0x23
	_, _ = rand.Read(packet[40:48])
	nonce := append([]byte(nil), packet[40:48]...)
	sent := time.Now()
	if _, e = conn.Write(packet); e != nil {
		return out
	}
	n, e := conn.Read(packet)
	received := time.Now()
	if e != nil || n != 48 || packet[0]>>6 == 3 || packet[0]&7 != 4 || packet[1] == 0 || packet[1] > 15 {
		return out
	}
	for i := range nonce {
		if packet[24+i] != nonce[i] {
			return out
		}
	}
	seconds := int64(binary.BigEndian.Uint32(packet[40:44])) - 2208988800
	fraction := int64(binary.BigEndian.Uint32(packet[44:48]))
	remote := time.Unix(seconds, (fraction*1000000000)>>32)
	mid := sent.Add(received.Sub(sent) / 2)
	offset := remote.Sub(mid).Seconds() * 1000
	out["offsetMs"] = offset
	out["trusted"] = offset > -1000 && offset < 1000
	return out
}
