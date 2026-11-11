// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"
)

type textResponse string
type binaryResponse struct {
	Data        []byte
	ContentType string
}

func digest(v string) string { d := sha256.Sum256([]byte(v)); return hex.EncodeToString(d[:]) }
func nextID(d database, kind string) (string, float64) {
	n := float64(number(d["sequence"][kind], "value", 0) + 1)
	bucket(d, "sequence")[kind] = Document{"value": n}
	return strconv.FormatInt(int64(n), 10), n
}
func timeRange(value, from, to string) bool {
	v, e := time.Parse(time.RFC3339Nano, value)
	if e != nil {
		return false
	}
	if from != "" {
		f, e := time.Parse(time.RFC3339Nano, from)
		if e != nil || v.Before(f) {
			return false
		}
	}
	if to != "" {
		t, e := time.Parse(time.RFC3339Nano, to)
		if e != nil || v.After(t) {
			return false
		}
	}
	return true
}
func (a *App) authorize(r *http.Request, definition, operation string) error {
	if a.Config.AuthorizationPolicy == "identity-only" {
		return nil
	}
	var granted bool
	e := a.Remote.Call(r.Context(), "authorization", "POST", "/consumerauthorization/authorization/verify", Document{"provider": a.Config.Name, "consumer": caller(r).Name, "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": definition, "scope": operation}, &granted)
	if e != nil {
		return e
	}
	if !granted {
		return forbidden()
	}
	return nil
}
func (a *App) serviceRoute(method, path, definition, operation string, fn endpoint) {
	a.route(method, path, "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		if e := a.authorize(r, definition, operation); e != nil {
			return nil, 0, e
		}
		return fn(w, r)
	})
	a.Routes[len(a.Routes)-1].Service = definition
	a.Routes[len(a.Routes)-1].Operation = operation
}
func (a *App) row(table, id string) (Document, error) {
	var row Document
	e := a.Store.View(func(d database) error {
		row = d[table][id]
		if row == nil {
			return &APIError{404, "Record not found"}
		}
		return nil
	})
	return row, e
}
func (a *App) rows(table string) []Document {
	out := []Document{}
	_ = a.Store.ViewTables(func(d database) error {
		for _, r := range d[table] {
			out = append(out, r)
		}
		return nil
	}, table)
	return out
}
func queryDoc(r *http.Request) Document {
	d := Document{}
	p := Document{}
	for k, vs := range r.URL.Query() {
		v := vs[0]
		switch k {
		case "page", "size":
			n, e := strconv.Atoi(v)
			if e == nil {
				p[k] = float64(n)
			} else {
				p[k] = v
			}
		case "direction", "sortField", "sort_field":
			if k == "sort_field" {
				k = "sortField"
			}
			p[k] = v
		default:
			d[k] = v
		}
	}
	if len(p) > 0 {
		d["pagination"] = p
	}
	return d
}
func decodeAny(w http.ResponseWriter, r *http.Request) (any, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	var v any
	if e := dec.Decode(&v); e != nil {
		return nil, bad("Invalid JSON")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return nil, bad("Multiple JSON values")
	}
	return v, nil
}
func (a *App) consume(ctx context.Context, name, method, path string, in, out any) error {
	origin := a.Config.Upstreams[name]
	if origin == "" {
		return &APIError{503, "No explicit upstream configured for " + name}
	}
	system := name
	if pinned := a.Config.UpstreamSystems[name]; pinned != "" {
		system = pinned
	}
	return a.Remote.callAt(ctx, system, origin, method, path, in, out)
}
func removeRow(a *App, table, id string) (Document, error) {
	var row Document
	e := a.Store.Update(func(d database) error {
		row = d[table][id]
		if row == nil {
			return &APIError{404, "Record not found"}
		}
		delete(d[table], id)
		return nil
	})
	return row, e
}
func active(row Document) bool {
	return flag(row, "active") && (str(row, "expiresAt") == "" || !expired(str(row, "expiresAt")))
}
