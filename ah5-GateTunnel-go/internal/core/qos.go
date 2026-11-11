// SPDX-License-Identifier: EPL-2.0
package core

import (
	"math"
	"net/http"
	"sort"
	"time"
)

func (a *App) qosRoutes() {
	b := "/deviceqosevaluator"
	for _, operation := range []string{"filter", "sort"} {
		op := operation
		a.serviceRoute("POST", b+"/qualityevaluation/"+op, "qualityEvaluation", op, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			providers := list(req, "providers")
			cfg := obj(req, "configuration")
			metrics := list(cfg, "metricNames")
			weights := list(cfg, "metricWeights")
			if len(providers) == 0 || len(metrics) == 0 || len(metrics) != len(weights) {
				return nil, 0, bad("providers and equally sized metricNames/metricWeights required")
			}
			threshold, _ := cfg["threshold"].(float64)
			window := number(cfg, "timeWindow", 300)
			if window < 1 {
				return nil, 0, bad("Positive timeWindow required")
			}
			type result struct {
				name    string
				score   float64
				missing []string
			}
			evaluated := []result{}
			warnings := Document{}
			for _, p := range providers {
				name, ok := p.(string)
				if !ok || !validName(name) {
					return nil, 0, bad("Invalid provider")
				}
				res := result{name: name}
				for i, m := range metrics {
					metric, ok := m.(string)
					weight, wok := weights[i].(float64)
					if !ok || !wok || math.IsNaN(weight) || math.IsInf(weight, 0) {
						return nil, 0, bad("Invalid metric/weight")
					}
					sum, count := 0.0, 0
					for _, row := range a.rows("measurements") {
						if str(row, "systemName") != name || str(row, "metricGroup") != metric {
							continue
						}
						t, e := time.Parse(time.RFC3339Nano, str(row, "timestamp"))
						if e != nil || time.Since(t) > time.Duration(window)*time.Second {
							continue
						}
						value, ok := row["current"].(float64)
						if ok {
							sum += value
							count++
						}
					}
					if count == 0 {
						res.missing = append(res.missing, metric)
						res.score = math.MaxFloat64
					} else if res.score != math.MaxFloat64 {
						res.score += sum / float64(count) * weight
					}
				}
				if len(res.missing) > 0 {
					warnings[name] = res.missing
				}
				evaluated = append(evaluated, res)
			}
			if op == "sort" {
				sort.SliceStable(evaluated, func(i, j int) bool { return evaluated[i].score < evaluated[j].score })
				names := []string{}
				for _, v := range evaluated {
					names = append(names, v.name)
				}
				return Document{"sortedProviders": names, "warnings": warnings}, 200, nil
			}
			passed, dropped := []string{}, []string{}
			for _, v := range evaluated {
				if len(v.missing) == 0 && v.score <= threshold {
					passed = append(passed, v.name)
				} else {
					dropped = append(dropped, v.name)
				}
			}
			return Document{"passedProviders": passed, "droppedProviders": dropped, "warnings": warnings}, 200, nil
		})
	}
	a.route("POST", b+"/mgmt/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		for _, row := range a.rows("measurements") {
			if !selected(req, "systemNames", str(row, "systemName")) || str(req, "metricGroup") != "" && str(req, "metricGroup") != str(row, "metricGroup") {
				continue
			}
			if !timeRange(str(row, "timestamp"), str(req, "from"), str(req, "to")) {
				continue
			}
			rows = append(rows, row)
		}
		v, e := page(rows, req, "records")
		return v, 200, e
	})
	a.route("POST", b+"/mgmt/reload", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		if a.Config.Upstreams["DeviceMeasurementAgent"] == "" {
			return nil, 0, &APIError{503, "No measurement agent is configured; existing measurements retained"}
		}
		var rows []Document
		if e := a.consume(r.Context(), "DeviceMeasurementAgent", "GET", "/measurements", nil, &rows); e != nil {
			return nil, 0, e
		}
		e := a.Store.Update(func(d database) error {
			for _, row := range rows {
				if e := require(row, "systemName", "metricGroup", "timestamp"); e != nil {
					return e
				}
				if _, ok := row["current"].(float64); !ok {
					return bad("Numeric measurement required")
				}
				bucket(d, "measurements")[uuid()] = row
			}
			return nil
		})
		return textResponse("Measurements reloaded"), 200, e
	})
}
