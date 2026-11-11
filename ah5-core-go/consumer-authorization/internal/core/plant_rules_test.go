// SPDX-License-Identifier: EPL-2.0
package core

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func plantDoc(t *testing.T, text string) Document {
	t.Helper()
	var d Document
	if e := json.Unmarshal([]byte(text), &d); e != nil {
		t.Fatal(e)
	}
	return d
}
func TestPlantSnapshotValidationPersistenceAndIntercloudGuard(t *testing.T) {
	s, e := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Store: s}
	valid := plantDoc(t, `{"rules":[{"consumer":"Consumer","serviceDefinition":"temperature","providers":[{"serviceInstanceId":"Sensor|temperature|1.0.0","priority":0}]},{"consumer":"Other","serviceDefinition":"temperature","providers":[]}]}`)
	n, e := normalizePlantRules(valid)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Update(func(d database) error { bucket(d, "plantRules")["active"] = n; return nil }); e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{`{}`, `{"rules":null}`, `{"rules":[{"consumer":"Consumer","serviceDefinition":"temperature","providers":null}]}`, `{"rules":[{"consumer":"Consumer","serviceDefinition":"temperature","providers":[{"serviceInstanceId":"x","priority":-1}]}]}`, `{"rules":[{"consumer":"Consumer","serviceDefinition":"temperature","providers":[{"serviceInstanceId":"x","priority":1},{"serviceInstanceId":"x","priority":0}]}]}`} {
		if _, e = normalizePlantRules(plantDoc(t, text)); e == nil {
			t.Fatal("accepted", text)
		}
	}
	ranks, managed, e := a.plantRanks("Consumer", "temperature")
	if e != nil || !managed || ranks["Sensor|temperature|1.0.0"] != 0 {
		t.Fatal(ranks, managed, e)
	}
	request := plantDoc(t, `{"serviceRequirement":{"serviceDefinition":"temperature"},"orchestrationFlags":{"ONLY_INTERCLOUD":true}}`)
	result, e := a.dynamicPull(httptest.NewRequest("POST", "/", nil), request, "Consumer", "")
	if e != nil || len(list(result, "results")) != 0 {
		t.Fatal(result, e)
	}
	s.Close()
	again, e := OpenStore(s.path)
	if e != nil {
		t.Fatal(e)
	}
	defer again.Close()
	a.Store = again
	_, managed, e = a.plantRanks("Other", "temperature")
	if e != nil || !managed {
		t.Fatal("empty scope lost", e)
	}
}
