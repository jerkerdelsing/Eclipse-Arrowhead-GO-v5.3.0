// SPDX-License-Identifier: EPL-2.0
package core

import (
	"encoding/json"
	"testing"
)

func TestSnapshotKeepsUnavailableScopeAndMinimumPriority(t *testing.T) {
	var input Document
	json.Unmarshal([]byte(`{"systems":[{"systemId":"c","systemName":"Consumer","ports":[{"portName":"in","consumer":true,"serviceDefinition":"temperature"}]},{"systemId":"p","systemName":"Sensor","ports":[{"portName":"out","serviceDefinition":"temperature"}]}],"connections":[{"consumer":{"systemId":"c","portName":"in"},"producer":{"systemId":"p","portName":"out"},"priority":4},{"consumer":{"systemId":"c","portName":"in"},"producer":{"systemId":"p","portName":"out"},"priority":0}]}`), &input)
	docs := func(key string) []Document {
		out := []Document{}
		for _, v := range list(input, key) {
			out = append(out, v.(Document))
		}
		return out
	}
	unavailable := resolveSnapshot(docs("systems"), docs("connections"), nil, nil)
	rules := list(unavailable, "rules")
	if len(rules) != 1 || len(list(rules[0].(Document), "providers")) != 0 {
		t.Fatal(unavailable)
	}
	available := resolveSnapshot(docs("systems"), docs("connections"), []Document{{"name": "Sensor"}}, []Document{{"instanceId": "Sensor|temperature|1.0.0", "provider": Document{"name": "Sensor"}, "serviceDefinition": Document{"name": "temperature"}}})
	providers := list(list(available, "rules")[0].(Document), "providers")
	if len(providers) != 1 || number(providers[0].(Document), "priority", 99) != 0 {
		t.Fatal(available)
	}
}

func TestPlantManagementPublishesReadAliases(t *testing.T) {
	f := newFixture(t, "PlantDescriptionEngine")
	for _, svc := range f.app.Services() {
		if svc.Definition == "plantDescriptionManagement" {
			if svc.BasePath != "/plantdescriptionengine/mgmt" {
				t.Fatal(svc.BasePath)
			}
			for _, pair := range [][2]string{{"query", "query-plant-descriptions"}, {"get", "get-plant-description"}} {
				if svc.Operations[pair[0]] == nil || str(svc.Operations[pair[0]], "path") != str(svc.Operations[pair[1]], "path") {
					t.Fatal(pair, svc.Operations)
				}
			}
			return
		}
	}
	t.Fatal("plant management service not registered")
}
