GO ?= go
DOCKER ?= docker
IMAGE ?= eclipse-arrowhead/localcloudconfigurator-go:5.2.2
CLOUD_DIR ?= ../../Arrowhead/Arrowhead-test-cloud-go
CATALOG ?= catalogs/gocloud.json
COLONY ?= arrowhead
STACK := $(DOCKER) compose -f deploy/colonyos/compose.yaml
SECRETS := deploy/colonyos/secrets
.PHONY: build test vet image keygen stack-up register up executor executor-start executor-stop down status smoke clean

build:
	mkdir -p bin
	GOWORK=off $(GO) build -trimpath -o bin/LocalCloudConfigurator ./cmd/localcloudconfigurator
test:
	GOWORK=off $(GO) test -race ./...
vet:
	GOWORK=off $(GO) vet ./...
image:
	mkdir -p bin/linux
	GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH=$$($(DOCKER) version -f '{{.Server.Arch}}') $(GO) build -trimpath -o bin/linux/localcloudconfigurator ./cmd/localcloudconfigurator
	$(DOCKER) build -t $(IMAGE) .

# ColonyOS stack: secrets, server + database + API, then the colony and the two identities.
keygen: build
	./bin/LocalCloudConfigurator keygen -dir $(SECRETS)
stack-up: keygen image
	LCC_COLONY=$(COLONY) $(STACK) up -d --wait timescaledb
	LCC_COLONY=$(COLONY) $(STACK) up -d colonies-server
	@for i in $$(seq 1 40); do curl -fsS -o /dev/null http://127.0.0.1:50080/ 2>/dev/null && break; \
	  $(STACK) logs colonies-server 2>/dev/null | grep -qi 'started\|listening' && break; sleep 1; done
register: build
	./bin/LocalCloudConfigurator register -dir $(SECRETS) -catalog $(CATALOG) -colony $(COLONY)
up: stack-up register
	LCC_COLONY=$(COLONY) $(STACK) up -d localcloudconfigurator
	@echo "UI: http://127.0.0.1:8095  (operator token: $(SECRETS)/lcc_api_token)"

# Cloud executor on the cloud host (needs docker compose, curl and jq like the cloud's own scripts).
EXECUTOR_ENV := COLONIES_SERVER_HOST=127.0.0.1 COLONIES_SERVER_PORT=50080 COLONIES_COLONY_NAME=$(COLONY) \
	COLONIES_PRVKEY_FILE=$(SECRETS)/lcc_executor_prvkey
executor: build
	$(EXECUTOR_ENV) ./bin/LocalCloudConfigurator executor -catalog $(CATALOG) -cloud-dir $(CLOUD_DIR)
executor-start: build
	@mkdir -p state && chmod 700 state
	@if [ -f state/executor.pid ] && kill -0 $$(cat state/executor.pid) 2>/dev/null; then echo "executor already running"; else \
	  $(EXECUTOR_ENV) nohup ./bin/LocalCloudConfigurator executor -catalog $(CATALOG) -cloud-dir $(CLOUD_DIR) >state/executor.log 2>&1 & \
	  echo $$! > state/executor.pid; echo "executor started (state/executor.log)"; fi
executor-stop:
	@if [ -f state/executor.pid ]; then kill $$(cat state/executor.pid) 2>/dev/null || true; rm -f state/executor.pid; fi

status:
	$(STACK) ps
smoke: build
	./scripts/smoke.sh
down: executor-stop
	$(STACK) down
clean:
	rm -rf bin
