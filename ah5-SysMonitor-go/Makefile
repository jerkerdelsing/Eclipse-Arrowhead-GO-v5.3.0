GO ?= go
DOCKER ?= docker
IMAGE ?= eclipse-arrowhead/sysmonitor-go:5.2.2
.PHONY: build test vet image prepare run clean
build:
	mkdir -p bin
	GOWORK=off $(GO) build -trimpath -o bin/SysMonitor ./cmd/sysmonitor
test:
	GOWORK=off $(GO) test -race ./...
vet:
	GOWORK=off $(GO) vet ./...
image:
	$(DOCKER) build -t $(IMAGE) .
prepare:
	mkdir -p state certs secrets
	chmod 700 state certs secrets
	@test -e .env || printf 'ARROWHEAD_UID=%s\nARROWHEAD_GID=%s\n' "$$(id -u)" "$$(id -g)" > .env
run: build
	./bin/SysMonitor -config config/config.json
clean:
	rm -f bin/SysMonitor
