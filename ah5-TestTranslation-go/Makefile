GO ?= go
DOCKER ?= docker
IMAGE ?= eclipse-arrowhead/testtranslation-go:5.4.0
.PHONY: build test vet image prepare run clean
build:
	mkdir -p bin
	GOWORK=off $(GO) build -trimpath -o bin/TestTranslation ./cmd/testtranslation
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
	./bin/TestTranslation -config config/config.json
clean:
	rm -f bin/TestTranslation
