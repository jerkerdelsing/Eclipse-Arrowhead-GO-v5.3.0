GO ?= go
DOCKER ?= docker
.PHONY: build test vet verify
build test vet:
	@python3 tools/run-all.py $@ --go "$(GO)"
verify:
	@python3 tools/verify-layout.py

.PHONY: isolation images
isolation:
	GO="$(GO)" python3 tools/check-isolation.py
images:
	DOCKER="$(DOCKER)" python3 tools/check-images.py
