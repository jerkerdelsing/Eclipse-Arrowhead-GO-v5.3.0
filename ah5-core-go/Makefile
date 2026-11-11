GO ?= go
.PHONY: build test vet
build test vet:
	@for system in authentication consumer-authorization serviceorchestration-dynamic serviceorchestration-simple serviceregistry; do $(MAKE) -C $$system $@ GO=$(GO) || exit; done
