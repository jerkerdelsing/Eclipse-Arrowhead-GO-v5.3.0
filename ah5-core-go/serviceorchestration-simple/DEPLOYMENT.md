# SimpleStoreServiceOrchestration standalone build and deployment

Requires Go 1.26+ (verified toolchain recorded in the distribution verification report). Dockerfiles default to the locally available Go 1.27 Alpine builder; override `GO_IMAGE` when pinning a release builder.

`make build` creates `bin/SimpleStoreServiceOrchestration` from this directory with `GOWORK=off`. `make test` runs the retained tests with the race detector; `make vet` checks this module. `make image` builds `eclipse-arrowhead/simplestoreserviceorchestration-go:5.2.2` using this folder as the entire build context.

The illustrative configuration is `config/config.json`. It derives from the supplied upstream example and requires provisioning for the target cloud. Original examples remain in the source/provenance documentation. No active-cloud credentials are included.

For container use, run `make prepare` to create private bind-mount directories and a local .env containing your numeric UID/GID. Provision the system certificate/key and trust material under certs/, identity passwords under secrets/, and its own state directory. Set ARROWHEAD_NETWORK to the existing cloud network and set upstream addresses and registration policies for that cloud. Then run `docker compose up -d --build`. HOST_PORT can override the loopback-only published port. The service runs as the prepared UID/GID so the private state directory is writable.

Core authority services, brokers, configured external providers, registration policies and federation dependencies are not embedded in this service template. Templates are not an instruction to replace a running cloud. No deployment is performed as part of this reorganization. Retained native-Go compatibility limits and test-only providers are documented upstream.
