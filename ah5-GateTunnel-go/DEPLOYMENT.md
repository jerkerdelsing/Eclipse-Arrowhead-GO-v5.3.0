# GateTunnel standalone build and deployment

Requires Go 1.26+ (verified toolchain recorded in the distribution verification report). Dockerfiles default to the locally available Go 1.27 Alpine builder; override `GO_IMAGE` when pinning a release builder.

`make build` creates `bin/GateTunnel` from this directory with `GOWORK=off`. `make test` runs the retained tests with the race detector; `make vet` checks this module. `make image` builds `eclipse-arrowhead/gatetunnel-go:5.2.2` using this folder as the entire build context.

The illustrative configuration is `config/config.json`. It derives from the supplied upstream example and requires provisioning for the target cloud. Original examples remain in the source/provenance documentation. No active-cloud credentials are included.

For container use, run `make prepare` to create private bind-mount directories and a local .env containing your numeric UID/GID. Provision the system certificate/key and trust material under certs/, identity passwords under secrets/, and its own state directory. Set ARROWHEAD_NETWORK to the existing cloud network and set upstream addresses and registration policies for that cloud. Then run `docker compose up -d --build`. HOST_PORT can override the loopback-only published port. The service runs as the prepared UID/GID so the private state directory is writable.

Core authority services, brokers, configured external providers, registration policies and federation dependencies are not embedded in this service template. Templates are not an instruction to replace a running cloud. No deployment is performed as part of this reorganization. Retained native-Go compatibility limits and test-only providers are documented upstream.

## AH-GT-1 peer revocation (SOS-4, 2026-11-10)

With `FEDERATION_PROFILE=ah-gt-1` the GateTunnel needs `RELAY_CRL_FILES`: the CRL files of the organization CA and of
every peer cloud's CA, comma-separated (PEM or DER), next to `RELAY_KEY`, `RELAY_CHAIN_CERT` and `RELAY_CA_CERT`. It
refuses to start without them or when a file holds no CRL. In every key exchange the peer's relay certificate must not
be listed by a current CRL of its cloud CA, and its cross-certificate not by a current CRL of the organization CA; a
missing, forged or out-of-date CRL refuses the session. The files are read again for each key exchange, so mount the
directories the CAs update (read-only, e.g. `/peer-crl/TestCloud/ca.crl`), not copies. The check lives in the shared
`internal/relay/session_security.go`, identical in every module; only the GateTunnel role loads it.
