2026-10-23: PDE now synchronizes durable DSO plant-rule snapshots. [API, deployment and verification guide](docs/PDE-DSO.md).

# Arrowhead core systems in Go

Native Go source for the five core modules in the local `ah5-core-java-spring` 5.2.2 reference. The existing ServiceRegistry is retained, with a v5.2.2 authorization-contract correction; the other four implementations are new. No Java subprocess or Python implementation is used by the core executables.

**Status: working secure HTTP profile, not complete Java feature equivalence or a production-qualified replacement.** All 61 HTTP routes discovered in the four newly ported Java modules have handlers. Route presence is not proof of behavioral conformance. The MQTT API is served since 2026-10-24 (with the differences listed there); several Java framework behaviors remain unimplemented; see [COMPATIBILITY.md](docs/COMPATIBILITY.md) before considering a deployment.

| Java core module | Go source | Executable |
| --- | --- | --- |
| serviceregistry | `ServiceRegistry/` (existing separate module) | `bin/serviceregistry` |
| authentication | `authentication/`, shared `internal/core/` | `bin/authentication` |
| consumer-authorization | `consumer-authorization/`, shared `internal/core/` | `bin/consumer-authorization` |
| serviceorchestration-dynamic | `serviceorchestration-dynamic/`, shared `internal/core/` | `bin/serviceorchestration-dynamic` |
| serviceorchestration-simple | `serviceorchestration-simple/`, shared `internal/core/` | `bin/serviceorchestration-simple` |

The two orchestration variants are separate systems implementing the same orchestration API. Normally choose one for a cloud. Deploy both only with distinct identities, ports and state files and deliberate service selection.

## Build and verify

Go 1.26 or newer, Unix/macOS/Linux, and Make are required. The implementation was tested with Go 1.27.1 on macOS ARM64.

```sh
make build
make vet
make test
make contracts
```

`make test` builds all five binaries, runs race-checked root tests including a temporary ServiceRegistry process, and runs the separate ServiceRegistry tests. Tests generate isolated PKI and temporary state, use random localhost ports, and never target the deployed test clouds. Running `go test ./...` alone does not test the nested ServiceRegistry module; the native-process test skips if its binary has not been built.

`make contracts` reads sibling Java core/common source trees and regenerates [contracts.json](contracts.json), including controller source hashes. It fails on unresolved or missing HTTP routes. It does **not** certify DTO validation, Java interoperability, optional integration behavior or MQTT support.

## Running

The four new executables accept `-config path/to/config.json`. Configuration templates in [examples/](examples/) contain file references, not credentials or CA private keys. They deliberately disable service registration until you configure identities, certificates and advertised addresses. ServiceRegistry retains its existing `.properties` configuration; do not use its historical insecure sample unchanged in a test cloud.

```sh
./bin/authentication -config examples/authentication.json
./bin/consumer-authorization -config examples/consumer-authorization.json
./bin/serviceorchestration-dynamic -config examples/serviceorchestration-dynamic.json
```

New systems require mutual TLS, trusted local-cloud certificates, and certificate/token identity binding. There is no HTTP, declared-identity or TLS-verification-disable switch. Configuration fails on unknown keys. Secret files must be owner-readable only (mode `0600` or stricter). Each process needs its own state file and certificate/private key. The cloud CA private key is neither needed nor loaded.

See [OPERATIONS.md](docs/OPERATIONS.md) for bootstrap and integration requirements, [SECURITY.md](docs/SECURITY.md) for the threat boundaries, and [VERIFICATION.md](docs/VERIFICATION.md) for evidence and limits.

## Reference and license

Behavior and contracts were derived from the local `ah5-core-java-spring` and `ah5-common-java-spring` 5.2.2 code, particularly their HTTP APIs, DTO records, identity/password services, policy engine, token generator and orchestration utilities. The reference contains local security changes, so this is not an assertion of byte-for-byte correspondence to an upstream release tag. See [SOURCE-MAP.md](docs/SOURCE-MAP.md), `LICENSE` and `NOTICE.md`.

This change delivers source and documentation only. It does not replace deployed containers, restart Docker, migrate cloud databases, alter trust stores, rotate keys, or claim that earlier cloud security findings have been remediated.
