# Verification — 2026-10-16

Environment: Go 1.27.1, macOS ARM64. New dependency: `golang.org/x/crypto v0.58.0` for bcrypt; the existing registry retains its AMQP dependency. No deployed cloud was targeted or restarted.

| Check | Result |
| --- | --- |
| Build all five core executables (`make build`) | PASS |
| Root and nested ServiceRegistry static checks (`make vet`) | PASS |
| Root tests with race detector (`go test -race ./...`) | PASS |
| Existing ServiceRegistry module plus new contract test (`go test -race ./...` in ServiceRegistry) | PASS |
| Separate uncached root core test/coverage run | PASS; 58.1% statement coverage of `internal/core` |
| Controller-source HTTP inventory | 61/61 Go routes present; no unresolved route expressions |
| Temporary native ServiceRegistry process with new core implementations | PASS; real discovery, authorization, exclusivity and service registration validation |

The new core package contains 26 top-level tests, plus table-driven cases. The tests cover session rotation/logout/change/expiration, token/certificate mismatch, missing certificates, identity batch rollback, redaction, privilege checks, state rollback/reopen/locking/concurrency, token references, RSA JWT signature verification and claims, provider-bound encrypted-key storage/tamper rejection, metadata comparisons, simple-store selection, input/pagination/callback validation, authority-certificate substitution rejection, isolated real-mTLS login/authorization/orchestration, concurrent single-use token verification, HTTPS push delivery and policy precedence.

The native-process test starts only the newly built Go registry on a random localhost port with isolated generated PKI and temporary state. The other new core services run as HTTPS servers in the test process. It registers a provider offer, exercises discovery and authorization, acquires provider-consented exclusivity, and validates all four new systems' advertised service interfaces through the real registry. Registry discovery remains restricted with explicit direct access for the test orchestrator; the test does not globally disable discovery protections.

The tests are not an independent exhaustive protocol certification. Most integration peers are Go implementations from this bundle, and some tests use a narrowly scoped registry fixture. No complete Java-versus-Go golden suite, MQTT broker suite, federation suite, penetration test, dependency-advisory scan or production load test was performed. Coverage is not 100%; startup CLI branches, several management/filter/error combinations, cleaner behavior and optional integrations need further work.

`contracts.json` is reproducible source traceability, not semantic parity evidence. Its hashes refer to the local controller files, not an asserted pristine upstream release tag. Source and build verification do not imply that the three deployed clouds have changed implementation language or that prior security findings have been fixed.

## Reproduce

```sh
make build vet test
make contracts
go test -race -coverprofile=coverage.out ./internal/core -count=1
```

The process-level registry test requires `bin/serviceregistry` and skips if that binary is absent. `make test` builds it first. Running only root `go test ./...` omits the nested registry tests. Preserve test output and repeat the checks after any source/configuration change; this report applies to this delivered source revision only.
