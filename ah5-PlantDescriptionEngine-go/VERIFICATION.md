# Verification record — 2026-10-16

## Result and scope

**Development delivery; full Java equivalence remains incomplete.** Fifteen native Go support-system profiles build. The isolated tests pass, but do not qualify the implementations as interchangeable Java replacements. Material gaps are enumerated in `COMPATIBILITY.md` and every system's LaTeX documentation. No existing cloud/container, identity store, CA, broker or federation configuration was modified.

Reference roots:

- `OLD/Arrowhead/ah5-support-java-spring/`
- `OLD/Arrowhead/ah5-common-java-spring/`

The exact local source hashes, including shared Java support runtime and 417 common Java files, are in `documentation/contracts.json`. This is a local-reference port, not verification of a pristine upstream release tag.

## Executed checks

| Check | Observed result |
|---|---|
| Host toolchain | Go 1.27.1, darwin/arm64 |
| `make build` | All 15 named executables built successfully |
| Delivered-copy check | Build, static checks, race tests and route audit repeated successfully in the requested `ah5-support-go` destination; all 15 binaries accepted their CLI options |
| `go vet ./...` | Passed |
| `go test -race -coverprofile=coverage.out ./...` | Passed: 24 core-runtime tests and 4 federation-engine tests |
| Statement coverage | core 44.1%; relay 13.0%; command packages 0.0%; total 35.0% |
| Linux cross-compilation | Unified native executable compiled for linux/amd64 and linux/arm64 with CGO disabled; binaries not executed on Linux |
| Spring route extraction | 107 extracted reference method/path mappings present; zero missing/unresolved mappings |
| Go interface inventory | 168 routes and 65 produced HTTPS service groups across 15 profiles; includes common-management routes and Go extensions |
| LaTeX | 111 SysD/SysDD/SD/IDD/catalogue sources compiled; combined catalogue compiled twice with local TeX Live 2023 |
| PDF QA | Catalogue pages rendered with Poppler and visually checked using the PDF skill workflow; pagination repaired to keep each system's interface table together; no overfull-box errors in the compilation checks |

Coverage is deliberately stated rather than inferred from test counts. Much of the complex integration and failure behavior is not covered. Command-package coverage is zero because the tests exercise the runtime packages, not instrumented CLI processes; the build and documentation-generator executions are separate checks.

The initial fixture run failed because test certificates were incorrectly signed with a leaf key. The fixtures were corrected to use their isolated issuer key; subsequent race-checked runs passed. No live cloud certificates or private keys are used in the suite.

## Behaviors exercised

- All fifteen profiles construct distinct routes with explicit access categories; registration paths resolve to implemented routes.
- Blacklist lifecycle, configuration binary round-trip and cross-identity isolation, historian ownership, nearest-neighbour prediction, and exact primary TimeManager response fields.
- Plant graph validation/activation and transactional rejection of invalid topology; choreography cycle rejection and error state when an executor is missing.
- Missing QoS measurements fail closed; missing translation adapters return unavailable instead of fabricated success.
- Monitoring subscription revision conflicts, unauthorized providers, schema/value/time/identity validation, deterministic duplicate suppression, and atomic history/outbox enqueue.
- CA role/profile restrictions, CSR signature and CA-extension stripping, actual issuer signatures, revocation and signed CRL output. CRL verification rejects revoked, stale and wrong-issuer lists.
- Enrollment rejects reserved names and duplicated fingerprints; bootstrap approval is based on certificate fingerprint, not a manufacturer-supplied CN.
- Verified identity tokens must match certificates; management access is restricted. A missing ConsumerAuthorization authority cannot yield a successful authorized TimeManager call.
- A real local HTTPS listener uses loaded certificate files and rejects missing/untrusted client certificates. Valid mutual TLS succeeds. World-readable TLS private keys are rejected.
- Upstream authority CN/profile pinning precedes credential delivery; strict configuration rejects unknown fields and trailing JSON documents.
- State locking, rollback on validation/persistence failure and concurrent updates; durable event outbox delivers through a pinned subscriber identity.
- Federation reply correlation/expected peer/inbox, consumer ownership, expired-session handling, operation-restricted provider forwarding, and refusal to start an insecure federation.

Most business-function tests explicitly select the development `identity-only` policy to isolate the business logic. The default fail-closed policy, certificate/token binding, authority pinning, management guards and selected federation restrictions have separate tests; that separation is not an end-to-end policy-equivalence proof.

## Evidence and reproduction

`output/verification/coverage.txt` contains the coverage profile; `binary-build-info.txt` records actual linked dependency versions from the built SysMonitor binary. Run `make build vet test` to reproduce local checks. Test listeners use temporary local ports and temporary PKI/state. The documentation generator's audit is reproducible with the two source roots above; it fails on unresolved or absent extracted Spring routes.

Four systems use the shared Java HTTP dispatcher rather than Spring controllers. Their source is hashed and manually reviewed; **they are not included in the automatic 107-route coverage claim**. URL extraction is not DTO/error/security/side-effect parity testing, even for the Spring systems.

## Not established by this delivery

- Full translation of every Java capability; the remaining implementation work in `COMPATIBILITY.md` is real, not merely missing certification.
- Live real-core-system, AMQP/MQTT broker, translator, device measurement, executor or inter-cloud compatibility. No working federation was replaced or exercised against live neighbours.
- Java-versus-Go golden response/status/error fixtures, complete authorization/ACL parity, load/soak/fuzz tests, dependency outage and restart recovery qualification.
- Java database migration, preservation of existing identities/history/configuration, backup/restore, distributed side-effect reconciliation and rollback trials.
- An updated vulnerability/advisory scan. `govulncheck` was not available in the checked execution path; offline module enumeration also attempted to resolve uncached metadata. Successful builds/tests are not evidence that dependencies have no advisories. The actual linked modules are recorded for subsequent scanning.
- LocalCloudManager UI equivalence, cloud readiness, deployment or production approval.

These are release gates, not claims of success. Keep the existing clouds unchanged until the relevant gaps are implemented and qualified.
