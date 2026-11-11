2026-10-23: PDE now synchronizes durable DSO plant-rule snapshots. [API, deployment and verification guide](documentation/PDE-DSO.md).

# Arrowhead support systems in Go — development profile

Native Go implementations based on the **local** `ah5-support-java-spring` reference, targeting its Arrowhead 5.2.2 interfaces. One independently running executable is built per system. There is no Java/Python subprocess, HTTP forwarding to a Java implementation, or Java runtime dependency.

**This is a development port, not a complete or certified interchangeable Java replacement.** Route presence is not behavioral equivalence. Review [COMPATIBILITY.md](COMPATIBILITY.md) and each system's delimitations before use. No running test cloud is modified by this repository or its build.

## Scope

| Executable | Reference folder | Principal implementation |
|---|---|---|
| AIGym | AI-gym | Persistent samples and k-nearest-neighbour prediction; local extension |
| Blacklist | Blacklist | Time-bounded exclusions, lookup and management |
| CertificateAuthority | CertificateAuthority / JavaSupportRuntime | Constrained CSR issuance, revocation, CRL export, trusted keys |
| Choreographer | Choreography | Plans, executors, persistent sessions, synchronous execution and callbacks |
| Configuration | Configuration | Configuration CRUD, base64/raw retrieval and local proxy storage |
| DataManager | DataManager | SenML historian and registered-provider HTTPS data proxy |
| DeviceQoSEvaluator | DeviceQoSEvaluator | Measurement-based provider filtering and ranking |
| EventHandler | EventHandler | Subscriptions, authorized event publication, durable HTTPS callback outbox |
| Gatekeeper | Gatekeeper / JavaSupportRuntime | Existing native Go legacy-mTLS federation engine with pinned authorities |
| GateTunnel | GateTunnel / JavaSupportRuntime | Legacy-mTLS relay and tunnel control |
| Onboarding | Onboarding | Fingerprint approval, certificate/device/system enrollment and offboarding |
| PlantDescriptionEngine | PlantDescriptionEngine | Topology CRUD, include validation, monitor views and alarm records |
| SysMonitor | SysMonitor / JavaSupportRuntime | Authorized AMQPS observation intake, history and MQTT/TLS outbox |
| TimeManager | TimeManager | UTC/time-zone response and optional SNTP offset/trust check |
| TranslationManager | TranslationManager | Java translator discovery and bridge lifecycle (interface translators, data model translators, factories) |
| TestTranslation | (test system) | generic_https interface translator and simpleJson/senml data model translator for TranslationManager tests |
| LocalCloudManager | LocalCloudManager (relocated native Go cloud bundle) | Operator console/API, shared runtime, embedded UI and optional telemetry; standalone nested Go module |

The original support port covers fifteen active logical systems. LocalCloudManager is now included as an additional independently buildable module at [LocalCloudManager/](LocalCloudManager/README.md), bringing the repository inventory to sixteen. It was relocated from the existing native Go test-cloud source, not reimplemented through the generic support launcher. Its source dependencies, copied UI assets, preserved legacy documentation and dedicated SysD/SysDD/SD/IDD set are included. The existing deployment copy is retained to preserve cloud build paths; no cloud is redeployed. `_superseeded` and generated outputs are excluded; JavaSupportRuntime is shared reference source, not an extra system.

Build only the relocated manager with `make localcloudmanager`; generate its Arrowhead documentation with `make localcloudmanager-docs`. Its nested module has separate dependencies and is explicitly included by the repository build/test/vet targets. The original fifteen-system catalogue remains separate from the manager's dedicated catalogue under `documentation/LocalCloudManager/v5.2.2/`. Read its README and compatibility notes before use: inherited console behavior is not claimed to be fully Java-equivalent or newly security-hardened.

## Build and test

Requires Go 1.26 or newer. From this directory:

```sh
make build
make vet
make test
```

Executables are `bin/Blacklist`, `bin/Configuration`, and so on. Alternatively:

```sh
go run ./cmd/support -system TimeManager -config config.json
```

Each process must have its **own** identity, listen port, password and durable state path. Shared source does not imply shared runtime state. JSON state is not compatible with the Java SQL databases; do not point at existing Java state or import it by renaming files. Back up and retain the old deployment during qualification.

## Configure and run

Copy [examples/config.json](examples/config.json), replace the sample cloud, paths and authority endpoints, and keep registration off during initial checks. Paths are relative to the working directory unless absolute. The executable supplies its default system name; set `name` only for a deliberately provisioned alternate identity. Set distinct ports when running more than one process.

```sh
./bin/TimeManager -config config.json
```

Required provisioning:

1. Provision a system-profile (`sy`) certificate with CN `<System>.<Cloud>.<Organization>.arrowhead.eu`, matching private key, trusted CA bundle and correct DNS/IP SANs. Private keys and password files must be owner-only. Do not copy another cloud's CA signing key.
2. Provision the system identity/password in Authentication. Configure explicit HTTPS origins for Authentication, ServiceRegistry and ConsumerAuthorization. These peers must present their own system CN and `sy` profile; same-CA certificates with a different CN are rejected before credentials are sent.
3. Grant required business-service permissions in ConsumerAuthorization. `authorizationPolicy` defaults to `enforce`. `identity-only` is an explicit development relaxation, not production parity. Management requires a verified sysop or an explicit `managementWhitelist`; that whitelist grants broad management access.
4. Give the process a private state directory. JSON snapshots use owner-only permissions, process locking, clone/validate/persist/publish transactions, file synchronization and atomic rename. State, CA records, outboxes and tokens require separate backup/access policies. There is no encryption at rest or distributed transaction.
5. If configured, `crlFile` is a PEM CRL bundle reloaded for new TLS connections. Missing, stale, wrong-issuer and revoking CRLs fail closed. If omitted, chain/time verification alone does **not** check revocation. Rotate/reload certificate material by restarting the process. A new CRL does not terminate existing connections.
6. Enable `register` only after authority connectivity and permissions work; supply `advertiseAddress` and `advertisePort`. Registration retries in the background; an echo response does not establish successful registration or dependency readiness.

Standard business requests use mutual TLS and `Authorization: Bearer IDENTITY-TOKEN//<token>`; the verified token name must equal the certificate identity. Echo endpoints require a valid local certificate but not a token. Approved onboarding bootstrap/device endpoints deliberately use certificate fingerprint/profile/serial checks instead. The generated IDDs list these distinctions.

### Additional integrations

- **CA:** set `caCertificate` and `caSigningKey` to a separately authorized matching issuer certificate and owner-only PEM signing key. CA material is never generated or copied automatically. CRL download is not automatic CRL publication/enforcement.
- **Onboarding:** configure `upstreams.CertificateAuthority`; approve the device bootstrap DER fingerprint and permitted system names through sysop management. Registry and Authentication prerequisites remain external. Preserve enrollment state; partial failures require reconciliation before retry.
- **Data proxy / events / choreography / PDE / QoS / translation:** configure relevant pinned `upstreams` origins (for example `ServiceOrchestration`, `SysMonitor`, `DeviceMeasurementAgent`, `InterfaceTranslator`). Discovered providers still require valid HTTPS identities and SANs. The translator must implement the adapter contract in the Go source; arbitrary Java translator agents are not drop-in adapters.
- **Telemetry:** set `monitorEnabled`, `amqpURL` (`amqps://`), and broker certificate/ACL provisioning. SysMonitor additionally needs `mqttURL` (`ssl://`) and `upstreams.ServiceOrchestration`; its subscription default is `none`. Enable specific authorized providers through its management API. MQTT is 3.1.1, not the Java MQTTv5 client. Persistent message delivery is at-least-once; consumers must deduplicate observation IDs.
- **Federation:** off by default. `federationEnabled` opts into the imported native Go **legacy-mTLS** relay engine. `FEDERATION_PROFILE=legacy-mtls`, neighbour/relay configuration, broker EXTERNAL credentials, trust/ACLs and explicitly pinned authority origins must be provisioned. See `internal/relay/federation.go` for the existing engine's environment contract. AH-GT-1 encrypted messages are not implemented. Live inter-cloud qualification has not been performed here; do not switch a working federation to this bundle without it.
- **Time:** `timeZone` defaults to `UTC`; optional `ntpServer` enables a bounded SNTP check. It never sets the host clock. A response without a verified source reports untrusted time.

## Documentation and traceability

`documentation/` contains Arrowhead-class LaTeX SysD, SysDD, SD and HTTPS IDD sources per system, the original class/logo assets, `contracts.json` and the combined `Go-Support-Systems.tex` catalogue. `contracts.json` records hashes of the actual local Java files used, extracted Spring routes, corresponding Go routes, service descriptors and system-specific limitations. It is a traceability aid, not proof of equivalence or an upstream release signature.

```sh
go run ./cmd/documentation -source ../ah5-support-java-spring -common ../ah5-common-java-spring
make docs
```

The generator fails on unresolved or missing extracted Spring routes. The four shared-runtime Java implementations require manual contract review; their routes are not counted as automatically audited Spring mappings. A template for compiling individual documents is given in [documentation/README.md](documentation/README.md).

See [VERIFICATION.md](VERIFICATION.md) for the measured checks and remaining release gates. EPL-2.0 licensing is in `LICENSE`; source/template attribution is in `NOTICE.md`.
