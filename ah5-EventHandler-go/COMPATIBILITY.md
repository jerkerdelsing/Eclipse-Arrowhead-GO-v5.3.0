# Compatibility and remaining implementation work

Target: the local Arrowhead 5.2.2 Java support sources, including their local extensions. Status: **development port; full user-requested parity remains incomplete**. This repository is useful executable implementation work, not a declaration that all Java features have been translated. Do not substitute it into the test clouds until the relevant release gates pass.

## Per-system boundary

| System | Implemented development behavior | Material remaining work |
|---|---|---|
| AIGym | Persistent samples, Java-style nearest-neighbour prediction, status | Complete observation-publishing behavior; local extension rather than upstream mandatory system |
| Blacklist | Create/query/revoke, active-time checks, lookup | Golden tests for normalization, historical reactivation and query-mode edge cases |
| CertificateAuthority | Role/profile-constrained CSR signing, chain checks, certificate revocation, signed CRL export and trusted keys | Java SQL import, automatic CRL-file publication, wider relying-party revocation enforcement, HSM/OCSP/HA |
| Choreographer | Plan DAG validation, executor registration, synchronous orchestration, persistent steps/callbacks/worklog | Async result callback (explicit 501), complete dependency negotiation, optimal executor selection, session notification, remote abort propagation, inter-cloud sessions |
| Configuration | Local configuration CRUD/base64/raw download and local proxy save/get | Java external-provider fallback and full DTO/error parity |
| DataManager | Local SenML historian with query windows, registered HTTPS provider proxy | Complete SenML normalization and signalCount semantics, provider configuration, MQTT ingestion |
| DeviceQoSEvaluator | Measurement reload, weighted time-window means, threshold filtering and ranking; missing data rejected | Full Java SNMP/OID discovery, augmentation, normalization and scaling algorithm |
| EventHandler | Subscription lifetime/metadata matching, publication authorization, pinned HTTPS callbacks via persisted bounded outbox | MQTT notification, complete executor/backoff settings; at-most-three callback attempts differs from a fully configurable delivery policy |
| Gatekeeper | Native Go legacy-mTLS cloud discovery/negotiation engine adapted to this runtime | AH-GT-1 encryption, complete current Java edge-case parity, real peer/broker/ACL qualification |
| GateTunnel | Legacy-mTLS relay forwarding, owner-constrained session control, expired-session rejection | AH-GT-1 data plane; control-session rows are not additional AMQP tunnels; listeners are volatile and renegotiated on restart |
| Onboarding | Fingerprint/system approval, on/de/sy certificate stages, registry/identity provisioning and offboarding | Complete renewal, crash recovery, withdrawal handling and prerequisite discovery; partial compensating saga, not a distributed transaction |
| PlantDescriptionEngine | Topology/include composition, named/metadata resolution, periodic alarms, DSO snapshot synchronization and monitor enrichment | Java state import, complete normalization/error parity and production qualification |
| SysMonitor | Authorized AMQPS intake, strict observation validation, atomic dedup/history/outbox, subscriptions, history, MQTT QoS1 forwarding | Java MQTTv5 (Go uses 3.1.1), complete live-broker/UI parity, Java history import, broad schema golden tests |
| TimeManager | Exact primary response field names, time-zone/DST fields, optional single SNTP check | Full Java time-source cache, selection and trust policy |
| TranslationManager | Port of the Java TranslatorBridgeEngine (2026-10-24): registry discovery of interface translators (interfaceBridgeManagement), data model translators (dataModelTranslation) and factories (dataModelTranslatorFactoryControl); check-targets / initialize-bridge / abort-bridge; Java bridge statuses, transitions, reports, query and 8-hour cleanup; consumer and management APIs | Translators with TOKEN_AUTH interfaceBridgeManagement policies are not selected; custom translator configuration (TODO in Java) not sent; first-match matchmaking |
| TestTranslation | Test system (2026-10-24): generic_https interface translator with forwarding bridges (TRANSLATION_BRIDGE_TOKEN_AUTH), simpleJson <-> senml data model translator, usage reports | Test system only: one bridge kind, two data models, CERT_AUTH/NONE targets |

## Cross-cutting boundaries

- JSON snapshots replace SQL/JPA. There is no automatic data migration, multi-process shared state, multi-instance coordination, database transaction import, or encryption at rest.
- HTTP method/path coverage is necessary but insufficient. Exhaustive DTO validation, normalization, pagination order, error bodies/codes, authorization policy semantics, service versions and failure/retry behavior need Java-versus-Go contract evidence. Generated SDs describe the delivered profile, including explicit Go extensions.
- Business HTTPS authorization normally uses ConsumerAuthorization; management uses verified sysop/whitelist, with additional ownership checks where implemented. CA/enrollment/federation use additional role/profile/owner rules. This is not proof of equivalence to every Java security policy. `identity-only` deliberately bypasses business authorization and must not be mistaken for a secure replacement profile.
- Upstream TLS peers are pinned by CN/profile as well as normal trust/SAN verification. Broker trust/ACLs and bootstrap trust are separately provisioned. CRL enforcement is optional and leaf-focused; it does not establish chain-wide or ecosystem-wide revocation enforcement.
- Telemetry/outbox processing is at-least-once. An outbox is not an exactly-once distributed transaction. External side effects can require operator reconciliation after timeouts or crashes.
- No Java/Python implementation is executed by the Go processes. Native dependencies are the Go MQTT/AMQP clients and their transitive Go modules. The imported federation engine is native Go, with legacy-mTLS limitations retained.
- No LocalCloudManager UI, cloud deployment, live federation, state import or rollback trial is included. The requested destination is a source/documentation repository, not authorization to replace running clouds.

## Release gates

Before claiming interchangeability or replacing a Java service:

1. Close every material behavior gap for that system and add regression cases, including failures and unauthorized callers.
2. Replay DTO/status/error and registration fixtures against both the exact hashed Java reference and Go implementation; compare behavior rather than just URLs.
3. Exercise real Authentication, ConsumerAuthorization, ServiceRegistry, brokers, executor/translator/device integrations and inter-cloud peers with least-privilege identities, certificate rotation/revocation and broker ACL tests.
4. Demonstrate state import, restart recovery, duplicate delivery, partial-failure reconciliation, backup/restore and a working rollback to Java.
5. Complete vulnerability/advisory review for the actual deployment toolchain and modules. Race tests and static checks do not establish absence of vulnerabilities.
6. Test LocalCloudManager discovery, readiness, management and UI behavior against the candidate systems before deployment approval.

## Changes 2026-10-17 (GoCloud deployment)

- `upstreamSystems`: pinned system identity per logical upstream (ServiceOrchestration → DynamicServiceOrchestration).
- CertificateAuthority `crlExportFile`: atomic PEM CRL at start-up, daily and after each revocation.
- Onboarding `clientCA`: manufacturer CAs trusted for client certificates only (never for upstream servers); no
  registry pre-creation of the system (it registers itself); device and identity update on re-onboarding;
  enrollments list `systems`; off-boarding clears them.
- DataManager: GateTunnel may PUT historian data for the remote consumer of a negotiated session
  (`X-Arrowhead-Remote-Consumer`), as the Java DataManager does.
- Deployed in Arrowhead-test-cloud-go (GO-NATIVE-FULL-2026-10-17.md) by operator decision; the release gates above
  are not thereby satisfied.

- SysMonitor: batched AMQP intake (one commit per batch), `ViewTables` reads, `maxObservationsPerSystem` (default 2000).
- AIGym: orchestrated sysMonitorData MQTT subscription, latest 200 observations at /aigym/observations, Java status.
- Gatekeeper/GateTunnel: `GET /<system>/mgmt/status` (relay link and session status, mTLS management).
- `managementPolicy: authorization` (per-operation management by ConsumerAuthorization).
- PlantDescriptionEngine: orchestration-rule synchronization with SimpleStore and Java alarm causes
  (`alarmIgnoredSystems`).
- Choreographer: orchestration by proxy for the executor via push subscription and /orchestration-result callback,
  allowInterCloud sessions, abort propagation, HTTPS owner notifications.
- DeviceQoSEvaluator: device discovery and RTT/augmented measurement (`qosMeasurement`).
- Still not ported: MQTT interfaces.

## Changes 2026-10-24 (translation)

- TranslationManager rewritten as a port of the Java engine and drivers (see the table); `translation_test.go` runs
  TranslationManager, TestTranslation and DataManager end to end over mutual TLS (discovery, negotiation, bridge
  call with senml -> simpleJson, USED report, abort) and the factory fallback.
- TestTranslation added (documentation/TestTranslation: SysD, SysDD, two SDs, HTTPS IDD).
- DataManager registers the data models of dataHistorian (`dataModels`: get-data output senml, put-data input senml).
- Onboarding: peers issued by a `clientCA` (device manufacturers) are not checked against the cloud CA's CRL (J4
  refused every bootstrap certificate with "No CRL matches peer issuer"); Onboarding controls them by fingerprint and
  enrollment state. Cloud-issued peers stay CRL-checked (fail closed).
- `Remote.localClient`/`callLocal`: calls to local-cloud systems known only by interface (bridge targets, data model
  translators), verified by cloud CA, `sy` profile, cloud name and host name.

## Changes 2026-10-24 (MQTT bridges)

- TestTranslation translates between HTTPS and MQTT (with `mqttURL`): interfaceBridgeManagement 1.0.0 accepts
  generic_https and generic_mqtts consumers for generic_https targets; a second instance (1.1.0, as `interfaceBridge.to`
  is a single template) bridges generic_https consumers to generic_mqtts targets on its broker. MQTT bridges use the
  Java MQTT envelope; the MQTT consumer authenticates with `TRANSLATION-BRIDGE-TOKEN//<bridgeId>` and gets the answer on
  its response topic (under `arrowhead/response/`); towards MQTT targets TestTranslation uses its identity token and
  `arrowhead/response/TestTranslation/<traceId>`. Data model translation applies on both kinds.
- TranslationManager: discovery candidates carry the target interface template (Java DTOConverter
  `getToInterfaceTemplate`), not the consumer's; the orchestrator matched the bridge to the target by it, so
  generic_mqtts consumers of HTTPS providers got no result.
