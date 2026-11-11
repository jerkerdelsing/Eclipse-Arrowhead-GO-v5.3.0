# Compatibility profile and remaining work

This document is deliberately separate from the route inventory. It records the actual implemented behavior and material gaps, rather than calling a set of HTTP handlers a complete Java replacement.

## Implemented

- Authentication: PASSWORD identities, bcrypt cost 10, batch management, credential changes, credential-authenticated logout, UUID sessions, one active session per identity, expiration checks, session query/closure and identity query filters. Credentials and session tokens are excluded from management responses. Credential changes and management updates invalidate sessions (a stricter security choice).
- ConsumerAuthorization: provider and MGMT policy levels, MGMT precedence, ALL/WHITELIST/BLACKLIST/SYS_METADATA policies, scoped/default fallback, all-scopes checks, grant/lookup/query/revoke/check operations. Missing policies deny access.
- Authorization tokens: usage/time-limited tokens; URL-base64 self-contained tokens with the Java pipe-separated field order; RS256/RS512 JWTs with `psn/csn/ccn/tat/tan/sco` claims; public-key export; management generation/query/revocation; provider-bound online verification with atomic usage decrement. Raw tokens are returned only at generation, not retained for later retrieval.
- Encryption-key registration: Java AES/ECB/PKCS5Padding and AES/CBC/PKCS5Padding wire encodings, provider-specific IVs for CBC, owner/management removal. Provider keys are authenticated-encrypted at rest with AES-GCM and provider identity as additional authenticated data. The server certificate's RSA key signs JWTs.
- Simple orchestration: consumer-specific store, unique priorities per consumer/service, priority modification, preferred providers, ONLY_PREFERRED, per-service MATCHMAKING, ignored-field/flag warnings, pull/history.
- Dynamic orchestration: service discovery through ServiceRegistry, mandatory authorization checks, preferred providers, interface operations, token acquisition, MATCHMAKING, provider-consented exclusivity capped by `allowExclusivity`, atomic lock conflict rechecks, lock management, pull/history.
- Both orchestrators: persisted subscriptions, owner checks, management subscription/query/unsubscribe/trigger operations, persisted jobs and HTTPS push callbacks. Callback TLS is pinned to the target system identity before sending results. Interrupted in-progress jobs become ERROR on restart instead of being redelivered automatically.
- General management: sanitized configuration map, bounded persisted audit log querying, authenticated echo. Source-generated service descriptions and opt-in periodic service registration.
- Shared runtime: mandatory local-cloud mTLS, identity-token certificate binding, fixed authority identity pinning before credentials, redirect rejection, coalesced login refresh, conditional token invalidation, body limits, server timeouts, atomic JSON snapshots and exclusive process ownership of a state file.
- ServiceRegistry: pre-existing Go implementation plus corrected `AuthorizationVerifyRequestDTO` fields/operation names and removal of an implicit Sysop-name privilege escalation in outsourced token verification. Its original configuration and publisher are preserved.

## Not implemented / not equivalent

1. **MQTT APIs (since 2026-10-24) differ from Java in three deliberate points**: the response topic must lie under
   `arrowhead/response/<requester>/`, requests with an invalid identity token are not answered (no 401 response), and
   identity login/logout/change stay HTTPS only. Request topics, envelopes, operation names and error payloads follow
   the Java MQTT API; see "Changes 2026-10-24 (MQTT)".
2. **Dynamic federation, translation and QoS integration are absent.** Requests that enable ALLOW_INTERCLOUD, ONLY_INTERCLOUD or ALLOW_TRANSLATION, or supply QoS requirements, fail explicitly with 501. They are not silently treated as successful local equivalents. Foreign-consumer management token generation also returns 501. This is unsuitable for a federated orchestration replacement until those paths are ported and tested.
3. **Blacklist support and authorization-driven management filters are not ported** to the four new systems. Management uses identity sysop privileges or an explicit whole-management whitelist. This is less granular than per-operation authorization; do not use the whitelist as a substitute for fine-grained policy enforcement.
4. **The new systems do not yet publish native sysMonitor/AMQP telemetry.** Their echo APIs and history/logs exist, but they will not satisfy a LocalCloudManager native-telemetry readiness requirement. The existing ServiceRegistry publisher remains available.
5. **No Java SQL database compatibility/import.** Each new system uses a private atomic JSON state file, not JPA/MySQL. Never mount a Java database volume as a Go state file. Java identity, authorization, key, store, lock, subscription and history data need a separately reviewed importer before migration.
6. **Configuration is JSON**, not Spring properties, environment override semantics, keystores or Java's full property catalog. `get-config` returns a sanitized native configuration subset in the Java `map` response wrapper. There is no cloud registration health/readiness gate; registration failures are retried and reported to the process log.
7. **Validation/normalization and query semantics are not exhaustively matched.** Supply canonical names and enum spelling. Field lengths, case normalization, HTTP error details/statuses, empty/null distinctions, ordering/default page sizes and warning text still need Java golden-contract tests. Pagination is bounded, but is not a full port of Java's per-entity paging service. JSON inputs use dynamic documents rather than generated, exhaustive DTO validation.
8. Metadata supports the documented comparisons and dotted/indexed paths, but REGEXP uses Go RE2, not Java Pattern; lookarounds/backreferences are not supported. Mixed-type numeric/collection edge cases need further Java fixture tests.
9. Dynamic candidate ranking is deterministic local/preferred ordering, not the complete Java matchmaking/QoS/fallback pipeline. Scopes are checked fail-closed; a denied requested operation can reject orchestration instead of yielding Java's precise partial-result behavior. Token acquisition is not rolled back if a later lock conflict aborts orchestration.
10. Push uses one worker and one delivery attempt, without Java's Quartz/thread-pool behavior, HTTP/plain MQTT callbacks, retries, or automatic event-driven re-orchestration. HTTPS result-delivery behavior is tested; duplicate delivery avoidance does not constitute exactly-once delivery. Notifications interrupted by a crash are reported as uncertain ERROR.
11. Logs are native bounded audit records (1,000 retained), not the full Java logging database or JVM-specific exceptions. Sessions/tokens/jobs/subscriptions/locks are validated for expiry at access but do not have complete Java cleaner/retention policies; state can grow over time. Expired entities may differ in query visibility.
12. No certificate revocation enforcement beyond Go's ordinary certificate-chain/time/hostname checks. No blacklist, rate limiter, distributed transactions, HA, distributed locks, SQL migration, or production security certification. Offline self-contained token revocation requires provider-side expiration/revocation handling; online revocation does not invalidate already-issued offline tokens.

## Release gate

Do not describe this profile as fully interchangeable with the Java cloud. Before replacement: implement the required missing capabilities, compare successful and failing requests against Java for every DTO/operation, verify all discovery/security policies, migrate data with rollback, verify monitoring/UI readiness and federation, and rerun the cloud security evaluation. None of those deployment changes is made by this source delivery.

## Changes 2026-10-17 (GoCloud deployment)

- Dynamic orchestration passes each requested operation as an authorization scope; a provider qualifies only if
  every requested operation is granted. Without operations the all-scopes check applies (as before). Test:
  `TestNativeServiceRegistryIntegration`.
- Deployed in Arrowhead-test-cloud-go (see its GO-NATIVE-FULL-2026-10-17.md) by operator decision, with the gaps
  listed above accepted; the release gate above is not thereby satisfied.

- Inter-cloud orchestration: ALLOW_INTERCLOUD (fallback when no local provider) and ONLY_INTERCLOUD through the local
  Gatekeeper (`gatekeeperURL`): globalServiceDiscovery query, interCloudNegotiation negotiate, GateTunnel interface
  result. ALLOW_TRANSLATION and QoS requirements still return 501.
- Native sysMonitor telemetry (`monitorEnabled`, `amqpURL`): sysMonitor offer on generic_amqps, echo/power/status.
- `managementPolicy: authorization`: ConsumerAuthorization decides management access per service and operation.
- Requested operations match string-set operations (MQTT/AMQP templates) as well as HTTP operation maps.
- Push subscriptions store `notifyRecipient`: a non-sysop management subscriber (orchestration by proxy) receives
  the result; own and sysop subscriptions deliver to the target.

## Changes 2026-10-24 (translation)

- ALLOW_TRANSLATION: an interface is translatable when it does not match the template or property requirements
  natively (as Java assortInterfacesAndMarkIfNonNative), so a bridge can also translate only the data model of the
  accepted template (generic_https senml -> generic_https simpleJson). Native candidates still win; the consumer's
  authorization for the provider is still checked before a bridge is built.

## Changes 2026-10-24 (MQTT)

- MQTT API of all five core systems (`internal/core/mqtt.go`, `ServiceRegistry/mqtt.go`), the Java `mqtt.api.enabled`
  counterpart: the Java request envelope (MqttRequestTemplate: traceId, authentication `IDENTITY-TOKEN//<token>`,
  responseTopic, qosRequirement, params, payload) on the Java base topics + operation
  (`arrowhead/serviceregistry/{device-discovery,system-discovery,service-discovery,management,general/management,
  monitor}/`, `arrowhead/authentication/identity/[management/]`, `arrowhead/consumer-authorization/authorization[-token]/
  [management/]`, `arrowhead/serviceorchestration/orchestration/[management/{push,history,lock,store,plant-rules}/]`,
  `general/management/`, `monitor/echo`); the response (MqttResponseTemplate: status, traceId, receiver, payload; errors
  as ErrorMessageDTO with exceptionType and origin = topic) goes to the request's response topic.
- The adapter verifies the identity token and runs the request in process through the HTTPS route, so the blacklist,
  management (whitelist/authorization) checks and handlers are the same as over HTTPS. Path parameters come from
  `params` (a single one also from a string payload, as Java), the other params become the query, a list payload of a
  removal operation is its list parameter (names, instanceIds, uuids, ids, tokenReferences, systemNames,
  serviceInstances, keys).
- Response binding (Go): the response topic must lie under `arrowhead/response/<system of the token>/`; with a broker
  ACL that lets each client read only its own prefix, a stolen token cannot be used to read answers.
- Configuration: `mqttURL` (ssl://host:port, client certificate = system certificate) and `mqttTopicPrefix` (a second
  orchestrator on the same broker needs another prefix); ServiceRegistry `mqtt.api.enabled`, `mqtt.broker.address`,
  `mqtt.broker.port`, `mqtt.topic.prefix` (requires TLS and the outsourced policy). With MQTT enabled every service is
  also registered with a `generic_mqtts` interface (baseTopic, operation list), as Java.
- ServiceRegistry: the Blacklist filter never checks Blacklist itself (Java BlacklistFilter); a Java Blacklist, which
  registers before it serves its check, was refused under `force.blacklist.filter`.
- `cmd/mqtt-call`: command-line client for one MQTT API request (tests).
