# Java source traceability

Reference root: sibling `ah5-core-java-spring/`, parent POM version 5.2.2, five modules. Shared contract root: sibling `ah5-common-java-spring/`. The generator records SHA-256 hashes of HTTP API files in `contracts.json`; regenerate against the intended checkout, including local security changes, before comparing another release.

| Go area | Java reference |
| --- | --- |
| `ServiceRegistry/` | `serviceregistry/` and its discovery/management/interface services; pre-existing Go module |
| `internal/core/authentication.go` | `authentication/.../service/{IdentityService,ManagementService}.java`, password authentication method, identity/session entities |
| `internal/core/authorization.go` | `consumer-authorization/.../service/Authorization{Service,ManagementService}.java`, `engine/AuthorizationPolicyEngine.java`, relevant-policy selection in `AuthorizationPolicyDbService.java` |
| `internal/core/tokens.go` | `engine/{TokenEngine,TokenGenerator}.java`, `service/utils/{SecretCryptographer,InstanceIdUtils}.java`, token/key DTO records |
| `internal/core/orchestration*.go` | both orchestration HTTP APIs; simple `utils/ServiceOrchestration.java`, dynamic `utils/LocalServiceOrchestration.java`, management/store/lock/history services and DTO converters |
| `internal/core/push.go` | both orchestration subscription/push management services; native worker deliberately differs from Java queue/Quartz implementation |
| `internal/core/metadata.go` | shared `MetadataRequirementsMatcher`, metadata tokenizer/key evaluator/MetaOps; Go RE2 differences documented |
| `internal/core/registration.go` | system-info service definitions, HTTP interface operations, shared service-operation constants |
| `internal/core/{http,config,state}.go` | native runtime; not a port of the entire common Spring/JPA/MQTT framework |

Java core module HTTP route counts: Authentication 13; ConsumerAuthorization 21; Dynamic orchestration 13; Simple orchestration 14 (61 total). Additional native echo endpoints do not imply Java exposes identical monitor resources in every module. The existing registry is built and tested separately rather than being counted in the new-module route total.

The original Java implementation credits AITIA and Arrowhead Consortia and uses EPL-2.0. Its license and notice accompany this source. See compatibility and verification documents for the boundary between derived behavior and unported behavior.
