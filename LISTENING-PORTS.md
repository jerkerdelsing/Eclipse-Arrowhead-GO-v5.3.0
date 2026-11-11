# Listening ports

Every Arrowhead core and support system follows two endpoint principles:

1. **Configured listening port**: the port where the microsystem accepts connections can be set in its
   configuration file, by environment variable and by command-line flag.
2. **Predefined default**: each system has a built-in default port, so a first deployment works without extra
   configuration.

The setting has the same name in all three primary implementations (Spring Boot names): `server.port`,
`SERVER_PORT`, `--server.port`. Highest precedence first:

| Source | Java (Spring Boot) | Go | Rust |
|---|---|---|---|
| command line | `--server.port=N` | `-server.port N` / `--server.port=N` | `--server.port N` / `--server.port=N` |
| environment | `SERVER_PORT=N` | `SERVER_PORT=N` | `SERVER_PORT=N` |
| configuration file | `server.port` in `config/application.properties` | `"listen": "host:port"` in `config.json` (ServiceRegistry: `server.port`) | `"listen": "host:port"` in the JSON configuration |
| built-in default | `server.port` in the packaged `application.properties` | `127.0.0.1:<default>` | `127.0.0.1:<default>` |

The command-line and environment overrides replace only the port and keep the configured host. Overrides must be
1..65535. `advertisePort`, the port published to the ServiceRegistry, is a separate setting, because it may differ
from the listening port (for example a Docker host port).

## Default ports

The Java packaged defaults are the reference Arrowhead 5 defaults. "Go shipped config" is the explicit
`listen` in the Go folders' `config.json`; since 2026-11-09 it equals the Go built-in default.

| System | Group | Java default | Go default | Go shipped config | Rust default |
|---|---|---|---|---|---|
| DynamicServiceOrchestration | core | 8441 | 8441 | 8441 | 8441 |
| SimpleStoreServiceOrchestration | core | 8442 | 8442 | 8442 | 8442 |
| ServiceRegistry | core | 8443 | 8443 | 8443 | 8443 |
| Authentication | core | 8444 | 8444 | 8444 | 8444 |
| ConsumerAuthorization | core | 8445 | 8445 | 8445 | 8445 |
| PlantDescriptionEngine | support | 8432 | 8432 | 8432 | 8432 |
| Onboarding | support | 8435 | 8435 | 8435 | 8435 |
| CertificateAuthority | support | 8448 | 8448 | 8448 | 8448 |
| Gatekeeper | support | 8449 | 8449 | 8449 | 8449 |
| GateTunnel | support | 8453 | 8453 | 8453 | 8453 |
| EventHandler | support | 8455 | 8455 | 8455 | 8455 |
| Choreographer | support | 8457 | 8457 | 8457 | 8457 |
| Configuration | support | 8459 | 8459 | 8459 | 8459 |
| DataManager | support | 8461 | 8461 | 8461 | 8461 |
| TimeManager | support | 8463 | 8463 | 8463 | 8463 |
| Blacklist | support | 8464 | 8464 | 8464 | 8464 |
| TranslationManager | support | 8465 | 8465 | 8465 | 8465 |
| GraphDBManager | support | 8467 | — | — | — |
| DeviceQoSEvaluator | support | 8472 | 8472 | 8472 | 8472 |
| SysMonitor | support | 8475 | 8475 | 8475 | 8475 |
| AIGym | support | 8478 | 8478 | 8478 | 8478 |
| TestTranslation | test | — | 8552 | 8552 | — |
| LocalCloudManager | support | 8491 | 8480 | 8480 | 8480 |
| LocalCloudConfigurator | support | 8492 | 8095 | 8095 | — |
| SoSConfigurator | support | 8494 | — | — | — |

LocalCloudManager and LocalCloudConfigurator keep their existing Go/Rust defaults (8480, 8095), which differ
from Java (8491, 8492); aligning them would change existing deployments and is left as a decision.

## Go specifics

- Support systems and the JSON-configured core systems (Authentication, ConsumerAuthorization, both orchestrators)
  share `internal/core/port.go` (`DefaultPorts`, `SERVER_PORT`, `-server.port`), with `port_test.go` checking the
  default, configured, environment and flag cases and that the address accepts connections.
- Before 2026-11-09, a configuration without `"listen"` fell back to `127.0.0.1:8443` for every system, which
  collided with ServiceRegistry. There was no environment or flag override.
- ServiceRegistry (`application.properties`) already used `server.port` (default 8443) and `SERVER_PORT`.
  `-server.port` and a 1..65535 check were added.
- LocalCloudManager is configured through the environment: `SERVER_PORT` (or `PORT`), default 8480.
  `--server.port N` was added. LocalCloudConfigurator `serve`: `-listen` (default `127.0.0.1:8095`),
  `SERVER_PORT` and `-server.port` were added.
- On 2026-11-09 the shipped `config.json` and `config/config.json` (`listen`, `advertisePort`), `compose.yaml`,
  Dockerfile `EXPOSE` and `systems.json` of the support systems moved from the earlier 8540–8555 layout to the
  Arrowhead defaults above (TestTranslation keeps 8552). Deployments built from older copies of these files
  still use the 854x/855x ports until they are rebuilt from this tree, and their peers' URLs need to change too.
