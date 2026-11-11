# Standalone Go system folders

| System | Group | Folder | Entry point |
|---|---|---|---|
| Authentication | core | [ah5-core-go/authentication](ah5-core-go/authentication/README.md) | `./cmd/authentication` |
| ConsumerAuthorization | core | [ah5-core-go/consumer-authorization](ah5-core-go/consumer-authorization/README.md) | `./cmd/consumer-authorization` |
| DynamicServiceOrchestration | core | [ah5-core-go/serviceorchestration-dynamic](ah5-core-go/serviceorchestration-dynamic/README.md) | `./cmd/serviceorchestration-dynamic` |
| SimpleStoreServiceOrchestration | core | [ah5-core-go/serviceorchestration-simple](ah5-core-go/serviceorchestration-simple/README.md) | `./cmd/serviceorchestration-simple` |
| ServiceRegistry | core | [ah5-core-go/serviceregistry](ah5-core-go/serviceregistry/README.md) | `.` |
| Blacklist | support | [ah5-Blacklist-go](ah5-Blacklist-go/README.md) | `./cmd/blacklist` |
| Configuration | support | [ah5-Configuration-go](ah5-Configuration-go/README.md) | `./cmd/configuration` |
| DataManager | support | [ah5-DataManager-go](ah5-DataManager-go/README.md) | `./cmd/datamanager` |
| TimeManager | support | [ah5-TimeManager-go](ah5-TimeManager-go/README.md) | `./cmd/timemanager` |
| EventHandler | support | [ah5-EventHandler-go](ah5-EventHandler-go/README.md) | `./cmd/eventhandler` |
| DeviceQoSEvaluator | support | [ah5-DeviceQoSEvaluator-go](ah5-DeviceQoSEvaluator-go/README.md) | `./cmd/deviceqosevaluator` |
| AIGym | support | [ah5-AIGym-go](ah5-AIGym-go/README.md) | `./cmd/aigym` |
| PlantDescriptionEngine | support | [ah5-PlantDescriptionEngine-go](ah5-PlantDescriptionEngine-go/README.md) | `./cmd/plantdescriptionengine` |
| Choreographer | support | [ah5-Choreographer-go](ah5-Choreographer-go/README.md) | `./cmd/choreographer` |
| CertificateAuthority | support | [ah5-CertificateAuthority-go](ah5-CertificateAuthority-go/README.md) | `./cmd/certificateauthority` |
| SysMonitor | support | [ah5-SysMonitor-go](ah5-SysMonitor-go/README.md) | `./cmd/sysmonitor` |
| Onboarding | support | [ah5-Onboarding-go](ah5-Onboarding-go/README.md) | `./cmd/onboarding` |
| TestTranslation | test | [ah5-TestTranslation-go](ah5-TestTranslation-go/README.md) | `./cmd/testtranslation` |
| TranslationManager | support | [ah5-TranslationManager-go](ah5-TranslationManager-go/README.md) | `./cmd/translationmanager` |
| Gatekeeper | support | [ah5-Gatekeeper-go](ah5-Gatekeeper-go/README.md) | `./cmd/gatekeeper` |
| GateTunnel | support | [ah5-GateTunnel-go](ah5-GateTunnel-go/README.md) | `./cmd/gatetunnel` |
| LocalCloudManager | support | [ah5-LocalCloudManager-go](ah5-LocalCloudManager-go/README.md) | `./cmd/localcloudmanager` |
| LocalCloudConfigurator | support | [ah5-LocalCloudConfigurator-go](ah5-LocalCloudConfigurator-go/README.md) | `./cmd/localcloudconfigurator` |

Every folder has its own build, tests, configuration and deployment files. Core grouping follows the Java distribution; support folders are independent peers. Each private runtime copy retains the original common helpers and tests.
