# Eclipse-Arrowhead-go reorganization verification

Completed 2026-10-28. Destination: /Users/jerkerdelsing/Work/lule/EISLAB/Project/Eclipse/Eclipse-Arrowhead-go/.

## Result

The Java distribution layout is mirrored with five individually buildable core modules under ah5-core-go/ and seventeen top-level support/test folders. All 22 modules have independent Go source/dependency manifests, tests, launchers, configuration/deployment documentation, Dockerfiles, compose templates and Makefiles. Each has a freshly built native host executable under bin/<System>. Shared runtime source is snapshotted into each private module; no sibling source dependency or original checkout is required. Source HTTP handlers and compatibility behavior are retained.

TestTranslation is a test provider. LocalCloudManager is the supplied dedicated native-Go implementation with embedded UI, not the Java/Node console. No Go GraphDBManager was present in the supplied source set. The five core systems correspond to ServiceRegistry, Authentication, ConsumerAuthorization, dynamic orchestration and simple-store orchestration.

Original source files were copied with tracked SHA-256 hashes. Module/import namespaces were relocated, support launchers were fixed to one system, and standalone build/config/deployment files were added. Original source trees and live clouds were not changed. No repository was published or initialized.

## Build and test results

Host toolchain: go version go1.27.1 darwin/arm64. All build/test/vet commands used GOWORK=off and GOPROXY=off, using the existing third-party module cache. Dependency fetching on a fresh computer remains the standard go.mod/go.sum workflow.

| System | Group | Build | Passed test events | Vet |
|---|---|---|---:|---|
| Authentication | core | PASS | 57 | PASS |
| ConsumerAuthorization | core | PASS | 57 | PASS |
| DynamicServiceOrchestration | core | PASS | 57 | PASS |
| SimpleStoreServiceOrchestration | core | PASS | 57 | PASS |
| ServiceRegistry | core | PASS | 24 | PASS |
| Blacklist | support | PASS | 50 | PASS |
| Configuration | support | PASS | 50 | PASS |
| DataManager | support | PASS | 50 | PASS |
| TimeManager | support | PASS | 50 | PASS |
| EventHandler | support | PASS | 50 | PASS |
| DeviceQoSEvaluator | support | PASS | 50 | PASS |
| AIGym | support | PASS | 50 | PASS |
| PlantDescriptionEngine | support | PASS | 50 | PASS |
| Choreographer | support | PASS | 50 | PASS |
| CertificateAuthority | support | PASS | 50 | PASS |
| SysMonitor | support | PASS | 50 | PASS |
| Onboarding | support | PASS | 50 | PASS |
| TestTranslation | test | PASS | 50 | PASS |
| TranslationManager | support | PASS | 50 | PASS |
| Gatekeeper | support | PASS | 50 | PASS |
| GateTunnel | support | PASS | 50 | PASS |
| LocalCloudManager | support | PASS | 32 | PASS |

All 22 normal module suites passed with the race detector (1084 passed test events, zero failed). Shared runtime tests are retained in each independent package, so repeated test events are not 1084 distinct behaviors.

The optional native ServiceRegistry process integration test is skipped by the four normal core suites because its separate registry fixture binary is not part of those single-system folders. It was explicitly enabled and run separately; see the inherited issue below.

## Independence and packaging checks

- All 22 source layouts passed import checks; no sibling/external Arrowhead source imports remain.
- All 381 tracked original source/documentation files still match their original hashes after the operation.
- Authentication, Blacklist, ServiceRegistry and LocalCloudManager were copied to unrelated temporary directories and built there with workspace resolution and network module fetching disabled; each executable's help command passed.
- All 16 dedicated generic-runtime support/test launchers reject the old -system role-switching argument.
- All 22 finalized compose templates parsed successfully with placeholder validation values; no services were started by that check.
- Four representative Dockerfiles (one per runtime family) built from their own source directories. Images are tagged eclipse-arrowhead-go-reorg/<system>:20261028. Their help commands passed in read-only containers with no network access. The other eighteen source Dockerfiles use the same tested templates with their separately built entrypoints; they were not individually image-built.
- Historical prebuilt ServiceRegistry Dockerfile is archived under documentation/legacy because its old build paths are not the standalone packaging contract.
- Fresh source hashes and binary hashes are included. Bin executables are native host builds; deploy source-built Docker images for Linux.

## Inherited native-registry integration issue

The additional TestNativeServiceRegistryIntegration reaches real registry discovery and authorization checks but fails when the core fixture registers serviceOrchestration: `serviceorchestration-dynamic register serviceOrchestration: Upstream ServiceRegistry rejected request`. The same test was run in a temporary copy of unmodified original ah5-core-go source against the freshly built supplied ServiceRegistry; it failed at the same registration step. This is not caused by namespace/folder relocation. The supplied registry's reserved-owner validation and the core fixture's orchestration identity/registration contract require follow-up compatibility work. Existing example identities and handler behavior are retained rather than silently changed by this packaging task.

Logs: native-registry-integration.log, native-registry-baseline.log and native-registry-baseline.json. This distribution is independently buildable packaging, not a claim of complete cross-system conformance or a newly verified live-cloud deployment.

## Reproduction

Use make build, make test, make vet and make verify at the distribution root, or each folder's own Makefile. `make isolation` reruns external-directory builds and the additional native-registry probe (whose known failure is recorded separately and returns a nonzero status); `make images` reruns the four representative source-image checks. Optional tools use GO/DOCKER environment overrides. Full per-system logs and JSON results are in this directory.
