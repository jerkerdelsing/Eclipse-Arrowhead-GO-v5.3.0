# Go LocalCloudManager relocation verification — 2026-10-17

## Source and scope

Canonical destination: `ah5-support-go/LocalCloudManager`. Original local source: `Arrowhead-test-cloud-go/native-go`. The source manager matched the workspace copy before relocation (SHA2569b0b0537c5aa03fcee3f5902f0a3612829c60fe59d3b44e17013d5118331a714). The original deployment copy is retained unchanged because its package is shared by other roles and existing Docker build contexts. No running cloud, Compose configuration, credentials, CA key or state file is moved/restarted/deployed.

Packaged shared runtime and original tests are retained. Deliberate changes are the nested module path, dedicated role-constrained launcher, embedded UI fallback (three lines added to the existing asset loader), additional regression tests, and new documentation/provenance. Source hashes cover21original Go/module/UI files and25relocated files in docs/source-manifest.json. Hashes demonstrate provenance, not an upstream release signature or security assurance.

## Checks run

Environment: macOS ARM64, Go1.27.1; go.mod declares Go1.26. No Go1.26/Linux/Windows build or live deployment is claimed.

| Check | Result |
|---|---|
| Standalone `go build -trimpath` | Passed; native LocalCloudManager binary |
| `go vet ./...` in nested module | Passed |
| `go test -race ./...` in nested module | **32 tests passed**, no failures/race reports |
| Launcher `--help` | Passed without provisioned cloud resources |
| Role guard | Separate process rejects non-localcloudmanager role |
| UI relocation | HTML/JS/CSS load from embedded assets with working directory and external UI_ROOT unavailable |
| Console guards | Session/login/logout, missing password503, invalid Host/Origin403, lockout, mutation confirmation428 |
| Runtime control | Invalid action/unlisted target rejected; project filter verified using isolated mock Unix Docker socket |
| Telemetry | Descriptor/schema routing checks only; no real broker contacted |
| Arrowhead LaTeX | SysD, SysDD, three SDs, three IDDs, plus combined catalogue: all9sources compiled |
| Combined PDF |12pages, compiled three passes, all pages rendered/visually checked; no overfull boxes in latest logs |

Of32tests,21are inherited shared-runtime tests (TLS, authentication, core/federation/control behavior) and11are new relocation/manager/launcher checks. The mock-Docker test does not contact Docker Desktop. Fresh temporary test PKI is generated internally; no cloud CA private key is loaded. Direct handler tests do not by themselves verify network TLS; inherited TLS tests exercise that layer separately.

Root Makefile now explicitly includes this nested module in build/test/vet and provides localcloudmanager/localcloudmanager-docs targets. Existing parent README/Makefile/NOTICE are backed up before installation; unrelated support-system code and documentation remain unchanged. This record does not claim that the original fifteen-system root suite was rerun as part of relocation.

## Qualification boundary

No new Java parity, full endpoint differential suite, browser end-to-end deployment test, AMQP broker qualification, vulnerability scan or SysML parser validation is claimed. See COMPATIBILITY.md for13inherited limitations, including no-op subscription writes, placeholder intercloud/status views, registration metadata mismatch, incomplete origin-port isolation and Docker privilege exposure. Documentation describes actual behavior rather than repeating historical interchangeability claims.

The PDF skill guided compile/render inspection and fixes to long routing-key wrapping and an orphaned paragraph. Arrowhead's existing class/logo were reused.
