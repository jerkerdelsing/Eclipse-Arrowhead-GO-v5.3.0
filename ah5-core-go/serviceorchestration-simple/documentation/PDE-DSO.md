# PDE uses DynamicServiceOrchestration — 23 October 2026

The local Go and native Rust implementations now provide the same plant-rule snapshot contract as the local Java extension. Unmodified upstream DSO does not provide this API. SimpleStore remains independently available; PDE no longer writes its rows.

## API and state

| Operation | HTTP |
|---|---|
| query | POST `/serviceorchestration/mgmt/plant-rules/query` |
| replace | PUT `/serviceorchestration/mgmt/plant-rules/replace` |

Both return the complete snapshot. Query has no required body. Replace requires the full snapshot:

```json
{"rules":[{"consumer":"LineController","serviceDefinition":"temperature","providers":[{"serviceInstanceId":"Sensor|temperature|1.0.0","priority":0}]}]}
```

`rules: []` clears managed scopes; `providers: []` preserves a managed scope with no eligible provider. Priority is an integer in 0..2147483647; lower wins. Duplicate scopes/provider IDs, null arrays and invalid priorities are rejected before commit. Scopes and providers are normalized deterministically. One atomic `plantRules.active` record in DSO’s private JSON state survives restart; existing state files need no SQL migration. Java deployment uses a separate SQL migration.

PDE composes included descriptions, matches registered systems by name/metadata and resolves service instances. Named consumers stay managed even when unregistered. Missing or ambiguous producers retain empty scopes. Repeated providers use the minimum priority. PDE queries before replacing, compares the acknowledgment, and reports failure if the backend cannot be read or the acknowledgment differs. It never interprets a failed query as empty state. No active plant clears the snapshot. Registry query pages are bounded at 1000 entries; an incomplete response fails synchronization and retains the previous DSO snapshot rather than resolving ambiguous data from a truncated page. Registry changes reconcile within 30 seconds; plant changes normally reconcile within two seconds. `GET /plantdescriptionengine/mgmt/sync-status` reports the loop status under management access.

DSO restricts the candidate set to those engineered instance IDs, then retains its existing authorization, interfaces, exclusivity and other supported checks. The lowest-priority eligible provider wins matchmaking; without matchmaking the eligible list is sorted. A missing or denied primary can use a lower-priority engineered provider. An unrelated provider cannot be selected. Both ALLOW_INTERCLOUD and ONLY_INTERCLOUD are constrained for managed scopes. Existing unsupported translation/QoS features remain unsupported; this extension does not establish full Java parity.

## Security

Mutual TLS and certificate-bound identity tokens remain mandatory. PDE and Sysop may replace; PDE, LocalCloudManager and Sysop may query. The handler checks those identities separately from general management access. PDE’s exception applies only to this API, never other DSO administration. Native Rust also grants PDE only the two registry query operations it uses. ServiceRegistry reserves the new definition for DynamicServiceOrchestration. The PDE’s configured DSO origin is pinned to DSO’s certificate identity. The console remains read-only for snapshots and edits plants through PDE.

## Deployment and recovery

Go: run `Arrowhead-test-cloud-go/scripts/deploy-pde-dso.sh` against an initialized cloud. It builds native binaries, regenerates pinned runtime configuration, installs scoped discovery/management policies, and updates registry, DSO, PDE, SSO access configuration and the console. `make up` also installs the policy; `make up-plantdescriptionengine` uses the native deployment workflow.

Rust: run `Arrowhead-test-cloud-rust/candidate-native/deploy-pde-dso.sh`. It builds from workspace repositories, configures PDE’s pinned DSO origin and updates registry, DSO, PDE and LocalCloudManager only in `arrowhead-rust-candidate`. The older `arrowhead-v52-test-cloud-rust` stack has no PDE and is not changed. Shared runtime images do not require restarting every role. `make deploy-pde-dso` is available from the cloud directories.

Preserve previous images/executables, private state, configuration and policies before deployment. A rollback must coordinate PDE and its orchestration backend. Existing SimpleStore rows are retained; remove only confirmed PDE-owned rows after deciding they are no longer needed. No automatic Java/legacy-Rust state conversion or SSO-row import is performed. Existing orchestration caches can delay observation of changes.

## Verified in the running clouds

Both languages passed the temporary-fixture end-to-end checks for priority zero, deduplication/minimum priority, authorization fallback, missing primary, exclusion of an authorized unrelated provider, empty-scope restrictions, both inter-cloud flags, DSO restart persistence with PDE stopped, and deactivation. Fixtures were removed and both snapshots returned to empty. See `security-evaluation/pde-dso-go-rust-2026-10-23/` in the workspace for test evidence, private rollback snapshots and the deployment report. The tested state had no active operator plant; this is functional deployment verification, not production load qualification.

### Console access boundary

Go publishes backward-compatible `query`/`get` aliases for PDE reads and the Java-compatible management base path. The shared console can read the plant descriptions and DSO constraints. Automatic approval review rejected adding console plant-write grants during this deployment, so no new console create/replace/update/remove grants were applied. Existing Sysop APIs were used for functional tests; this deployment does not claim console plant-edit actions were verified. Native Rust exposes the DSO snapshot in its console consumers response.
