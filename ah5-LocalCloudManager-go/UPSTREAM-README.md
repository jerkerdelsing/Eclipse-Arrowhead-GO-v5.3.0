# LocalCloudManager — Go, Arrowhead 5.2.2

Canonical source package relocated into `ah5-support-go/LocalCloudManager/` from the latest available local Go test-cloud source. The workspace and cloud copies of `localcloudmanager.go` matched SHA256 `9b0b0537c5aa03fcee3f5902f0a3612829c60fe59d3b44e17013d5118331a714` before relocation.

This is a **source/documentation relocation, not a deployment or Java-parity upgrade**. The existing `Arrowhead-test-cloud-go/native-go` copy remains a deployment compatibility snapshot so its Docker build context and other shared-runtime roles are not broken. No running cloud, Compose file, credentials, CA keys or stored cloud data is changed. New development should use this canonical package; do not edit both copies independently.

## Contents and build

- `cmd/localcloudmanager`: dedicated launcher; rejects selection of other runtime roles.
- `internal/cloud/localcloudmanager.go`: existing manager API, operator sessions, aggregation and Unix-socket Docker client.
- `internal/cloud/ui/`: copied dashboard HTML/CSS/JavaScript, now embedded in the executable. Explicit `LOCALCLOUDMANAGER_UI_ROOT` overrides remain supported. No dependency on the old checkout is needed for default UI assets.
- Other `internal/cloud` files and tests: the original shared Go runtime is retained because manager clients, registration, TLS, models and helpers depend on it. These are not additional implementations selected by this launcher. This avoids coupling the relocated manager to an external source directory.
- `docs/legacy`: unchanged historical Markdown/SysML snapshots, including their historical equivalence claims. They are provenance, not the current compatibility assessment.
- `../documentation/LocalCloudManager/v5.2.2/`: SysD, SysDD, three SDs, three IDDs and a combined Arrowhead-style LaTeX catalogue.
- `docs/LocalCloudManager.sysml`: revised implementation-variability model with the canonical Go source location and explicit qualification boundary.

Requires Go1.26 or newer. From this directory:

```
make build
make vet
make test
make docs
./bin/LocalCloudManager --help
```

From the repository root: `make localcloudmanager` builds `bin/LocalCloudManager`; the root build/test/vet targets explicitly include this nested Go module. The generic `cmd/support` launcher does not select this manager. Dependencies remain isolated in this module's own go.mod/go.sum.

## Configuration and endpoints

The default listener is `:8480` with mutual TLS. It serves the UI and API on the same listener. The historical cloud publishes API9480 and UI9490 through deployment-specific forwarding; those addresses are not created by this source relocation. Use `https://<provisioned-host>:8480/` for a standalone secure listener. Any reverse proxy must be provisioned with a legitimate client certificate for the upstream mTLS hop. Do not infer public HTTP access from example UI ports.

Required secure setup:

| Environment | Meaning |
|---|---|
| `ARROWHEAD_ROLE` | Omit or set `localcloudmanager`; other values rejected by dedicated launcher |
| `SYSTEM_NAME`, `LOCAL_CLOUD`, `ORGANIZATION` | Default LocalCloudManager, GoCloud, Company; server certificate CN must match `<System>.<Cloud>.<Organization>.arrowhead.eu`, profile sy |
| `SERVER_PORT`, `DOMAIN_NAME` | Listener port and advertised address; default8480/localcloudmanager |
| `TLS_SERVER_CERT`, `TLS_SERVER_KEY`, `TLS_CA_CERT` | Provisioned PEM service certificate/key/trust; never copy another cloud's CA private key |
| `TLS_CRL_FILE` | Optional current PEM CRL; checked on new TLS connections, not existing sessions |
| `AUTHENTICATION_URL`, `AUTHENTICATION_PASSWORD` | Explicit HTTPS Authentication origin and this manager's provisioned password; Authentication CN/profile pinned before credentials |
| `SERVICE_REGISTRY_URL` | Explicit HTTPS registry origin; no implicit cleartext in secure mode |
| `DATAMANAGER_URL`, `SIMPLE_ORCHESTRATION_URL`, `SYSMONITOR_URL`, `PLANT_DESCRIPTION_ENGINE_URL` | Configure HTTPS provider origins; inherited defaults for these are HTTP and fail in secure mode |
| `DATA_FILE` | Private independent runtime state file; do not reuse an active cloud's file |
| `CONSOLE_PASSWORD_HASH` | `scrypt:<base64 salt>:<base64 hash>`; N16384,r8,p1; salt>=16bytes, hash>=32bytes; missing/invalid hash disables console API with503 |
| `CONSOLE_ALLOWED_HOSTS` | Host-name allowlist; defaults127.0.0.1,localhost,[::1]; does not enforce same port |
| `CONSOLE_SESSION_SECONDS` | Session lifetime; default28800seconds |
| `DOCKER_SOCKET`, `COMPOSE_PROJECT_NAME` | Unix Docker socket and exact Compose project; lifecycle uses the source's static systemToCompose allowlist (MANAGED_SERVICES is not consumed); avoid raw socket exposure beyond isolated development |
| `SYSMONITOR_ENABLED`, `AMQP_HOST`, `AMQP_PORT` | Optional native AMQPS publisher; disabled by default; exchange arrowhead, SASL EXTERNAL, persistent confirmed messages |

Provider management policies must authorize LocalCloudManager. A successful `/health` or displayed `registered:true` is not proof of registration. Treat provider and Docker failures as real dependencies, not reasons to disable TLS. Do not use `ALLOW_INSECURE_DEVELOPMENT=true` beyond isolated tests.

## Services and contracts

`localCloudManagement`1.0.0 uses `/api` and an operator session. Login: `POST /api/session` with JSON `{"password":"..."}`; successful login204sets an HttpOnly SameSite=Strict cookie. Read session withGET; logoutDELETE. Mutations require `X-Arrowhead-Action: confirm`. The IDD lists every endpoint and DTO. The API is not an identity-token-only management endpoint: browsers use console cookies; the adapter uses its own Arrowhead identity for provider calls.

The source also registers historical `monitor`1.0.0 echo at `/localcloud/monitor/echo`. This is a legacy registration name retained by the relocation, not the canonical `sysMonitor` telemetry service. With `SYSMONITOR_ENABLED=true` in secure mode, `sysMonitor`1.0.0 is separately registered on `generic_amqps`, using `echo/power/status` observations under `<Cloud>.sysmonitor.LocalCloudManager.LocalCloudManager.<type>`.

See [COMPATIBILITY.md](COMPATIBILITY.md) for inherited gaps and security restrictions. In particular, subscription writes currently acknowledge without forwarding, intercloud is a placeholder, several status fields are synthetic, and the cookie/Origin policy does not isolate localhost ports. No complete Java equivalence or new security certification is claimed.
