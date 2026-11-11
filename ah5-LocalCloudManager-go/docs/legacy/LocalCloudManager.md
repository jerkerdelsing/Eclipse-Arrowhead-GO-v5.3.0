# LocalCloudManager 5.2.2

LocalCloudManager is the operator-facing management microsystem for an Arrowhead local cloud. The service contract is implementation-neutral. A deployment selects exactly one implementation: JavaScript/Node.js alongside the Java cloud, Go, or Rust.

## Service contract

The system registers `localCloudManagement` version `1.0.0` with base path `/api` and the `monitor` service. The three implementations expose the same browser dashboard and operations:

| Capability | HTTP operation |
| --- | --- |
| Health and registration | `GET /health` |
| Cloud overview and activity history | `GET /api/overview` |
| Device, system, service, and runtime grouping | `GET /api/service-registry-management` |
| DataManager historian content | `GET /api/datamanager?limit={1..1000}` |
| Read stored orchestration rules | `GET /api/orchestration/rules` |
| Create an orchestration rule | `POST /api/orchestration/rules` |
| Remove an orchestration rule | `DELETE /api/orchestration/rules/{id}` |
| Read allowlisted container logs | `GET /api/logs?service={name}&tail={1..500}` |
| Start, stop, or restart an allowlisted system | `POST /api/containers/{service}/{action}` |
| Legacy inventory compatibility | `GET /localcloud/management/{status,systems,services}` |
| Monitor echo | `GET /localcloud/monitor/echo` |

The interchangeable console also exposes `GET/POST/DELETE /api/session`, `GET /api/consumers`, `GET /api/intercloud`, `GET /api/sysmonitor`, SysMonitor subscription management below `/api/sysmonitor/subscriptions`, and Plant Description CRUD below `/api/plantdescriptions`. All three implementations use the same Java-console HTML, CSS, response shapes, confirmation header, operator session, and Host/Origin policy.

Mutating operations require `X-Arrowhead-Action: confirm`. Runtime targets are constrained to the deployment's explicit system allowlist. Database containers and arbitrary Docker resources are not manageable.

## Implementations

| Variant | Deployment | UI | Implementation notes |
| --- | --- | --- | --- |
| Java cloud | `Arrowhead-test-cloud` | `http://127.0.0.1:8080` | Node.js management adapter used with the Java 5.2.2 systems; Docker access is isolated behind the Java-cloud deployment boundary. |
| Go | `Arrowhead-test-cloud-go` | `http://127.0.0.1:9490` | Native Go HTTP adapter and Unix-socket Docker client; system API is also published on port `9480`. |
| Rust | `Arrowhead-test-cloud-rust` | `http://127.0.0.1:8590` | Native Axum/Tokio adapter and Unix-socket Docker client; system API is also published on port `8580`. |

All variants discover inventory from their own ServiceRegistry, query their own DataManager and Simple Store Service Orchestration, and restrict runtime inspection to containers carrying the deployment's Compose project label. The implementation language does not change the Arrowhead system name, service definitions, operation semantics, or dashboard information model.

## Deployment constraints

- Exactly one LocalCloudManager variant is selected in a local cloud.
- The selected manager registers as `LocalCloudManager` and publishes `localCloudManagement` and `monitor`.
- The manager must not act on a container outside its configured Compose project or management allowlist.
- The browser never submits arbitrary Docker paths or container identifiers.
- Go and Rust test-cloud containers mount the Docker socket only for the LocalCloudManager process and run that process as root because Docker Desktop exposes a root-owned socket. Production deployments should place the socket behind a least-privilege proxy, as in the hardened Java-cloud topology.

The corresponding SysML v2 variability model is in [`LocalCloudManager.sysml`](LocalCloudManager.sysml).
