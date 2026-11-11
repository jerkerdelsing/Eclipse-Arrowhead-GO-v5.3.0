# LocalCloudConfigurator

LocalCloudConfigurator fills an Arrowhead 5.2.2 local cloud with the support systems and application systems an operator picks. The operator picks the systems in a web UI or through the API. The configurator turns the selection into an ordered deployment plan and submits that plan to [ColonyOS](https://colonyos.io) as a workflow. A ColonyOS executor on the cloud host carries out each step.

The first target is the GoCloud (`Arrowhead-test-cloud-go`). The executor runs the cloud's own scripts, so the configurator follows the same steps as the cloud's Makefile.

## Parts

| Part | Where | Role |
|---|---|---|
| Catalog | `catalogs/gocloud.json` | The cloud's selectable systems, their Compose services, alternates (Rust/Java swaps), dependencies, identity provisioning and policy scripts |
| Planner | `internal/planner` | Turns a selection into steps (`provision` → `up` → `policy`, then `stop`, then `smoke`) in dependency order |
| API + UI | `localcloudconfigurator serve` (container in the ColonyOS stack) | `GET /api/catalog`, `GET /api/status`, `POST /api/plan`, `POST /api/deployments`, `GET /api/deployments/{id}`; UI at `/` |
| Cloud executor | `localcloudconfigurator executor` (on the cloud host) | ColonyOS executor of type `arrowhead-cloud-executor`; serves `lcc.status` and `lcc.step` |
| ColonyOS stack | `deploy/colonyos/compose.yaml` | TimescaleDB, Colonies server v1.9.10, the API |

```
operator ──UI/API──▶ LocalCloudConfigurator ──workflow──▶ Colonies server ◀──assign── cloud executor ──▶ docker compose / scripts/ of the cloud
```

## Rules the executor enforces

- The executor checks every step against its own catalog. It does not trust the arguments of a process.
  - Only catalogued Compose services can be started or stopped. Core systems are never touched.
  - Only catalogued scripts in the cloud's `scripts/` directory can run.
- Services start with `docker compose up -d --wait --no-deps <service>`. Dependencies are explicit plan steps. Compose therefore never starts a Go service while its Rust or Java alternate runs (see the GoCloud swap targets).
- When an alternate runs, the system counts as present. The configurator neither starts nor stops it; the cloud's `swap-*`/`restore-*` targets manage it.
- Step output goes to the ColonyOS process logs with credential-like values masked. Secrets are never printed.
- No secret rotation and no PKI changes. Identities are provisioned through the cloud's `provision-*-identity.sh` scripts, which log in as Sysop with `sysop.crt`.

LocalCloudConfigurator is an operations tool. It is not an Arrowhead system: it does not register in the ServiceRegistry and has no Arrowhead identity. The new-system checklist (AMQP ACL, sysMonitor policy, Orchestration grants) therefore does not apply.

## Build and test

```sh
make build test vet
```

Deploying and the smoke test are described in [DEPLOYMENT.md](DEPLOYMENT.md).

## Adding a cloud or a system

Add a system as an entry in the catalog: `id`, `kind` (`infrastructure`/`support`/`application`), `services`, and optionally `alternates`, `requires`, `provision` and `policies`. To support another cloud, write a catalog with its own `composeProject` and `executorType`. Then run one executor per cloud host with `-catalog` and `-cloud-dir`.

## Listening port

`serve` listens on **127.0.0.1:8095** by default. Override with `-listen host:port`, `SERVER_PORT=N` or `-server.port N`; the port overrides keep the `-listen` host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
