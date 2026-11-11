# Deploying LocalCloudConfigurator with ColonyOS

## Prerequisites

- Docker Desktop with Compose v2, Go 1.26 or newer, and `curl` and `jq` on the host (the cloud scripts use them).
- A running target cloud. The default is `../../Arrowhead/Arrowhead-test-cloud-go`; override it with `CLOUD_DIR=...`.
- The first `make up` pulls `colonyos/colonies:v1.9.10` and `timescale/timescaledb:2.30.2-pg17` from Docker Hub.

## 1. ColonyOS stack and API

```sh
make up
```

`make up` does the following:

1. `make keygen` writes fresh secrets to `deploy/colonyos/secrets/` (files with mode 0600, git-ignored): the Colonies server key and id, the colony key, the API and executor keys, the database password and the operator token. Existing secrets are kept; `-force` replaces them.
2. It builds the static image `eclipse-arrowhead/localcloudconfigurator-go:5.2.2` (scratch base, non-root, read-only root filesystem).
3. It starts TimescaleDB and the Colonies server. The server is published on `127.0.0.1:50080` only.
4. `make register` creates the colony `arrowhead` and registers and approves two executors: `lcc-api` (the API's identity, which submits workflows) and `gocloud-executor` (type `arrowhead-cloud-executor`).
5. It starts the API and UI on `127.0.0.1:8095`.

The stack network uses the explicit subnet `10.240.90.0/24`, because the Docker Desktop address pools on the test host are used up. Override it with `LCC_SUBNET`.

## 2. Cloud executor on the cloud host

```sh
make executor-start        # background; log in state/executor.log
make executor              # foreground alternative
```

The executor needs the host's `docker compose` and the cloud directory. That is why it runs as a host process and not as a container. It reads its key from `deploy/colonyos/secrets/lcc_executor_prvkey`. Stop it with `make executor-stop`.

## 3. Use

- UI: open http://127.0.0.1:8095 and enter the operator token from `deploy/colonyos/secrets/lcc_api_token`. The table shows each system's state:
  - `running`
  - `alternate` (a Rust or Java swap runs)
  - `partial`
  - `stopped`
- In the UI, tick systems under *Run* or *Remove*, preview the plan, and apply it. The workflow's steps update live.
- CLI:

```sh
./bin/LocalCloudConfigurator apply -systems timemanager,eventhandler -smoke
./bin/LocalCloudConfigurator apply -remove cloud-monitor
```

- The plan adds required systems automatically. Removing a system that a running system still requires is refused.

## 4. Smoke test

```sh
make smoke
```

The smoke test checks four things:

1. The API is healthy and requires the token.
2. A status request makes the round trip through the ColonyOS executor.
3. TestTranslation (`SMOKE_SYSTEM=...` picks another system) is stopped and then deployed again through ColonyOS workflows.
4. The cloud's own `smoke-test.sh` runs as the last workflow step.

It ends with `SMOKE PASSED`.

## Operations

- `make status` shows the stack containers. `make down` stops the executor and the stack; the volumes are kept.
- Failed steps appear as failed ColonyOS processes. Their masked error is shown in the UI and the CLI, and the rest of the workflow does not run.
- A new GoCloud swap (for example a new Rust implementation) belongs in the `alternates` of the system's catalog entry.
