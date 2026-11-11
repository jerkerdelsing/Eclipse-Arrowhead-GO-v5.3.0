# LocalCloudManager — Go 5.2.2

Standalone support system, reorganized on 2026-10-28 following the Eclipse-Arrowhead-java distribution layout.

Build and operate from this folder; no original Arrowhead checkout or sibling source module is required.

```sh
make build
make test
make vet
make image
```

The executable is `bin/LocalCloudManager`. Entry point: `./cmd/localcloudmanager`. Module: `arrowhead/ah5-support-go/localcloudmanager`. See [DEPLOYMENT.md](DEPLOYMENT.md) for configuration and standalone container use. Existing compatibility limits remain in the copied upstream documentation and [UPSTREAM-README.md](UPSTREAM-README.md).

Existing role selection and API behavior are retained.

Documentation and license notices are included in this folder. Source provenance and import-only rewrites are listed in the distribution's SOURCE-MANIFEST.json. No running cloud or upstream source was changed.

See [Graphical orchestration and security editor](GRAPHICAL-ORCHESTRATION.md) for local rule and policy editing.

## Listening port

Default **8480** on all interfaces. Override with `SERVER_PORT=N` (or `PORT=N`) or `--server.port N`.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
