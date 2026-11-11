# ServiceRegistry — Go 5.2.2

Standalone core system, reorganized on 2026-10-28 following the Eclipse-Arrowhead-java distribution layout.

Build and operate from this folder; no original Arrowhead checkout or sibling source module is required.

```sh
make build
make test
make vet
make image
```

The executable is `bin/ServiceRegistry`. Entry point: `.`. Module: `arrowhead/serviceregistry`. See [DEPLOYMENT.md](DEPLOYMENT.md) for configuration and standalone container use. Existing compatibility limits remain in the copied upstream documentation and [UPSTREAM-README.md](UPSTREAM-README.md).

Existing role selection and API behavior are retained.

Documentation and license notices are included in this folder. Source provenance and import-only rewrites are listed in the distribution's SOURCE-MANIFEST.json. No running cloud or upstream source was changed.

## Listening port

Default **8443** (`server.port` in `application.properties`). Override with `server.port`, `SERVER_PORT=N` or `-server.port N`; the host is `server.address`.

See [LISTENING-PORTS.md](../../LISTENING-PORTS.md) for precedence and all systems.
