# TestTranslation — Go 5.2.2

Standalone test provider system, reorganized on 2026-10-28 following the Eclipse-Arrowhead-java distribution layout.

Build and operate from this folder; no original Arrowhead checkout or sibling source module is required.

```sh
make build
make test
make vet
make image
```

The executable is `bin/TestTranslation`. Entry point: `./cmd/testtranslation`. Module: `arrowhead/ah5-support-go/testtranslation`. See [DEPLOYMENT.md](DEPLOYMENT.md) for configuration and standalone container use. Existing compatibility limits remain in the copied upstream documentation and [UPSTREAM-README.md](UPSTREAM-README.md).

The dedicated launcher selects only this support-system role. The formerly shared internal runtime and regression tests are copied locally, not linked from another tree. Files for common helpers and other route implementations remain in that private runtime; this packaging does not claim new functionality or Java parity.

Documentation and license notices are included in this folder. Source provenance and import-only rewrites are listed in the distribution's SOURCE-MANIFEST.json. No running cloud or upstream source was changed.

## Listening port

Built-in default **127.0.0.1:8552** (Arrowhead default). The shipped `config.json` sets `"listen": "0.0.0.0:8552"`. Override with `"listen"` in the configuration file, `SERVER_PORT=N` or `-server.port N`; the port overrides keep the configured host.

See [LISTENING-PORTS.md](../LISTENING-PORTS.md) for precedence and all systems.
