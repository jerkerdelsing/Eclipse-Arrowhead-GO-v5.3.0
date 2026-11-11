# Eclipse Arrowhead — Go distribution

> **Primary source:** This is the primary Go implementation tree for further updates in this Eclipse workspace, designated on 2026-10-30. See [primary-source policy](../PRIMARY-SOURCES.md). Historical source-copy notes below describe provenance, not current development ownership.

Five core systems and seventeen support/test systems reorganized on 2026-10-28 from the supplied ah5-core-go and ah5-support-go source trees, following the Eclipse-Arrowhead-java layout.

Core systems are grouped in `ah5-core-go/`; support systems have individual `ah5-<System>-go/` folders. Each of the 22 modules contains its own source, dependencies, tests, executable launcher, configuration example, Dockerfile and standalone deployment template. No sibling source module or original checkout is needed. `go.work` is an optional development convenience; per-system builds and checks use `GOWORK=off`.

See [GO-SYSTEM-FOLDERS.md](GO-SYSTEM-FOLDERS.md), [DEPLOYMENT-GUIDE.md](DEPLOYMENT-GUIDE.md), and [verification/REPORT.md](verification/REPORT.md).

```sh
make build
make test
make vet
make verify
```

Or enter any system folder and run its own Makefile. System binaries are built into that folder's bin/ directory. The root runner defaults to two concurrent modules; use `python3 tools/run-all.py build --jobs 2` to control this. It uses the local Go module cache in offline mode; populate third-party Go dependencies with `GOWORK=off go mod download` if needed on a new computer.

This is packaging of the supplied implementations, not a functionality/parity upgrade. Compatibility assessments and Arrowhead-style documentation are retained. TestTranslation is explicitly a test provider. There is no GraphDBManager implementation in the supplied Go trees, so no Go system of that name is invented. LocalCloudManager retains the supplied native-Go implementation and embedded UI.

The old core/support trees, Java reference distribution and running clouds are unchanged. No upstream repository is initialized or published. External Go modules are resolved through go.mod/go.sum, not copied from unrelated projects. Source provenance and namespace rewrites are in SOURCE-MANIFEST.json.

## Listening port

Every core and support system has a configurable listening port (`server.port`, `SERVER_PORT`, `--server.port`) and a built-in default. The defaults, the precedence and the differences between languages are listed in this file.

See [LISTENING-PORTS.md](LISTENING-PORTS.md) for precedence and all systems.
