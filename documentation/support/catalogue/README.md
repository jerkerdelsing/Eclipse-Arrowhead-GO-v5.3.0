# Arrowhead-style LaTeX documentation

The `arrowhead.cls` and logo are copied from the local Arrowhead `roadmap/Documentation_templates/LaTeX` template, retaining attribution. Generated documents use the Arrowhead title/type/version/status header, system/service naming and document categories:

- SysD: system purpose, services, trust boundary and delimitations.
- SysDD: implementation structure, persistence, integrations and HTTPS routes.
- SD: produced service definition, version, base path and operation names.
- HTTPS IDD: implemented methods/paths and access categories.

Every document is **DEVELOPMENT**, version target 5.2.2. None asserts complete Java interchangeability. The documents describe the actual Go development profile. Consult the local Java DTOs and `contracts.json` for reference contracts; complete DTO/error-schema parity remains unverified. AMQPS and MQTT integrations are described in the catalogue and source, not presented as a complete separate protocol-conformance specification.

From the repository root, `make docs` regenerates the sources and compiles the combined catalogue twice. It requires local LaTeX with the packages used by `arrowhead.cls`, plus `longtable`, `booktabs`, `xurl`. It does not depend on the Codex built-in standalone compiler, because these documents use additional assets.

Compile an individual document from this directory so the class and logo resolve:

```sh
pdflatex -interaction=nonstopmode -halt-on-error Blacklist/Blacklist-SysD.tex
pdflatex -interaction=nonstopmode -halt-on-error Blacklist/Blacklist-SysD.tex
```

The combined PDF preview is distributed under `output/pdf/Go-Support-Systems.pdf`. Source hashes in `contracts.json` should be regenerated whenever the local Java reference changes. Automatic route extraction covers Spring mappings only; the shared Java runtime is manually reviewed. An extracted route's `Present=true` establishes a matching method/path, not matching DTOs, authorization or failure behavior.
