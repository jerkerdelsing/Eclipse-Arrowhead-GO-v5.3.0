# Sources and maintenance

Primary policy: `/Users/jerkerdelsing/Work/lule/EISLAB/Project/Eclipse/PRIMARY-SOURCES.md`.

Baseline: `Eclipse-Arrowhead-go/ah5-LocalCloudManager-go/documentation/LocalCloudManager/v5.2.2`. This folder was copied into the new edition without modifying its source. Existing system/operation/DTO descriptions and historical verification records are inherited from that baseline. Document metadata, local document references and bibliography edition numbers have been updated. Runtime version literals, dependency versions, wire payload identifiers and historical dates retain their original meanings.

Go/Rust sections in the Java SysDD/IDD files use the primary language folders, per-system README/build files and native compatibility/design documents. A folder's presence or a route inventory does not prove semantic or security parity. No application source, configuration or deployment was modified.

The 5.3.0 sources are maintained directly. Use this folder's build-docs.sh; do not run a legacy generator that writes the retained 5.2.2 edition.
