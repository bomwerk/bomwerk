# Capabilities

What bomwerk Community can do today, what is usable but not yet released, and
what is only planned. This page and the help texts in [`cli-help/`](cli-help/)
are the reference for command syntax: if a blog post, slide or website example
disagrees with them, those are what is wrong.

- **shipped**: in a tagged release. Its syntax only changes with a major version.
- **preview**: on `main` and covered by tests, but not yet in a tagged release.
  Build from source to use it (see the [README](../README.md#install)). The
  syntax may still change before 1.0.
- **planned**: not implemented. Do not document it as available.

There is no tagged release yet, so nothing is **shipped**. The first tag moves
the preview rows it contains to shipped and records the version in **Since**.

`scripts/check_docs.py` enforces this page in CI (ctest `docs_contract`):

- Every command the binary has must have a row here.
- Every preview or shipped row must cite a registered test.
- No planned row may already exist in the binary.
- Every `bomwerk ...` example in the README and `docs/` must match `--help`.

## Commands

| Capability | Status | Since | Evidence |
| --- | --- | --- | --- |
| `scan` | preview | 0.1.0 | `golden_*`, `purl_spec_*`, `cyclonedx_schema_validation` |
| `observe` | preview | 0.1.0 | `observe_cmake_build` |
| `trim` | preview | 0.1.0 | `trim_used_set`, `trim_nightmare_config_*` |
| `binscan` | preview | 0.1.0 | `binscan_dynamic_deps` |

## Notable options

| Capability | Status | Since | Evidence |
| --- | --- | --- | --- |
| `--endpoints` (list every outbound host, enforced in the network layer) | preview | 0.1.0 | `endpoints` |
| `scan --format spdx` (SPDX 3.0.1 and 2.3 JSON) | preview | 0.1.0 | `spdx_2_3_schema_validation`, `spdx_3_0_schema_validation` |
| `scan --html` (self-contained offline report) | preview | 0.1.0 | `html_report` |
| `scan --product --product-version` (CRA release identity) | preview | 0.1.0 | `cra_sidecar`, `golden_mixed-product` |
| `scan --coverage` / `scan --warnings` sidecars | preview | 0.1.0 | `coverage_report`, `warnings_report` |
| `scan --fail-on` | preview | 0.1.0 | `fail_on_cli` |
| `scan --offline` / `scan --no-vuln` / `scan --cpe-fallback` | preview | 0.1.0 | `osv`, `vuln_cache`, `nvd` |
| `scan --all-cpes` | preview | 0.1.0 | `all_cpes_cli`, `golden_all-cpes-npm` |
| `scan --license-fallback` | preview | 0.1.0 | `license_enrichment`, `license_fallback_timeout_cli` |
| `scan --config` / `scan --no-config` (`bomwerk.toml`) | preview | 0.1.0 | `scan_config`, `golden_repo-config` |

## Planned

| Capability | Status | Since | Evidence |
| --- | --- | --- | --- |
| Prebuilt, signed static binaries (Linux, macOS, Windows) | planned | | Release pipeline not built yet; build from source until then |
| `scan --stats` (timings and counts) | planned | | Performance work in progress |
| `scan --format all` (CycloneDX and SPDX in one run) | planned | | Run `scan` once per format today |
| Component-to-component dependency edges | planned | | See [Limitations](../README.md#limitations) |

## Not in Community

Monitoring, the product registry, triage/VEX state and CRA report drafts belong
to the separately licensed Pro extension. They are not commands of this binary,
so they do not appear here. See [the open-core boundary](open-core-boundary.md).
