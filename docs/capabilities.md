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

`1.0.0-rc.2` is a release candidate, a pre-release tag, so nothing is
**shipped** yet. **Since** already names 1.0.0, the first release that will
contain each preview row; the 1.0.0 tag moves those rows to shipped.

`scripts/check_docs.py` enforces this page in CI (ctest `docs_contract`):

- Every command the binary has must have a row here.
- Every preview or shipped row must cite a registered test.
- No planned row may already exist in the binary.
- Every `bomwerk ...` example in the README and `docs/` must match `--help`.

## Commands

| Capability | Status | Since | Evidence |
| --- | --- | --- | --- |
| `scan` | preview | 1.0.0 | `golden_*`, `purl_spec_*`, `cyclonedx_schema_validation` |
| `observe` | preview | 1.0.0 | `observe_cmake_build` |
| `trim` | preview | 1.0.0 | `trim_used_set`, `trim_nightmare_config_*` |
| `binscan` | preview | 1.0.0 | `binscan_dynamic_deps` |

## Notable options

| Capability | Status | Since | Evidence |
| --- | --- | --- | --- |
| `--endpoints` (list every outbound host, enforced in the network layer) | preview | 1.0.0 | `endpoints` |
| `scan --format spdx` (SPDX 3.0.1 and 2.3 JSON) | preview | 1.0.0 | `spdx_2_3_schema_validation`, `spdx_3_0_schema_validation` |
| `scan --html` (self-contained offline report) | preview | 1.0.0 | `html_report` |
| `scan --product --product-version` (CRA release identity) | preview | 1.0.0 | `cra_sidecar`, `golden_mixed-product` |
| `scan --coverage` / `scan --warnings` sidecars | preview | 1.0.0 | `coverage_report`, `warnings_report` |
| `scan --fail-on` | preview | 1.0.0 | `fail_on_cli` |
| `scan --offline` / `scan --no-vuln` / `scan --cpe-fallback` | preview | 1.0.0 | `osv`, `vuln_cache`, `nvd` |
| `scan --all-cpes` | preview | 1.0.0 | `all_cpes_cli`, `golden_all-cpes-npm` |
| `scan --license-fallback` | preview | 1.0.0 | `license_enrichment`, `license_fallback_timeout_cli` |
| `scan --config` / `scan --no-config` (`bomwerk.toml`) | preview | 1.0.0 | `scan_config`, `golden_repo-config` |
| `scan --fingerprint-index` (identify vendored C/C++ by file hash against a corpus you supply) | preview | 1.0.0 | `fingerprint`, `scan_fingerprint`, `sha256`, `golden_nightmare-corpus-fingerprint` |
| `scan` reads ESP-IDF component manager files (`dependencies.lock`, `idf_component.yml`) | preview | 1.0.0 | `esp_idf`, `golden_esp-idf-*` |
| Atomic artifact writes: SBOM, CRA sidecar, coverage, warnings, HTML, trimmed and enriched SBOMs, binscan sidecar, trace (Linux, macOS) | preview | 1.0.0 | `atomic_file`, `atomic_artifacts_cli`, `trace_check` |

`--fingerprint-index` needs a corpus index, and bomwerk does not ship one: the
flag is useless on its own. Build one with
`scripts/build_fingerprint_corpus.py`, which downloads pinned upstream releases
and hashes them, or obtain one. There is no default path, so a plain `scan`
behaves exactly as it did before this option existed. The matcher reads that
one local file and opens no socket, so `--endpoints` is unchanged and
`--offline` makes no difference to it.

### How artifacts are written

Every file bomwerk generates (the SBOM, the CRA sidecar, `--coverage`,
`--warnings`, `--html`, `trim -o`, the `binscan` sidecar and enriched SBOM, and
the `observe` trace) is first written in full to a temporary file beside it,
flushed to disk, and then renamed over the destination. A reader sees either the
previous whole file or the new whole file, never a truncated one. If any step
fails (the directory is not writable, the disk fills up, the destination is a
directory or read-only), the previous file is left exactly as it was, the
temporary file is removed, and the command exits 2 with a message that names the
step, the path and what to check. A replaced file keeps its permissions, and a
destination that is a symbolic link has its target replaced, not the link.

The temporary file is always named
`<file name>.bomwerk-<process id>-<number>.tmp` in the destination's directory,
for example `sbom.cdx.json.bomwerk-4182-0.tmp`. The name is plain and
predictable on purpose: a `.tmp` extension, no random characters, not hidden,
never executable. If endpoint protection flags the write-then-rename pattern,
allowlist `*.bomwerk-*.tmp` in the output directories. A run killed mid-write
(for example with `kill -9`) can leave one such file behind. It never replaces
the destination, and you can delete it.

This is tested on Linux and macOS. The Windows code path (`MoveFileExW` with
write-through) exists but is not built or tested, since Windows binaries are
not planned.

### What `--cpe-fallback` asks NVD

The fallback covers the components OSV cannot match by purl: Conan, vcpkg and
generic purls, and GitHub, GitLab or Bitbucket repositories pinned to a tag
rather than a commit. For each, it sends NVD one `virtualMatchString` with a
wildcard vendor, the purl's name as product and its version without a leading
`v`: `cpe:2.3:a:*:zlib:1.2.11`. Part `a` (application) is always asked.

NVD files operating systems and RTOS kernels under part `o`, so a component
whose name is on a short reviewed list (`contiki-ng`, `freertos`,
`linux_kernel`, `mbed_os`, `riot`, `zephyr`) is asked a second time with part
`o`: `cpe:2.3:o:*:zephyr:3.5.0`. Each list entry in `src/vuln/cpe.cpp` cites
the NVD dictionary entry it was checked against, and a name joins the list only
after that check. The two answers merge into one finding per component,
deduplicated by CVE id, and every other component still costs one request.
Each answer is cached under its own match string, so `--offline` replays both.
All CPE-fallback findings are labelled lower confidence: a wildcard vendor
also matches another vendor's product of the same name.

## Planned

| Capability | Status | Since | Evidence |
| --- | --- | --- | --- |
| Prebuilt, signed static binaries (Linux, macOS) | planned | | Release pipeline not built yet; build from source until then. Windows binaries are not planned |
| `scan --stats` (timings and counts) | planned | | Performance work in progress |
| `scan --format all` (CycloneDX and SPDX in one run) | planned | | Run `scan` once per format today |
| Component-to-component dependency edges | planned | | See [Limitations](../README.md#limitations) |

## Not in Community

Monitoring, the product registry, triage/VEX state and CRA report drafts belong
to the separately licensed Pro extension. They are not commands of this binary,
so they do not appear here. See [the open-core boundary](open-core-boundary.md).
