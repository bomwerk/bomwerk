# Warning codes

Every warning bomwerk raises carries a stable, permanent id like `BW-CORE-004`: this is
the full list Community can produce, generated from `core::WarningCode` in
`src/core/warning_code.cpp`. `tests/python/test_warning_codes_reference.py` checks this
file against that source on every change, so it cannot drift silently.

An id's meaning never changes once shipped, and an id is never reused for a different
cause, even after the cause it names becomes unreachable. The numbering has gaps on
purpose (for example `BW-VULN-007` is missing): a composed build can register its own
codes alongside these without ever colliding with one, so a gap here is a code owned
by something other than this Community build, not a mistake in this table.

Two ids are not in the table because they are not something you would ever suppress:
`BW-EXT-000` is a fallback used only if a caller misuses the lookup API directly, and
`BW-UNKNOWN` is a defensive fallback the compiler-checked switch in
`warning_code.cpp` guarantees is unreachable.

## Finding out which codes your repository actually triggers

The table below is everything bomwerk *can* raise; a given repository usually
triggers only a handful. Ask bomwerk directly instead of guessing from this list:

```bash
bomwerk scan . --warnings warnings.json --quiet
```

Each entry in `warnings.json` looks like this:

```json
{
  "code": "BW-CORE-004",
  "ecosystem": "npm",
  "message": "manifest declares ranges only, no lockfile alongside it",
  "count": 3,
  "suppressed": false,
  "affected_paths": ["frontend/package.json", "tools/package.json"]
}
```

`count` collapses every occurrence of the same `(code, ecosystem)` pair into one
entry, so a lockfile-wide issue is one line, not hundreds. Copy the `code` (and,
to scope it to one ecosystem, append `:` and the `ecosystem` value) straight into
`bomwerk.toml`'s `[warnings] suppress` list, documented in the
[README's Configuration section](../README.md#configuration).

## Suppressing a code

```toml
[warnings]
suppress = ["BW-CORE-004:npm", "BW-GIT-004"]
```

- `"BW-CORE-004:npm"` suppresses that cause only when it fires for the `npm`
  ecosystem; the same cause still counts toward the exit code for every other
  ecosystem.
- `"BW-GIT-004"` (no `:ecosystem` suffix) suppresses that cause everywhere it
  fires.

Suppressing a code never removes it from any artifact: it still appears on the
console, in `--warnings`, and with `"suppressed": true` in the manifest above.
The only thing suppression changes is whether that occurrence counts toward
`--fail-on warnings` (the default `--fail-on` policy), so a repository you have
already reviewed and accepted stops failing your pipeline over a cause you
cannot fix.

## All codes

### Manifest and lockfile parsing, file walking, purls

| Code | Meaning |
| --- | --- |
| `BW-CORE-001` | Nesting exceeds the JSON depth limit |
| `BW-CORE-002` | File is not valid JSON |
| `BW-CORE-003` | File is not valid TOML |
| `BW-CORE-004` | Manifest declares ranges only, no lockfile alongside it |
| `BW-CORE-005` | A real lockfile was found with no parser for it yet |
| `BW-CORE-006` | Package/dependency count budget reached |
| `BW-CORE-007` | Manifest/lockfile file count budget reached |
| `BW-CORE-008` | File exceeds its byte budget |
| `BW-CORE-009` | File could not be read |
| `BW-CORE-010` | An assembled component purl failed validation |
| `BW-CORE-011` | Entries without a resolvable name/version were skipped |
| `BW-CORE-012` | An entry had an unreadable shape and was skipped |
| `BW-CORE-013` | A recognized lockfile's format/version is not supported |
| `BW-CORE-014` | The manifest's own component lacks enough identity to emit |
| `BW-CORE-015` | A name or version depends on an unresolved variable |
| `BW-CORE-016` | A dependency declaration has no name, repository or URL |
| `BW-CORE-017` | A dependency is not pinned to a resolved reference |
| `BW-CORE-018` | The directory walk stopped early |
| `BW-CORE-019` | A skipped build-output directory holds a recognized manifest |
| `BW-CORE-020` | A supplied purl is malformed |
| `BW-CORE-021` | A --manifest-list/--exclude-list file is unreadable |
| `BW-CORE-022` | A --manifest-list/--exclude-list file is empty |

### `bomwerk.toml` validation

| Code | Meaning |
| --- | --- |
| `BW-CONFIG-001` | Config file is not valid TOML |
| `BW-CONFIG-002` | Config file could not be read |
| `BW-CONFIG-003` | Config file exceeds its size cap |
| `BW-CONFIG-004` | A config key has the wrong value type |
| `BW-CONFIG-005` | A config array entry is invalid or unsafe |
| `BW-CONFIG-006` | Config names an unknown key |
| `BW-CONFIG-007` | Config names an unknown table |
| `BW-CONFIG-008` | A top-level config key is not a table |
| `BW-CONFIG-009` | A config value does not match its expected format |
| `BW-CONFIG-010` | Config uses a key that has been removed |
| `BW-CONFIG-011` | Config carries a secret directly instead of by reference |
| `BW-CONFIG-012` | A config section is missing required keys and stays unconfigured |
| `BW-CONFIG-013` | A config/metadata file could not be written |

### Git metadata (`.gitmodules`, `.git/config`)

| Code | Meaning |
| --- | --- |
| `BW-GIT-001` | A .git config file has an invalid structure |
| `BW-GIT-002` | A submodule entry has no path |
| `BW-GIT-003` | A submodule entry has an unsafe path |
| `BW-GIT-004` | A submodule is not initialized |
| `BW-GIT-005` | A submodule's url is missing or cannot be resolved |

### `observe` (build-trace capture)

| Code | Meaning |
| --- | --- |
| `BW-OBSERVE-001` | No build trace file was written |
| `BW-OBSERVE-002` | Trace lines were unreadable and were dropped |
| `BW-OBSERVE-003` | The trace exceeds its line limit |
| `BW-OBSERVE-004` | The trace could not be rewritten in canonical order |
| `BW-OBSERVE-005` | The shim binary was not found or not executable |
| `BW-OBSERVE-006` | The shim directory could not be created |
| `BW-OBSERVE-007` | A tool shim could not be created or recorded |
| `BW-OBSERVE-008` | No compiler, linker or archiver was found on PATH |
| `BW-OBSERVE-009` | The trace holds no compiler invocations naming a source file |
| `BW-OBSERVE-010` | Observed compile/link evidence lies outside the scan root |
| `BW-OBSERVE-011` | A compile/link argument was a response file bomwerk does not open |
| `BW-OBSERVE-012` | A link argument did not resolve to a file bomwerk observed |
| `BW-OBSERVE-013` | An auto-detected build trace could not be applied |
| `BW-OBSERVE-014` | A build trace judged zero components as used |

### `binscan` (ELF/`ar` reader)

| Code | Meaning |
| --- | --- |
| `BW-BINSCAN-001` | A binary artifact could not be read |
| `BW-BINSCAN-002` | A binary artifact exceeds its size cap |
| `BW-BINSCAN-003` | A binary artifact has a malformed ELF/ar header |
| `BW-BINSCAN-004` | Binary-level dependency evidence is partial for this run |

### SBOM readers (`trim`, `binscan` re-reading a CycloneDX/SPDX document)

| Code | Meaning |
| --- | --- |
| `BW-SBOM-001` | An SBOM document could not be read |
| `BW-SBOM-002` | An SBOM document is not in the expected/recognized format |
| `BW-SBOM-003` | An SBOM component entry was skipped |

### Output writers

| Code | Meaning |
| --- | --- |
| `BW-OUTPUT-001` | A --report-config field is invalid |

### Vulnerability matching (OSV/NVD clients, license-fallback enrichment, HTTP transport)

| Code | Meaning |
| --- | --- |
| `BW-VULN-001` | The vulnerability cache could not be opened |
| `BW-VULN-002` | A request targeted a non-allowlisted endpoint and was refused |
| `BW-VULN-003` | An HTTP request failed |
| `BW-VULN-004` | An HTTP request returned an unexpected status |
| `BW-VULN-005` | A feed response was malformed |
| `BW-VULN-006` | Vulnerability match coverage is incomplete for this run |
| `BW-VULN-008` | License-fallback enrichment is incomplete for this run |
