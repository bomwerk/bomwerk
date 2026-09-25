# bomwerk

**Build-accurate SBOMs and EU Cyber Resilience Act evidence, on your own machine.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-informational.svg)](CMakeLists.txt)

bomwerk is a command-line scanner for teams that ship software into the EU and
have to say, on paper, what is inside it. It reads a repository, produces a
CycloneDX or SPDX inventory of the components it finds, matches them against
public vulnerability data, and can check that inventory against what the build
actually compiled and linked.

It runs entirely on your machine. There is no account, no server, no telemetry,
and it never uploads your source.

> **Status:** pre-1.0 and moving fast. There is no tagged release yet; build
> from source. The scanner and its output formats are usable today, but
> interfaces may still change before 1.0. What is usable today, what is
> planned, and the test behind each claim are listed in
> [docs/capabilities.md](docs/capabilities.md).

## Why another SBOM tool

Most scanners answer "what does this repository *declare*?" by reading manifests
and lockfiles. bomwerk answers that too, and then two questions that matter for
C and C++ firmware, where the declaration is often missing or wrong:

- **What did the build actually use?** `observe` records a real build through
  compiler shims, and `trim` reports which components were genuinely compiled,
  linked or included, so an SBOM can stop listing things the product does not
  ship.
- **What is here with no manifest at all?** Vendored and copied third-party
  source, prebuilt archives and pinned submodules are detected from evidence in
  the tree, not from a package manager that was never used.

Two more properties are deliberate: **deterministic output** (two runs over the
same tree are byte-identical, and `SOURCE_DATE_EPOCH` is honoured) and
**partial results over no results** (a malformed manifest becomes a warning and
a smaller SBOM, never a crash and never an empty file).

## See it catch what other tools miss

We publish [bomwerk/nightmare](https://github.com/bomwerk/nightmare), a small,
deliberately hostile C project built to break manifest-only scanners: a
vendored library with a known CVE, a pinned submodule nobody initialized, a
forked dependency, prebuilt binaries with no manifest at all. Clone it and
point bomwerk, or any other scanner, at it. `docs/nightmare-corpus.md`
documents each pattern and the answer a correct scanner should give, including
the cases bomwerk itself still gets wrong.

## Install

There are no prebuilt binaries yet; build from source. You need a C++20 compiler
(GCC 12+, Clang 15+, or AppleClang 14+), CMake 3.22+, and git.

```bash
git clone --recurse-submodules https://github.com/bomwerk/bomwerk.git
cd bomwerk
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

Dependencies come from <a href="https://vcpkg.io" target="_blank" rel="noopener noreferrer">vcpkg</a>,
vendored as a submodule and pinned, so the first build resolves and compiles
them. Expect it to take a while; later builds reuse the cache. The binary
lands at `build/bomwerk`.

```bash
./build/bomwerk --version
./build/bomwerk --help
```

## Quick start

<!-- docs-check: skip -->
```console
$ bomwerk scan .
bomwerk 0.1.0, scanning /home/you/project
scanned:         17 files under /home/you/project
submodules:      1 subtree(s) skipped, each submodule is one pinned component (--include-submodule-contents to scan their contents)
components:      17
  - pkg:conan/libcurl@8.5.0  [medium]
  - pkg:generic/cjson-prebuilt  [low]  third_party/cjson-prebuilt
  - pkg:generic/zlib@1.2.11  [medium]  third_party/zlib
  - pkg:github/actions/checkout@0f1e2d3c4b5a...  [high]
  - pkg:npm/debug@4.3.4  [high]
  - pkg:vcpkg/nlohmann-json@3.11.3  [high]
  ...
coverage:        17 components, 6 matchable (35.3%), 11 unmatched: 4 unmapped-purl-type, 2 unversioned-purl, 5 no-identifier
manifests:       5
output:          sbom.cdx.json (format=cyclonedx)
```

Each component carries a confidence level and, where the evidence was a
directory rather than a manifest, the path it came from. The coverage line is
the honest part: it says how many components any purl-driven tool could look up
at all, so "no vulnerabilities found" can never be mistaken for "everything was
checked".

## Commands

| Command | What it does |
| --- | --- |
| `scan` | Read a directory and write an SBOM of the components it declares or contains |
| `observe` | Run a build under bomwerk's compiler shims and record what it compiled and linked |
| `trim` | Compare an SBOM against a recorded build trace and report what the build actually used |
| `binscan` | Read the binaries a build produced: dynamic dependencies, archive contents, symbols |

Every command's full flag reference is its own `--help`, for example
`bomwerk scan --help`; the same text is kept in [docs/cli-help/](docs/cli-help/)
and checked against the binary in CI. The examples below cover the ones worth
knowing up front.

### `scan`

```bash
bomwerk scan .                                                  # sbom.cdx.json, the default
bomwerk scan . --format spdx -o sbom.spdx.json                  # SPDX instead of CycloneDX
bomwerk scan . --html report.html                                # self-contained HTML, opens offline
bomwerk scan . --offline                                         # cached advisory data only, no network
bomwerk scan . --no-vuln                                         # skip vulnerability matching entirely
bomwerk scan . --product acme-gateway --product-version 2.1.0    # record a CRA release identity
bomwerk scan . --coverage coverage.json --warnings warnings.json # machine-readable sidecars
```

### `observe`

```bash
bomwerk observe -- cmake --build build
```

Wraps any build command. It records what actually got compiled and linked to
`.bomwerk/trace.jsonl` by default; `trim` and `binscan` read that trace.

### `trim`

```bash
bomwerk trim sbom.cdx.json                          # report only: what the build actually used
bomwerk trim sbom.cdx.json -o sbom.trimmed.cdx.json # write the reduced SBOM
```

### `binscan`

```bash
bomwerk binscan sbom.cdx.json                          # report dynamic deps, archive contents, symbols
bomwerk binscan sbom.cdx.json -o sbom.enriched.cdx.json
```

### Putting it together

A full build-truth pass, from a fresh scan to what the binaries actually carry:

```bash
bomwerk scan . -o sbom.cdx.json
bomwerk observe -- cmake --build build
bomwerk trim sbom.cdx.json
bomwerk binscan sbom.cdx.json
```

## What it reads

| Ecosystem | Files |
| --- | --- |
| C / C++ | `.gitmodules`, CMake `FetchContent`/CPM, `conanfile.txt`, `conanfile.py` (read, never executed), `conan.lock`, `vcpkg.json` |
| JavaScript | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` |
| Python | `requirements.txt`, `uv.lock`, `poetry.lock` |
| Rust | `Cargo.lock` |
| Go | `go.sum` |
| Java / JVM | `pom.xml`, `gradle.lockfile` |
| .NET | `packages.lock.json`, `packages.config`, `.csproj`, `Directory.Packages.props` |
| PHP | `composer.lock`, `composer.json` |
| Ruby | `Gemfile.lock` |
| Dart | `pubspec.lock` |
| CI | GitHub Actions workflows |
| No manifest | vendored and copied C/C++ source, prebuilt archives, pinned submodules |

## Output

- **CycloneDX 1.6** (default) or **SPDX 3.0.1 / 2.3**, validated in CI against the
  official schemas.
- **A self-contained HTML report** (`--html`): inline CSS, no JavaScript, no
  external requests, prints cleanly to PDF for filing.
- **A CRA sidecar** with the release metadata a Cyber Resilience Act submission
  expects, when `--product`/`--product-version` are supplied.
- **Machine-readable extras**: `--coverage` classifies every component's
  identifier quality, `--warnings` writes every warning with a stable `BW-…`
  code.

Vulnerability findings are reported on the console and in the HTML report, and
deliberately never written into the SBOM: advisory data changes daily, SBOM
bytes must not.

## Vulnerability matching

`scan` queries <a href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV</a>
by default (`--no-vuln` turns it off) and caches every answer in SQLite, so a
second run is fast and `--offline` works
from the cache alone. `--cpe-fallback` additionally queries NVD by CPE for
Conan, vcpkg and generic components that no OSV ecosystem covers; those findings
are labelled lower-confidence everywhere they appear, because a wildcard vendor
can match a different vendor's identically-named product.

`bomwerk --endpoints` prints every host bomwerk can contact. The list is
enforced in the network layer, not merely documented: a URL that is not in it
cannot be requested. There are no inbound ports.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean run |
| `1` | Completed with warnings (an SBOM was written) |
| `2` | Incomplete (the run could not do what was asked) |

`scan --fail-on none|warnings|incomplete` decides which of those fail your
pipeline.
The default is `warnings`; `--fail-on incomplete` is the usual choice for
third-party code you do not control.

## Configuration

The common `scan` settings (what to walk, output format and paths, product
identity, CRA manufacturer details, warning suppressions) can be set once in a
`bomwerk.toml` at the root of the repository being scanned, so a reproducible
scan needs no long command line. A flag given explicitly on the command line
always overrides the file; `scan --no-config` ignores it for one run. Network,
exit-code and trace options (`--vuln`, `--offline`, `--fail-on`, `--trace`, the
license and CPE fallbacks) are command-line only.

```toml
[scan]
include = ["src", "vendor"]
exclude = ["src/generated"]

[output]
format = "cyclonedx"
path = "sbom.cdx.json"
html = "report.html"

[product]
id = "acme-gateway"
version = "2.1.0"

[cra]
manufacturer_name = "Acme GmbH"
manufacturer_email = "security@acme.example"

[warnings]
suppress = ["BW-CORE-004:npm"]
```

Every code bomwerk can raise, what it means, and how to find out which ones
your own repository triggers are in
[docs/warning-codes.md](docs/warning-codes.md).

The file lives inside the repository being scanned and is treated as untrusted
input: every path in it must resolve inside the tree, and it cannot grant new
network access. `--vuln`/`--offline` are deliberately CLI-only for the same
reason: a repository must never be able to switch off its own audit from the
inside.

## Limitations

- C and C++ dependency declarations are frequently incomplete in the wild. The
  coverage line tells you when that is the case instead of hiding it.
- Conan and vcpkg have no OSV ecosystem, so those components are only matched
  with `--cpe-fallback`, at lower confidence.
- `observe` supports GCC and Clang toolchains on Linux and macOS today.
- Component-to-component dependency edges are not recorded yet; the SBOM's
  `dependencies` section carries the root relationship only.

## Pro

Continuous monitoring of released products, a product registry, triage/VEX
state, and the ENISA Article 14 evidence report are a separate commercial
extension, built from a private repository and delivered as signed artifacts.
None of it is in this repository, and Community is not a trial: everything here
is Apache-2.0, unlimited and free. See
[the open-core boundary](docs/open-core-boundary.md).

## Contributing

Bug reports and pull requests are welcome. See
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for the build, the test suite and
the engineering rules. Security issues go through GitHub's private vulnerability
reporting on this repository; see [docs/SECURITY.md](docs/SECURITY.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
