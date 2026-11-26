# Changelog

All notable changes to bomwerk Community. Format:
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning:
[SemVer](https://semver.org/). One line per task
(`docs/CONTRIBUTING.md` hard rule 7). Entries reference issues and pull
requests in this repository.

This file starts with the first public release. The pre-publication development
log lives in Bomwerk's private archive, because the history it described
contained the paid extension's source.

## [Unreleased]

### Added
- The vendored-source heuristic reads vendoring records, the notes a project
  keeps beside code it copied in. These are a directory's `README.md` index in
  Godot's layout (one `## <folder>` section with `- Version:` and
  `- Upstream:` per library) and a `README.chromium` inside the folder. A
  stated release is reported as `pkg:generic/<folder>@<release>`. A stated
  commit with a GitHub, GitLab or Bitbucket repository upstream becomes
  `pkg:github/<owner>/<repo>@<commit>`, as a leftover `.git` does. The record
  is named in the evidence. A record never overrides the library's own header
  or build file: a different release is reported as `BW-VENDORED-001` with
  both values. The version tables also read libjpeg-turbo's
  `set(VERSION 3.1.2)` and openjpeg's `set(OPENJPEG_VERSION_MAJOR/_MINOR/_BUILD)`
  from their own top-level `CMakeLists.txt`, and protobuf's encoded
  `PROTOBUF_VERSION 3019001` (3.19.1). Godot's 69 vendored directories go from
  4 to 65 with a version, and OpenCV's 3rdparty libjpeg-turbo, openjpeg and
  protobuf are now versioned. See `docs/vendored-versions.md` (T123).
- `scan` reads the ESP-IDF component manager's files. A `dependencies.lock`
  reports each component at its locked version with High confidence:
  registry components as `pkg:generic/<namespace>/<name>@<version>` with the
  lock's `component_hash` as their SHA-256, the framework itself as
  `pkg:generic/espressif/esp-idf@<version>`, and git components through the
  usual forge mapping with their repository subdirectory as the purl subpath.
  An `idf_component.yml` is read only where no lock sits in its directory or
  above it; its constraints stay in the evidence and the component is
  reported version-less at Medium, never with a guessed version. Local
  components are the project itself and are not reported, and files under
  `managed_components/` are never read. None of these identities has an OSV
  ecosystem, so match coverage lists them as unmatched unless the NVD CPE
  fallback finds them. See `docs/esp-idf-components.md` (T86).
- The NVD CPE fallback (`vuln::match_via_cpe`) takes an optional stop
  predicate, `NvdOptions::should_stop`, so a long-running caller can shut down
  during NVD's rate-limit waits. It is asked before each request and every
  250 ms of the wait; once it says stop, no further request is sent and the
  CPEs not yet fetched are answered from stale cache or reported unchecked.
  The wait before a request is never shortened. `scan` does not set it and
  behaves as before. `vuln::nvd_request_interval` and
  `vuln::wait_for_nvd_interval` expose the same spacing and wait to a caller
  that makes several lookups.
- `vuln::MatchOutcome::unresolved_purls` lists the purls the OSV pass queried
  but could not answer at all (fetch failed, a page of a long advisory list
  failed, or `--offline` with nothing cached), so a caller that keeps state
  between runs can tell "unknown" from "clean". `scan` output is unchanged.
- `make_curl_http_get` and `make_curl_http_post` take an optional
  `should_abort` predicate that aborts a request in flight, so a long-running
  caller can shut down without waiting out the 60 s timeout. `scan` does not
  set it.
- `scan` versions a submodule that was never checked out, the shape of every
  default CI clone (`actions/checkout` without `submodules:`). The commit the
  superproject pins for it is read from the gitlink in `.git/index`, as a
  file and never through `git`, so `pkg:github/openssl/openssl` becomes
  `pkg:github/openssl/openssl@<commit>` and CVE lookups can match it. Index
  versions 2, 3 and 4 and SHA-1 and SHA-256 repositories are read; a split
  index, an unknown version, an index over 128 MiB or one that is
  structurally inconsistent is refused whole with `BW-GIT-007`, never
  half-read. A checked-out HEAD still wins. New fuzz targets
  `fuzz_git_index_sha1` and `fuzz_git_index_sha256` (T110).
- Every parser of untrusted input has a libFuzzer harness: the manifest and
  lockfile producers, GitHub Actions workflows, `.gitmodules`, ELF and `ar`
  binaries, CycloneDX input, build trace lines, vendored version headers, the
  fingerprint corpus index, `bomwerk.toml`, and OSV, NVD and registry license
  responses. Pull requests run a ten-minute fuzz smoke, a two-hour run fuzzes
  every night, and each harness also runs as a ctest that replays its seeds and
  every input that once crashed it. Each producer has a `parse_bytes` entry
  point that parses a file from memory through the same code a scan uses. See
  `docs/fuzzing.md` (T40).
- `scan` reads Zephyr west manifests (`west.yml`, `west.yaml`) and reports one
  component per `manifest.projects[]` entry, resolved by west's own rules: an
  explicit `url` wins, otherwise the project's remote (or `defaults.remote`,
  or the only remote) supplies its `url-base` joined with `repo-path` or the
  name, and the revision falls back to `defaults.revision`, kept verbatim.
  github.com projects become `pkg:github/<owner>/<repo>@<revision>`, other
  hosts `pkg:generic`; a full SHA is High confidence, a tag or branch Medium.
  `manifest.self` is never a component, and projects pulled in by `import:`
  are named in a warning instead of being guessed. Upstream Zephyr v4.5.0's
  manifest yields all 81 of its projects. See `docs/west-manifests.md`
  (T87).
- `scan` falls back to a `composer.json` where no `composer.lock` sits beside
  it, so a PHP project that never committed a lock produces a dependency list
  instead of nothing (laravel/framework went from zero components to its full
  declared set). `require` and `require-dev` are declared ranges, not resolved
  versions, so each component is Medium confidence with a **version-less**
  purl and the range recorded as evidence: a `pkg:composer/...@^7.8` could
  never match an OSV or CPE record, so the version is dropped rather than
  guessed. `require-dev` becomes CycloneDX `scope: "excluded"`, platform
  pseudo-requirements (`php`, `hhvm`, `ext-*`, `lib-*`, `composer-*`) are
  skipped with one counted warning per file, and a `composer.json` inside an
  installed tree such as `vendor/` is ignored as the dependency's own
  declaration. A `composer.lock` is still authoritative wherever one exists,
  per directory, and a version-less fallback component is dropped when a lock
  elsewhere in the scan already resolved the same package, so a monorepo does
  not list it twice (T66).
- `scan --fingerprint-index <path>` identifies vendored C/C++ libraries by the
  content of their files instead of by a version header, against a corpus of
  pinned upstream releases. A match fills in a version no header states and
  reports how many files agree,
  so a copy that differs from upstream in one file says so instead of passing
  as pristine. Evidence appears as a `bomwerk:fingerprint` CycloneDX property,
  and a version another producer already resolved is never overwritten: a
  conflict is reported as `BW-FINGERPRINT-004`. The corpus is not shipped;
  build one with `scripts/build_fingerprint_corpus.py`. There is no default
  path, so a scan without the option behaves exactly as before, and the matcher
  reads one local file and opens no socket, leaving `--endpoints` and
  `--offline` untouched (T36).
- The vendored-source heuristic reads a version written as a bare dotted number,
  not only a quoted string, so uthash (`#define UTHASH_VERSION 2.4.0`) is reported
  as `pkg:generic/uthash@2.4.0` instead of by its folder name. A bare integer
  never qualifies.
- The vendored-source heuristic assembles a version split across MAJOR, MINOR
  and PATCH macros for the libraries listed for it, starting with cJSON, so
  nightmare's `third_party/cjson-prebuilt` is reported as
  `pkg:generic/cjson@1.7.15` at Medium instead of by its folder name. All three
  parts must be single, bare, non-negative integers or no version is reported
  at all, never a partial one; the rows are opt-in because a MAJOR/MINOR pair is
  not always the release (libsodium's is its ABI version). A bare or split
  version macro now names a vendored directory only when the folder carries the
  library's name, so a library that bundles `uthash.h` (godot's
  `thirdparty/libktx`) keeps its own name instead of becoming `uthash@1.9.1`,
  and a header cut off by the read cap no longer yields a truncated value (T109).
- Initial public release of bomwerk Community, the Apache-2.0 scanner:
  - `scan` reads git submodules, CMake `FetchContent`/CPM, `conanfile.txt`,
    `conan.lock`, `vcpkg.json`, `package-lock.json`, `pnpm-lock.yaml`,
    `yarn.lock`, `pom.xml`, `packages.lock.json` and `.csproj`,
    `requirements.txt`, `uv.lock`, `poetry.lock`, `Cargo.lock`, `go.mod`,
    `composer.lock`, `Gemfile.lock`, `pubspec.lock` and GitHub Actions
    workflows, and detects vendored C/C++ code that carries no manifest at all;
  - CycloneDX 1.6 and SPDX 3.0.1 output, deterministic to the byte: sorted
    collections, canonical JSON, UUIDv5 component ids and `SOURCE_DATE_EPOCH`
    support, so two runs of the same tree produce identical files;
  - vulnerability matching against OSV with a local SQLite cache, optional
    NVD CPE fallback for the C/C++ purls OSV cannot answer, optional registry
    license enrichment, and a fully offline mode;
  - `observe` records a real build and maps compiled and linked artifacts back
    to their sources, `trim` reduces an SBOM to what a build actually used, and
    `binscan` reads ELF and `ar` artifacts directly;
  - a self-contained HTML report, and the `--endpoints` listing of every host
    the tool can contact, enforced in the transport rather than documented.
- `scripts/audit_public_history.py` audits a repository's whole history: every
  ref, commit and object, including objects left behind by deleted branches,
  against the public layout, an optional private policy, and optional
  reference repositories. `docs/CONTRIBUTING.md` carries the engineering rules
  for contributors.
- Continuous integration runs on pull requests and on pushes to `main`, so a
  fork's contribution is built and tested, and a `public-history` job audits
  the repository's whole history on every change rather than once at
  publication. macOS is back in the build matrix. `docs/SECURITY.md` states
  how to report a vulnerability, what counts as one, and what does not.
- `docs/capabilities.md` lists what is usable today (preview), what is planned,
  and the test behind each claim. `docs/cli-help/` pins every command's
  `--help`, and the `docs_contract` test fails when the help text, the ledger,
  a documented `bomwerk ...` example or a relative link drifts from the binary.
  The README's Quick-start output, ecosystem table (`go.sum`, `conanfile.py`,
  `gradle.lockfile`, `packages.config`, `Directory.Packages.props`) and
  `bomwerk.toml` scope now match the code.

### Changed
- Informational warning codes: a code can now describe a complete result
  without degrading the run. It is still printed (at info level), written to
  `--warnings` and the HTML report, but never sets exit code 1 on its own.
  The first is `BW-GIT-006`: a submodule versioned from the superproject's
  index raises it instead of `BW-GIT-004`, so a default CI clone of a
  repository whose only gap was uninitialized submodules now exits 0. See
  `docs/warning-codes.md` (T110).
- The bounds-checked `ByteCursor` moved from `binscan` to `core`, so the git
  index reader and the ELF and `ar` readers share one reviewed type (T110).
- Parsing no longer slows down quadratically on hostile or unusual input, with
  the same output as before. Fixed spots: the XML scanner behind `pom.xml` and
  `.csproj` reading, merging many duplicates of one component, Maven and NuGet
  line numbers in warnings, GNU `ar` long names, relative submodule urls and the
  west remote lookup. MSBuild files are stripped of comments once instead of
  twice, OSV severity answers are parsed once, and manifest discovery no longer
  allocates a file name per indexed file (T40).
- Release candidate `1.0.0-rc.1`: `bomwerk --version` carries the SemVer
  pre-release label, `vcpkg.json` is checked against the CMake version by the
  `version_sync` test, the README lists every prerequisite a clean Ubuntu 24.04
  machine needs, and `docs/capabilities.md` names 1.0.0 as the release each
  preview row ships in.
- Community carries only what Community does: the warning taxonomy enumerates
  only causes this build can raise, `bomwerk --endpoints` lists only hosts this
  build can contact, and the cache schema creates only tables this build reads
  and writes. A build composed with the paid extension registers its own
  warning codes and endpoints through `Result::warn(WarningCodeInfo, ...)` and
  `vuln::register_feed_endpoints`, and creates its own tables, so both
  artifacts stay exact about themselves.
- Fixture descriptions, notes and comments no longer carry internal tracker
  identifiers, and the `=>` glyph replaces a typographic arrow throughout, so
  everything in the tree reads without access to anything outside it.
- Release candidate `1.0.0-rc.2`: the HTML report fix listed under Fixed. CI builds macOS on
  `macos-15`, and Apple links no longer warn about the repeated core library (#6).

### Fixed
- A GitHub, GitLab or Bitbucket dependency pinned to a tag, not a commit, is no longer counted as checked by OSV: OSV answers `{}` for such a purl (Zephyr `v3.5.0`, a known-vulnerable Action), so it read as clean when nothing had checked it. Its match coverage is now `unmapped-purl-type`, a plain scan publishes a wildcard-vendor CPE for it, and `--cpe-fallback` asks NVD about it. The CPE fallback also asks NVD with part `o` (operating system) for a short reviewed list of OS and RTOS names (`contiki-ng`, `freertos`, `linux_kernel`, `mbed_os`, `riot`, `zephyr`), where NVD files their releases: Zephyr 3.5.0 has 74 CVEs under part `o` and none under part `a`. Both answers merge into one lower-confidence finding per component, each part is cached on its own so `--offline` replays both, every other component still sends one request, and a listed OS publishes its CPE with part `o`. The part `o` answer is a new cache entry, so after upgrading, an `--offline` scan reports a listed OS (a vendored FreeRTOS, say) unchecked until one online scan has fetched it (T122).
- A synthesized CPE drops one leading `v` or `V` from the version when a digit follows it, because NVD files the bare number: FreeRTOS `V11.1.0` now gives `cpe:2.3:a:*:freertos:11.1.0` instead of `...:v11.1.0`, which no NVD entry matched, and Go modules under `--all-cpes` lose their `v` the same way. Versions like `vendor-1` keep their letter, purls are unchanged, and CPE-fallback findings are still labelled lower-confidence. The NVD cache is keyed by the CPE, so after upgrading, the first online scan makes one fresh lookup for each such component, and an `--offline` scan reports them unchecked until it has (T92).
- `scan` finds vendored libraries in OpenCV-style trees: `3rdparty/`, `third-party/` and `extern/` are vendor roots now, next to `third_party/`, `vendor/` and the rest, and the directory name is matched ignoring case, so `ThirdParty/` (VTK, ParaView) and `External/` count too. Only whole directory names match, and a trigger below a test or fixture directory is still ignored. An `include/` folder right after a vendor root is looked through, so OpenCV's `3rdparty/include/vulkan` and `3rdparty/include/opencl` are two libraries instead of one called `include` (T121).
- The nightly corpus minimization (`scripts/run_fuzz.py --merge`) no longer fails at random: libFuzzer's merge control file was kept beside the cached corpus, so the next night's merge reused coverage for inputs the previous merge had deleted and exited 1 when it tried to keep one. The control file now lives in the artifact directory for one merge only, a leftover one is deleted, a merge that cannot finish is a warning that keeps the corpus unchanged, and `fuzz-nightly` uploads every `merge.log` (T120).
- A `package-lock.json` entry whose `link` or `dev` field is present but not a boolean (for example `"link": "some-string"`) no longer crashes `scan`: both are now treated as absent instead of throwing `nlohmann::json::type_error`. Found by fuzzing (T40).
- A `bomwerk.toml` `[scan].max_packages` far outside `int64_t`'s range (a float like `8.9e87`) no longer triggers undefined behavior while being rejected; it is read with `value_exact<int64_t>()`, which only accepts a real TOML integer node, so it lands in the existing "must be an integer" warning instead of toml++'s float-to-int conversion. Found by fuzzing (T40).
- `scan` now reports an incomplete result when the directory walk stops early on a repository whose only manifests are CMake or Conan files, as it already did for every other ecosystem (T40).
- A Python requirement or lock entry whose name is only separators (`_`, `._.`, `..-`) is skipped instead of producing a purl with no name (`pkg:pypi/`). Found by fuzzing (T40).
- A vendored version macro holding an empty string (`#define ZLIB_VERSION ""`) is no longer reported as a match with an empty version; a later real definition of the same macro still counts. Found by fuzzing (T40).
- A CMake `URL_HASH` whose algorithm is not a plain name (a control byte or `&` before the `=`, with a valid hex digest) no longer produces an unparsable purl: the checksum is ignored with a warning and the component is still reported. Found by fuzzing (T40).
- An oversized GitHub Actions workflow, CMake file or `conanfile.txt`/`conanfile.py`
  is now read up to its last complete line, so a `uses:` value, `GIT_TAG` or
  requirement cut off by the size cap can no longer become a component with a
  truncated name or version. An oversized `conan.lock` is skipped with one
  warning instead of being parsed as broken JSON. Every manifest producer now
  reads files through one shared pipeline with the same warning texts for an
  unreadable or oversized file (T40).
- `scan` strips a UTF-8 byte-order mark from every manifest, not only the JSON
  ones, so a `Cargo.lock`, `go.sum`, `pom.xml`, `pnpm-lock.yaml`, `yarn.lock`,
  `Gemfile.lock`, `pubspec.lock`, requirements file, `west.yml` or CMake file
  saved with one no longer loses its first entry (T40).
- When the GitHub Actions, conan or vcpkg producer reaches its entry budget it
  warns once, instead of repeating the warning for every remaining file. The
  CMake producer and the conan producer now report a scan as incomplete when
  the directory walk itself was cut short (T40).
- The HTML report renders an empty or unknown value as `-` instead of `: `, in table
  cells and summary tiles (#5).
- A build variable no parser could resolve no longer ends up in a component purl
  (`pkg:generic/${NAME}`, `pkg:nuget/Azure.Identity@$(AzureIdentityVersion)`).
  CMake `${...}` is expanded from the `set()` commands of any CMake file in the
  tree, MSBuild `$(...)` from the project, the `Directory.Build.props` and
  `Directory.Packages.props` above it, what they import and `eng/Versions.props`,
  and a pom's own coordinates now resolve (`${revision}`, `project.artifactId`).
  What stays unresolved is left out: a name drops the dependency, a version or
  URL is omitted and the component is reported at low confidence, and each case
  warns (`BW-CORE-015`) with the file and line. A Maven dependency with an
  unresolved `groupId` or `artifactId` is now dropped instead of kept, and one
  with an unresolved `version` is kept without it instead of dropped. NuGet's
  exact-version notation `[1.2.3]` is read as `1.2.3`. A repository whose
  `.csproj` files use properties that cannot be resolved now exits 1 until
  `BW-CORE-015:nuget` is suppressed.
