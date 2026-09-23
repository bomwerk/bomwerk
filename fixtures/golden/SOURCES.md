# Golden fixtures: what they are and how to change them

Unlike the sibling corpora, **these are not vendored from upstream projects**.
`gitmodules/`, `cmake/` and `conan/` hold real files real projects wrote, because
a parser should be tested against input its author did not invent. These are the
opposite on purpose: hand-written, minimal repos, each one built to make a single
seam visible in the output document. A vendored 56-submodule `.gitmodules` makes
a wonderful parser fixture and an unreadable snapshot diff.

Every commit id here is **synthetic** (valid 40-hex, deliberately patterned, e.g.
`0f1e2d3c…`). Nothing here resolves to a real upstream commit and nothing here is
queried against a feed: golden runs never touch the network (`--no-vuln` is
hard-wired into the harness). The live OSV demo with a real commit is
[`fixtures/vuln/known-vulnerable/`](../vuln/known-vulnerable/).

## The cases

| Case | Exercises | Exit |
|---|---|---|
| `gitmodules-pinned` | detached-HEAD and packed-refs commit resolution; one submodule declared but never initialized | 1 |
| `cmake-fetchcontent` | commit-pinned (High) and mutable-tag (Medium) FetchContent, plus a CPM `gh:` shorthand in a second file | 0 |
| `cmake-archive` | FetchContent source archives: `URL_HASH` => `checksum`+`download_url` purl qualifiers and a `hashes` block (High), an unhashed `URL` => `download_url` alone (Medium). The only case emitting a qualified purl, so it is what `scripts/validate_purls.py` checks that shape against | 0 |
| `conan-lock` | `conanfile.txt` declarations merging with the `conan.lock` conan itself resolved | 0 |
| `vcpkg-manifest` | a bare dependency, and a `version>=` floor superseded by an exact `overrides` pin | 0 |
| `vcpkg-ports-registry` | a `ports/<name>/vcpkg.json` port definition reports its own name+version as a component (High), in addition to its `dependencies` (Low/unversioned): the path-anchored fix, contrasted with `vcpkg-manifest`'s consumer-manifest case where the top-level name/version are never a dependency | 0 |
| `mixed-product` | The composition: one purl from two producers => one component after `merge_all`; `--product` => `metadata.component` | 0 |
| `npm-lockfile` | package-lock.json v3: root entry skipped; `dev: true` => `scope: "excluded"`; scoped package keeps its `%40scope` namespace | 0 |
| `lockfile-package-budget` | `--max-packages 2` overrides `[scan].max_packages = 1`; npm and Yarn each retain two of three entries, proving independent budgets; the deterministic partial SBOM is still written | 2 |
| `python-uv` | uv.lock: the virtual root project skipped; registry packages High | 0 |
| `python-poetry` | poetry.lock: `groups` lacking `main` => `scope: "excluded"` | 0 |
| `python-requirements` | both `requirements-*.txt` and `requirements_*.txt` are parsed: `==` pin High with versioned purl vs. range floor Low and version-less | 0 |
| `go-sum` | go.sum: `/go.mod` metadata lines collapse into their module; `v` prefix kept in the `pkg:golang` purl | 0 |
| `go-vendor-namespace` | Go modules come only from `go.sum`; matching source and license trees under `vendor/github.com/...`, `LICENSES/vendor/k8s.io/...`, and other trigger directories such as `thirdparty/github.com/...` must not add generic host placeholders | 0 |
| `cargo-lock` | Cargo.lock: the workspace's own package (no `source`) skipped; a registry checksum becomes the component's sha256, the first `hashes` block from a lockfile parser | 0 |
| `maven-pom` | pom.xml: literal and `${property}`-resolved versions; `<scope>test</scope>` => `scope: "excluded"`; the `dependencyManagement` pin must NOT appear. Also exercises the pom's own self-identity emission: its own coordinates are additionally emitted as a High-confidence self-identity component | 0 |
| `maven-unresolved-identity` | pom.xml: a `<groupId>` referencing an undefined property is kept (never dropped) with the raw `${...}` text as identity, downgraded to Low confidence; this warning is the case's exit 1. Also exercises the pom's own self-identity emission: its own (fully-resolved) coordinates are additionally emitted as a High-confidence self-identity component, adding no warning of its own | 1 |
| `maven-pom-license` | pom.xml: a pom's own `<licenses><license><name>` text is captured verbatim (no SPDX normalization) onto its self-identity component, contrasted with `maven-pom`'s case where no `<licenses>` block is present, same as vcpkg's `vcpkg-ports-registry` own-identity precedent but for a declared license rather than a bare name+version | 0 |
| `gradle-lockfile` | gradle.lockfile: `group:artifact:version` triplets; an all-`test*`-configurations entry => `scope: "excluded"`; the `empty=` line ignored | 0 |
| `nuget-lock` | packages.lock.json: the same package under two target frameworks merges into ONE component; the `Project` reference (first-party) skipped | 0 |
| `composer-lock` | composer.lock: `packages-dev` => `scope: "excluded"`; vendor as purl namespace; the `v`-prefixed version kept exactly as resolved | 0 |
| `composer-json-only` | composer.json fallback when no composer.lock exists: `require`/`require-dev` parsed at Medium confidence (declared ranges, never resolved), `require-dev` => `scope: "excluded"`; `php`/`ext-*` platform entries are skipped and counted, which is this case's exit 1; a composer.json under `vendor/` (an installed package's own) leaks nothing | 1 |
| `gemfile-lock` | Gemfile.lock: GEM specs emitted, 6-space dependency edges are not gems; a GIT spec carries `remote@revision` evidence; the PATH spec (first-party) skipped | 0 |
| `yarn-berry-lock` | Yarn Berry `yarn.lock`: identity comes from `resolution:`, never the entry key's range; a scoped package keeps its `%40scope` namespace; a `patch:` locator resolves to the `npm:` locator underneath it. The `workspace:` member (the product itself) is skipped SILENTLY like a rubygems PATH spec; the `link:` entry is also first-party but can point outside the declared workspace graph, so it is skipped with a counted warning; that count is the exit 1 | 1 |
| `yarn-classic-lock` | Yarn Classic (v1) `yarn.lock`: a second, non-YAML grammar behind the same filename, told apart by its banner; name from the first descriptor in the entry key, version from the quoted `version` line; the nested `dependencies` edge is an edge, never a component | 0 |
| `pnpm-lock-v9` | pnpm-lock.yaml v9: only `packages:` becomes components. `snapshots:` repeats those exact keys with the peer set each was resolved against appended and must contribute NOTHING (a leak would emit a version reading `2.1.4(left-pad@1.3.0)`); `importers:` is the workspace's own members and is silent too. The `tarball` entry resolves without an integrity, so it is skipped with a counted warning; that count is the exit 1 | 1 |
| `pnpm-lock-v6` | pnpm-lock.yaml v6: the older key spelling no corpus repo carries, so this is where it is tested: a leading `/` and a trailing `(left-pad@1.3.0)` peer suffix are both stripped before the name/version split. The per-package `dev:` flag v6 still writes is deliberately not read, so both generations describe the same tree identically | 0 |
| `cpp-vendored` | Y15: a vendored zlib copy whose header declares `ZLIB_VERSION` (Medium, recognized `Zlib` license) alongside an unrecognized vendored library with only a LICENSE/README (Low, folder-name identity) | 0 |
| `submodule-not-walked` | a submodule is ONE pinned component and its contents are never walked: the CMakeLists.txt, package-lock.json and vcpkg.json inside `third_party/libfoo` must leak nothing, while the superproject's own FetchContent dependency still reports | 0 |
| `submodule-contents-included` | the same tree under `--include-submodule-contents`: the deep walk everyone gets by default is off. Read as a pair with the case above; the difference between the two snapshots is what the flag buys | 0 |
| `repo-config` | `bomwerk.toml` alone drives the scan: `[scan] include` keeps only `app/`, `[scan] exclude` drops `app/playground/` inside it, `[product]` becomes `metadata.component`; the excluded npm lock and the outside-the-include `Cargo.lock` must leak nothing | 0 |
| `coverage-mixed` | `--coverage` alongside the SBOM, exercising all three match-coverage classes a real producer can emit today in one tree: a resolved Cargo.lock pair (`matched`), a bare vcpkg dependency (`unversioned-purl`), and an `overrides`-pinned vcpkg dependency (`unmapped-purl-type`); both `expected.cdx.json`'s `bomwerk:coverage:*`/`bomwerk:match-coverage` properties and `expected.coverage.json` are diffed | 0 |
| `github-actions-clean` | `.github/workflows/*.yml` `uses:` references: a commit-SHA-pinned step (High) and a tag-pinned step (Medium), both `pkg:github/<owner>/<repo>@<ref>` | 0 |
| `github-actions-unresolved-expression` | a tag-pinned `uses:` alongside one whose ref is an unresolved `${{ ... }}` expression: degrades to Low confidence with no `@` segment in the purl rather than leaking `${{` into it (stricter than CMake's own unresolved-`${var}` handling); the warning is this case's exit 1 | 1 |
| `all-cpes-npm` | `--all-cpes`: OSV-native npm components, which the default CPE scope leaves untouched, gain a wildcard-vendor CPE marked `bomwerk:cpe-provenance=wildcard-vendor-guess`. `npm-lockfile` is the untouched baseline | 0 |
| `nuget-csproj` | `.csproj` `PackageReference` elements with no `packages.lock.json` present => Medium-confidence `pkg:nuget` components | 0 |
| `nuget-csproj-cpm` | Central Package Management: a versionless `.csproj` `PackageReference` resolved from `Directory.Packages.props` at Medium confidence, nearest file per directory | 0 |
| `nuget-packages-config` | legacy `packages.config` `<package>` elements => Medium-confidence `pkg:nuget` components | 0 |
| `spdx23-mixed` | the SPDX 2.3 (flat JSON) writer over the `mixed-product` tree: `fmt` merged to one package from two producers; `--product` becomes the document name and every package gets a `DESCRIBES` relationship | 0 |
| `spdx30-mixed` | the SPDX 3.0.1 (JSON-LD) writer over the `mixed-product` tree: `fmt` vendored as a submodule AND declared via FetchContent at the same commit => one `software_Package`; `--product`/`--product-version` name the `SpdxDocument` | 0 |
| `nightmare-corpus` | a miniature of every static shape the public `bomwerk/nightmare` results table depends on: three vendored identity tiers (zlib and freertos by version header at Medium, uthash and stb by folder name at Low), a `conanfile.txt` declaring a DIFFERENT zlib (1.3.1) than the vendored copy (1.2.11), stb's dual MIT-or-Unlicense LICENSE flattened to `MIT`, uthash's unrecognized LICENSE left unset, freertos's CPE carrying a `v11.1.0` version NVD will not match (a known gap, pinned so its fix shows up as a diff), two prebuilt-library roots identified from headers alone (sqlite3@3.41.2 at Medium; cjson-prebuilt by folder name with no version, because cJSON.h only has numeric version macros), and a `FetchContent_Declare` of tinyxml2 pinned to a synthetic commit. The openssl submodule is declared but never checked out: exit 1 | 1 |
| `nightmare-submodule-pinned` | the same tree with the openssl submodule's HEAD checked out => a versioned `pkg:github/openssl/openssl` and a clean run. Read as a pair with the case above: the diff between the two snapshots is the shallow-clone row of the public README | 0 |

`gitmodules-pinned`, `nightmare-corpus`, `yarn-berry-lock`, `pnpm-lock-v9`,
`composer-json-only`, `maven-unresolved-identity`, `github-actions-unresolved-expression`,
and `lockfile-package-budget`
are the cases that expect a non-zero exit, and that is the point. The first
seven cover degraded runs: an uninitialized submodule (twice), a skipped first-party
workspace member, a dependency resolved from a URL rather than the registry, a
composer.json's skipped platform pseudo-requirements, a pom.xml `<groupId>`
that could not be resolved from its properties, and a GitHub Actions ref that
is an unresolved `${{ ... }}` expression, so they pin exit 1. The
package-budget case pins exit 2: known lockfile truncation is incomplete even
though the deterministic partial SBOM is written successfully.

## What the byte-diff can't see

Confidence tiers (`High`/`Medium`/`Low`) are computed by every producer, but
`output::write_cyclonedx`'s `component_to_json` never serializes
`Component::evidence` or a confidence field anywhere in the document: only
`type`, `bom-ref`, `name`, `version`, `purl`, `supplier`, `hashes`, `licenses`.
The cases below run the real confidence-assignment code (a wrong High/Medium/Low
would still be a bug), but the tier a dependency lands on is invisible to the
snapshot: inverting which of a commit-pinned vs. a mutable-tag dependency rates
High would leave every byte of `expected.cdx.json` unchanged. Where a case
description names a tier, read it as *this is what the fixture is for*, not
*this is what the diff verifies*: that verification still lives in each
producer's own unit test (`test_cmake_deps.cpp`, `test_conan.cpp`,
`test_vcpkg.cpp`).

`submodule-not-walked` is the exception that proves the rule above: what it
verifies is an **absence**, and an absence is exactly what a byte-diff sees
best. It is also the only pair of cases meant to be read together: on its own
each looks unremarkable, and the point is the difference between them.

`coverage-mixed` has its own version of the caveat above: the match-coverage
taxonomy has a fourth class, `no-identifier` (no purl at all), but no producer
in this codebase ever leaves `Component::purl` empty: every one of them falls
back to at least a bare `pkg:generic/<name>` when it has nothing better (see
`match_coverage.hpp`'s doc comment). `no-identifier` is therefore unreachable
through any real scan today and cannot appear in a golden fixture; it is
covered where it belongs: `test_match_coverage.cpp`, `test_coverage_report.cpp`,
`test_cyclonedx.cpp` and `test_html_report.cpp` construct it directly.

The same caveat applies, more narrowly, to `gitmodules-pinned` and
`mixed-product`'s submodule commit resolution: their `_git/` plumbing is a plain
directory (`HEAD` [+ `packed-refs`]), which becomes a `.git` **directory** after
the harness's rename: the ordinary-worktree branch in `submodules.cpp`. A real,
initialized git submodule's `.git` is instead a **file** containing a `gitdir:`
pointer, resolved by a separate branch (with its own path-escape containment
check) that these fixtures don't reach. That branch, containment check
included, already has direct C++ unit coverage in `test_submodules.cpp`: it
just isn't exercised at this end-to-end, snapshot-diffed layer.

## Anatomy of a case

```text
<case>/
  case.json              {"description": …, "args": […], "expect_exit": 0,
                          optional "coverage": true}
  expected.cdx.json      the snapshot; bomwerk's own version held as @BOMWERK_VERSION@
  expected.coverage.json present only when case.json sets "coverage": true;
                         the `--coverage` snapshot, diffed the same way
  tree/                  the repo that gets scanned
```

Two conventions are worth knowing before you add one:

**`_git/` is git plumbing.** Git refuses to track any path containing a `.git`
component, so a fixture that exercises commit resolution cannot be committed with
real plumbing in place. Cases carry `_git/`, and the harness renames it to `.git`
in a throwaway copy before scanning. The plumbing is synthesized rather than
copied from a real repository, because the submodules producer reads exactly three things
and never runs git (rule 9): `HEAD`, `refs/…`, `packed-refs`. A `.git` holding
one `HEAD` file is a complete fixture; a real `git init` would add hundreds of
bytes of objects and config that nothing reads.

**`@BOMWERK_VERSION@` is not a typo.** It stands in for bomwerk's own version in
`metadata.tools`: the one field in the document that is neither pinned by
`SOURCE_DATE_EPOCH` nor derived from the scanned tree. Snapshotting it literally
would rewrite every file here on an unrelated version bump, and a diff nobody
reads is a test nobody has. The real version stays covered by `test_cyclonedx`
and by schema validation. Everything else is compared byte for byte, including
key order: `scripts/run_golden_case.py` never re-serializes the scanner's output,
because a JSON round-trip would mask exactly the canonical-form regressions rule 3
exists to prevent.

## Adding a case

1. `mkdir fixtures/golden/<case>/tree` and write the repo. Keep it small enough
   that its whole SBOM fits on a screen; name any git plumbing `_git/`.
2. Write `case.json`. `args` are appended to `scan <tree> -o <out> --no-vuln`.
   Add `"coverage": true` to also exercise and snapshot `--coverage`.
3. Bless the snapshot, then **read it before committing**:
   ```bash
   python3 scripts/run_golden_case.py ./build/bomwerk fixtures/golden/<case> --update
   ```
4. Rebuild once so CMake re-globs (`CONFIGURE_DEPENDS`), then `ctest -R golden_`.

Step 3's second half is the whole discipline. A snapshot nobody read locks in
whatever the code did on the day it was blessed, bug included, and every later
run then defends that bug. Re-blessing after a change is the same command,
and the same rule applies: read the diff, and if you cannot explain a line of
it, that line is the bug.

If `--update` refuses with *"the tool version occurs N times"*, a component in
your fixture declares the same version as bomwerk itself, which would make the
token ambiguous. Give the fixture component a different version.
