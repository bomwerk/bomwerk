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

### Changed
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
