# Contributing to bomwerk Community

bomwerk is an on-prem CLI (C++20) that produces build-accurate SBOMs, matches
them against vulnerability feeds, and generates EU Cyber Resilience Act
evidence. This repository is the Apache-2.0 Community edition, and it is the
whole scanner: `scan`, `observe`, `trim` and `binscan`. Paid surfaces are built
from a separate private extension and are described in
[the open-core build and release boundary](open-core-boundary.md).

Contributions are accepted under the Apache License 2.0. By opening a pull
request you license your contribution under that same licence, as its section 5
states; there is no separate CLA.

## Build, test, format

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DBOMWERK_PRO=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./scripts/check-format.sh clang-format
```

Dependencies come **only** from `vcpkg.json`, never brew, apt or
`FetchContent`. bomwerk must be able to scan itself, so every dependency has to
appear in our own SBOM.

## Hard rules

These are not style preferences. A change that breaks one of them will not be
merged, however useful it is otherwise.

1. **Parsers and producers never throw across module boundaries and never crash
   on hostile input.** Return `Result<T>` with warnings. Partial output beats no
   output.
2. **Exit codes are a contract:** `0` clean, `1` completed with warnings, `2`
   incomplete. Lockfile budget exhaustion writes partial artifacts and then
   exits 2. Exit codes come from `core/exit_codes.hpp`; never write a literal
   0/1/2.
3. **Deterministic output.** Sort every collection, emit canonical JSON with
   sorted keys, derive ids as UUIDv5 of the purl, and honour
   `SOURCE_DATE_EPOCH`. Two runs must be byte-identical.
4. **Dependencies only via `vcpkg.json`.**
5. **Do not weaken warning flags, change exit codes, or "simplify" determinism
   code** without an explicit maintainer decision.
6. **Ask before touching** `src/observe/` or anything cryptographic or related
   to signing and release workflows.
7. **Every function of consequence gets a test in the same pull request.**
   Definition of Done = code + test + documentation paragraph + changelog line.
8. **A TODO says what is missing and why**, not who will do it:
   `// TODO: no WarningCode distinguishes a cache read from a write failure.`
9. **Producers never shell out.** No `git`, no `system()`, no `popen()`. A
   subprocess honours the scanned repository's own configuration, which is an
   RCE vector on untrusted code, and it depends on a tool that may be absent or
   a different version. Read git metadata as files (refs, not
   `git submodule status`).

## Module dependency law

Everything may include `src/core`. Producers (`parsers`, `heuristics`,
`observe`, `binscan`) never include each other, nor `vuln`, `output` or `sbom`.
`cli` includes everything.

Producer signature:

```cpp
Result<std::vector<Component>> parse(const fs::path& root);
```

`binscan` (the ELF/`ar` reader) is a producer like the others and links only
`bomwerk_core`. It is handed **paths**, never trace records, so it cannot
include `observe` even by accident: `observe::collect_build_artifacts` turns a
trace into those paths and `cli` hands them over. It deliberately carries no
third-party binary-format library: bomwerk scans itself, so every dependency
is also a component in our own SBOM, and `byte_cursor.hpp` bounds-checks the
whole surface in one reviewable place.

`sbom` (the SBOM readers, the inverse of `output`'s writers) includes only
`core`, the same as `output` and `vuln`.

## Style

C++20 with `-Wall -Wextra -Wpedantic -Werror`. `snake_case` functions and
variables, `PascalCase` types, `kConstants`, `#pragma once`,
`std::filesystem`, no raw `new`/`delete`, spdlog levels. User-facing strings
are kept together in one table per command (a future `--lang de|es`).

Brace style is Allman, the opening brace on its own line, everywhere,
including namespaces. `.clang-format` is law; never hand-format braces.
Control statements always use explicit braces, which `InsertBraces: true`
enforces.

Namespaces are one compound declaration, never nested blocks, with no
indentation inside:

```cpp
namespace bomwerk::core::x
{
...
}  // namespace bomwerk::core::x
```

Run `clang-format -i` on every file you create or edit. Three formatting
behaviours `scripts/check-format.sh` checks and hand-written code often gets
wrong: free functions are never single-line
(`AllowShortFunctionsOnASingleLine: Inline` means one-liners exist only inside
classes); trailing `///<` comments inside one declaration block are
column-aligned to each other; arguments wrap by bin-packing at 100 columns.

### Naming

No short or cryptic names. Write `component_index`, not `idx`;
`buffer_iterator`, not `it`. Variables and functions are fully descriptive and
self-documenting.

## Code shape

- Boolean functions are positively named and return positive conditions. Prefer
  `is_valid()` over `is_invalid()`, and `return has_value;` over inverted
  boolean logic.
- Prefer early returns to reduce nesting, while preserving the `Result<T>` and
  exit-code contracts.
- No magic numbers: use named `constexpr` constants close to their use. Put
  `inline constexpr` constants in headers only when the value is shared or
  public. Do not introduce a generic `Constants` namespace.
- Prefer cohesive classes for stateful, multi-step or collaborator-heavy
  behaviour. Keep simple pure helpers and the required public producer
  entrypoints as free functions.
- Anonymous namespaces are allowed only in `.cpp` files, never in headers. When
  a named namespace is immediately followed by an anonymous one, leave no blank
  line between them.
- Built-in manifest defaults are scan candidates, not proof of an active
  dependency. Keep the defaults conservative: a stale file such as an old
  `package-lock.json` may be reported until parser or evidence logic proves
  whether it is active.

## C++20 and the toolchain caveat

`std::jthread` (long-running loops), `std::span` (parsing raw binary buffers
without copies), concepts and `<filesystem>` are fine today.
`std::ranges` algorithms and `std::views` are the target but are **not usable
yet**: AppleClang 14, the current local toolchain, ships an incomplete C++20
library. Use classic `<algorithm>` (`std::sort(begin, end)`, index loops) until
the toolchain moves to AppleClang 15 / Xcode 15, and switch then.

Error handling is strictly `Result<T>` (the `std::expected` equivalent) per hard
rule 1. Never wrap core logic in `try`/`catch` across a module boundary.

## Logging

Use spdlog, and wrap heavy log arguments in compile-time checks or lazy
evaluation so hot paths (`bomwerk observe`) pay nothing.

| Level | Means |
| --- | --- |
| `info` | user progress |
| `warn` | degraded state, for example a partial SBOM |
| `error` | the exit-2 path: crashes and critical failures |
| `debug` / `trace` | development only, compiled out in release via `SPDLOG_ACTIVE_LEVEL` |

**Logs go to stderr. Scan results (SBOM files, reports, stdout listings) are
product output, not logs.** Never mix the two.

## Tests

Unit tests live in `tests/unit`, Python integration harnesses in
`tests/python`, and fixture-driven golden cases in `fixtures/` with their
runners in `scripts/`. Name and comment tests in Gherkin style: `Given… When…
Then…`.

To exercise a `kUnreadableFile` path in a producer test, do **not** create a
directory where a regular file is expected: `core::build_file_index` only
indexes `is_regular_file` entries, so a same-named directory is invisible to it
and the read path is never reached, silently defeating the test. Hand-construct
a `core::FileIndex` naming a path that does not exist on disk and call the
producer's `FileIndex`-taking `parse` overload directly (see
`tests/unit/test_manifest_walk.cpp` and `tests/unit/test_pub.cpp`), or use a
real permission-denied file when the producer has no such overload.

## Documentation

Public headers use clean Markdown inside `///` comments; avoid heavy Doxygen
structural tags unless they are required. The API reference is Doxygen
(opt-in via `-DBOMWERK_DOCS=ON`, target `docs`). Product documentation lives in
`docs/`; do not create documentation files elsewhere in the tree.

## Pull requests

One task, one branch, one pull request. Reference the issue it closes, add the
changelog line, and make sure `ctest` and `check-format.sh` pass locally before
asking for review.

Two things never belong in a pull request to this repository: paid extension
source (see [the boundary](open-core-boundary.md)) and files that configure a
development assistant. `scripts/audit_public_history.py` checks the second one
mechanically over the whole history.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. See
[SECURITY.md](SECURITY.md) for how to report one, what is in scope, and what
happens next.
