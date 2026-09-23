# Real-world vcpkg manifests: provenance

Recipe for vendoring (human step; pin the commit you fetched from). Until
fetched, `test_vcpkg.cpp` exercises the parser with in-test `TempTree` manifests
and the hand-written hostile corpus below.

| Target file | Upstream | Pinned commit |
|---|---|---|
| `overrides.vcpkg.json` | any project pinning versions via `overrides` + `builtin-baseline` | (fill on fetch) |
| `features.vcpkg.json` | a manifest using object dependencies with `features`/`platform` | (fill on fetch) |

Hostile corpus: see `hostile/README.md` (hand-written, no upstream).
