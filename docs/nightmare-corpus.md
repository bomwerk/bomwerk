# The nightmare corpus

[`bomwerk/nightmare`](https://github.com/bomwerk/nightmare) is a small, public,
deliberately horrible C project: an SBOM torture test that anyone can clone and
point any scanner at. It is **not** part of bomwerk and contains no bomwerk
source. It exists so that "bomwerk finds what other tools miss" is something a
skeptic checks for themselves, rather than a claim they take from us.

It reproduces seven patterns real C/C++ firmware exhibits, using genuine upstream code
pinned by commit. `tools/verify_vendored.sh` in that repo proves every vendored byte
matches upstream:

| Ingredient | In the corpus | What bomwerk reports |
|---|---|---|
| Vendored library with a CVE | zlib 1.2.11 under `third_party/zlib`, compiled in `config-a` | `pkg:generic/zlib@1.2.11`, Medium. `conanfile.txt` declares zlib **1.3.1**, so both are reported, and only `trim` can tell which one ships |
| Pinned, forgotten submodule | openssl 3.0.7 at `third_party/openssl` | shallow clone: `pkg:github/openssl/openssl` with no version, `BW-GIT-004`, exit 1; initialized: versioned, exit 0 |
| Vendor fork | FreeRTOS V11.1.0 with one modified `list.c` | `pkg:generic/freertos@V11.1.0`: **the fork is not detected**, see below |
| Unused library | stb, referenced by no target in either build | `pkg:generic/stb`, Low; `trim`: UNUSED in both configurations |
| `#ifdef` variants | presets `config-a` / `config-b` | plain `scan` gives the same answer for both, and `observe` + `trim` give different used-sets |
| Prebuilt static library, quoted version header | SQLite 3.41.2 as `sqlite3.h` + `libsqlite3.a` under `third_party/sqlite-prebuilt`, linked in `config-a` | `pkg:generic/sqlite3@3.41.2`, Medium, no license (public-domain blessing); `trim`: used (1 link input) in `config-a`, UNUSED in `config-b` |
| Prebuilt static library, numeric version macros | cJSON 1.7.15 as `cJSON.h` + `libcjson.a` under `third_party/cjson-prebuilt`, linked in `config-a` | `pkg:generic/cjson-prebuilt`, Low, **no version, folder-derived name** (a scored miss); `trim`: used (1 link input) in `config-a` |
| CMake `FetchContent` | tinyxml2 9.0.0 pinned by commit, fetched only with `-DNIGHTMARE_ENABLE_XML=ON` | `pkg:github/leethomason/tinyxml2@<commit>` |

## Which bomwerk tests lock which claim

The public repo's results table is only as good as bomwerk's answer on it, so every
static shape and both used-sets are pinned in this repo's `ctest`, and a regression goes
red here before the public README goes stale:

- `golden_nightmare-corpus` / `golden_nightmare-submodule-pinned` pin the scan: every
  identity tier, the two zlibs, the licenses and the CPEs, as the shallow-clone vs
  initialized-submodule pair. The trees are miniatures, not copies.
- `trim_nightmare_config_a` / `trim_nightmare_config_b` pin the central claim: **one
  source tree, two different used-sets.** The two trees are byte-identical, and the
  traces are the real `bomwerk observe` traces of the corpus, minimized.
- `test_vendored_cpp` covers the `freertos` version-header signature
  (`include/task.h` -> `tskKERNEL_VERSION_NUMBER`) that this corpus added, plus the
  negative case where an unrelated `task.h` must not claim FreeRTOS.

The real build, the network-backed CVE lookups and the rival-tool numbers cannot be
hermetic. They run in the public repo's own CI.

## Known gaps the corpus makes visible

Published on purpose. A torture test whose author scores 5/5 is a brochure.

- **Forks are invisible.** The heuristic reports the version a header declares; it has
  no file hashes to compare against upstream. No tool in the comparison detects the
  FreeRTOS fork, bomwerk included.
- **A leading `v` breaks CPE matching.** `V11.1.0` synthesizes
  `cpe:2.3:a:*:freertos:v11.1.0`, while NVD files `11.1.0`. The same applies to `pkg:golang`
  under `--all-cpes`. The golden snapshot pins the current behavior, so the fix will
  show up as an intended diff.
- **Dual licenses are flattened.** stb is *MIT **or** Unlicense*; the first-match
  license recognizer reports `MIT` only.
- **Numeric version macros are not read.** cJSON writes its version only as
  `CJSON_VERSION_MAJOR/MINOR/PATCH`; the signature table matches quoted strings only,
  so identity falls back to the folder name, suffix included (`cjson-prebuilt`).
- **License text without a known name is not recognized.** cJSON's MIT text never says
  "MIT License", and SQLite's public-domain blessing is not a license name; both come
  back with no license.
- **No version is read from a binary.** Both prebuilt archives are identified from their
  headers alone; the `.a` contributes only link evidence.

## Rules for the public repo

- **It configures no scanner.** No `bomwerk.toml`, no `syft.yaml`, no `.cdxgenrc`. A
  corpus that tunes one tool and not its rivals produces a worthless table.
- **Scan an exported tree, never the working tree.** Scanners do not read `.gitignore`,
  so `build/`, `.bomwerk/shims` or a local cache would pollute every tool's result.
  `tools/export_tree.sh` gives the tree a stranger's `git clone` would.
