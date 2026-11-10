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
| Pinned, forgotten submodule | openssl 3.0.7 at `third_party/openssl` | shallow clone (`.git` present, submodule not checked out): `pkg:github/openssl/openssl@<pin>` read from `.git/index`, informational `BW-GIT-006`, exit 0; initialized: versioned, exit 0; exported tree with no `.git` at all: no version, `BW-GIT-004`, exit 1 |
| Vendor fork | FreeRTOS V11.1.0 with one modified `list.c` | `pkg:generic/freertos@V11.1.0`. A plain scan cannot see the fork; with `--fingerprint-index` the component also carries a count of how many of that directory's files are byte-identical to the pinned release, and `list.c` is not among them. See below |
| Unused library | stb, referenced by no target in either build | `pkg:generic/stb`, Low; `trim`: UNUSED in both configurations |
| `#ifdef` variants | presets `config-a` / `config-b` | plain `scan` gives the same answer for both, and `observe` + `trim` give different used-sets |
| Prebuilt static library, quoted version header | SQLite 3.41.2 as `sqlite3.h` + `libsqlite3.a` under `third_party/sqlite-prebuilt`, linked in `config-a` | `pkg:generic/sqlite3@3.41.2`, Medium, no license (public-domain blessing); `trim`: used (1 link input) in `config-a`, UNUSED in `config-b` |
| Prebuilt static library, numeric version macros | cJSON 1.7.15 as `cJSON.h` + `libcjson.a` under `third_party/cjson-prebuilt`, linked in `config-a` | `pkg:generic/cjson@1.7.15`, Medium, version assembled from `CJSON_VERSION_MAJOR`, `_MINOR` and `_PATCH`; `trim`: used (1 link input) in `config-a` |
| CMake `FetchContent` | tinyxml2 9.0.0 pinned by commit, fetched only with `-DNIGHTMARE_ENABLE_XML=ON` | `pkg:github/leethomason/tinyxml2@<commit>` |

## Which bomwerk tests lock which claim

The public repo's results table is only as good as bomwerk's answer on it, so every
static shape and both used-sets are pinned in this repo's `ctest`, and a regression goes
red here before the public README goes stale:

- `golden_nightmare-corpus` / `golden_nightmare-submodule-pinned` pin the scan: every
  identity tier, the two zlibs, the licenses and the CPEs, as the exported-tree vs
  initialized-submodule pair. The trees are miniatures, not copies.
  `golden_nightmare-shallow-clone` adds the default CI clone between them: `.git`
  present, openssl never checked out, its pin read from a real `.git/index`. Its
  snapshot is byte-identical to `nightmare-submodule-pinned`'s.
- `trim_nightmare_config_a` / `trim_nightmare_config_b` pin the central claim: **one
  source tree, two different used-sets.** The two trees are byte-identical, and the
  traces are the real `bomwerk observe` traces of the corpus, minimized.
- `test_vendored_cpp` covers the `freertos` version-header signature
  (`include/task.h` -> `tskKERNEL_VERSION_NUMBER`) that this corpus added, plus the
  negative case where an unrelated `task.h` must not claim FreeRTOS.
- `golden_nightmare-corpus-fingerprint` pins what `--fingerprint-index` adds, on a
  miniature of `cjson-prebuilt` whose `cJSON.h` has its version macros removed on
  purpose, so no header can version it and only the content match can. Its corpus
  index is built from the fixture's own bytes, so the wiring is proved without
  upstream content entering this repository.

The real build, the network-backed CVE lookups and the rival-tool numbers cannot be
hermetic. They run in the public repo's own CI.

Neither can the fingerprint corpus: a real index is built from pinned upstream
releases, which needs the network, and checking it against this corpus needs a
nightmare checkout. `scripts/run_fingerprint_corpus.py` is that check, run by hand or
on a schedule. It hashes the vendored files itself and looks the digests up in the
index, so it reports whether the CORPUS knows those bytes with no bomwerk binary in
the picture: when a scan shows no fingerprint evidence, that is what separates a gap
in the corpus from a bug in the matcher. Its expectations come from nightmare's own
`third_party/pins.json`, including the two that matter most: `list.c` must NOT match,
because pins.json records it as modified, and `include/FreeRTOSConfig.h` must match
even though upstream ships it from `examples/template_configuration/`.

## Known gaps the corpus makes visible

Published on purpose. A torture test whose author scores 5/5 is a brochure.

- **Forks are reported as a count, not as a verdict.** A plain scan reports the version
  a header declares and has nothing to compare against upstream, so the FreeRTOS fork
  passes as pristine `V11.1.0`, and no tool in the comparison detects it. With
  `scan --fingerprint-index` and a corpus covering FreeRTOS, bomwerk has the file
  hashes, and the component carries evidence naming how many of that directory's files
  are byte-identical to the pinned release. `list.c` is not one of them. With the tier-0
  manifest in `scripts/fingerprint_corpus.json` the count reads "9 of 14 hashed files
  match freertos V11.1.0": the exact number depends on which upstream files that
  manifest indexes, so read the ratio, not the integer. `include/FreeRTOSConfig.h` is
  among the nine even though upstream ships it from
  `examples/template_configuration/`, because the match is on content and ignores paths
  entirely.

  That is the ingredient, not the conclusion. Nothing yet says "this library is
  modified", and a gap that needs a flag and a corpus you build yourself is not a closed
  gap.
- **A leading `v` breaks CPE matching.** `V11.1.0` synthesizes
  `cpe:2.3:a:*:freertos:v11.1.0`, while NVD files `11.1.0`. The same applies to `pkg:golang`
  under `--all-cpes`. The golden snapshot pins the current behavior, so the fix will
  show up as an intended diff.
- **Dual licenses are flattened.** stb is *MIT **or** Unlicense*; the first-match
  license recognizer reports `MIT` only.
- **A version split across several macros is read only for listed libraries.** cJSON
  writes its version as `CJSON_VERSION_MAJOR/MINOR/PATCH`, three integers on three
  lines, and bomwerk assembles `1.7.15` from them, all or nothing: a missing,
  duplicated, quoted or non-integer part gives no version at all, never a partial one.
  This is a table of named libraries, not a pattern, because a MAJOR/MINOR pair is not
  always the release: libsodium's `SODIUM_LIBRARY_VERSION_MAJOR` is its ABI version.
  A library whose header splits its version and is not in the table still falls back
  to its folder name. A single bare integer never qualifies either: stb's
  `STBI_VERSION 1` is an API revision, not a release, so stb stays unversioned, which
  is also what the answer key says.

  A bare or split version macro names the directory only when the folder carries the
  library's name (`third_party/uthash`, `third_party/cjson-prebuilt`), so a library
  that bundles someone else's header, such as libktx bundling `uthash.h`, keeps its
  own name. The quoted-string rows (zlib, lz4, zstd and the rest) do not have this
  check yet, so a library bundling a copy of `zlib.h` can still be reported as zlib.
  Only a `#define` that starts its line counts; a commented-out one never does.
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
