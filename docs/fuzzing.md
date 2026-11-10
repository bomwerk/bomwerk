# Fuzzing

Bomwerk reads files it does not control: lockfiles and manifests, CI workflows,
`.gitmodules` and the superproject's `.git/index`, ELF binaries and `ar`
archives, CycloneDX documents, build traces, `bomwerk.toml`, and OSV, NVD and
package registry responses. Hard rule 1 in
[CONTRIBUTING](CONTRIBUTING.md) says hostile input degrades to warnings and never
crashes. Every one of those parsers has a [libFuzzer](https://llvm.org/docs/LibFuzzer.html)
harness that checks the rule continuously, alongside the hand-written hostile
fixtures.

## What runs where

- **Every build.** Each harness is also built without libFuzzer and registered
  as the ctest `<target>_seeds`. It replays the target's seeds, its parser's
  hostile fixtures and every input that ever crashed it, once, under the build's
  sanitizers. A plain `ctest` therefore compiles all harnesses and keeps every
  fixed crash fixed.
- **Every pull request.** The `fuzz-smoke` job in `.github/workflows/ci.yml`
  fuzzes all targets for ten minutes of wall clock on four cores, starting from
  the corpus the nightly run saved.
- **Every night.** `.github/workflows/fuzz-nightly.yml` fuzzes for two hours
  in four parallel shards, minimizes each shard's corpus and saves it for the
  next night. The goal is a night with all four shards green.

Any crash, leak, timeout (one input taking over 10 s) or out-of-memory input
(over 2 GiB) fails the job; the input is uploaded as a workflow artifact.

## The pieces

| Path | Role |
|---|---|
| `tests/fuzz/fuzz_<parser>.cpp` | One harness per parser. `LLVMFuzzerTestOneInput` hands the bytes to the parser's in-memory entry point (`parse_bytes`, `read_elf_bytes`, ...) and aborts on a broken invariant. |
| `tests/fuzz/fuzz_support.{hpp,cpp}` | Shared checks: every purl a producer emits parses back; sorted, deduplicated lists stay so. |
| `tests/fuzz/replay_main.cpp` | The `main` a harness gets without libFuzzer: the `<target>_seeds` ctest. |
| `tests/fuzz/write_binary_seeds.cpp` | Generates the ELF and `ar` seeds, which are never committed. |
| `scripts/fuzz_targets.json` | The one list of targets: source, file-name variant, libraries, seed paths, dictionary. CMake builds from it and `scripts/run_fuzz.py` runs from it. |
| `scripts/run_fuzz.py` | Seeds corpora, runs campaigns, replays and merges; exits 1 on any finding. |
| `fixtures/fuzz/seeds/`, `fixtures/fuzz/dicts/` | Hand-written seeds no other fixture provides, and libFuzzer dictionaries ([README](../fixtures/fuzz/README.md)). |
| `fixtures/<parser>/hostile/` | Known-bad inputs: regression tests, and seeds for the same parser. |

A parser that reads several formats gets one target per format, built from the
same source with a different `BOMWERK_FUZZ_VARIANT` (`fuzz_conan_txt`,
`fuzz_conan_lock`, ...). A crash input is then a plain file of that format.

## Running it locally

libFuzzer ships only with LLVM Clang, so the fuzz build is separate from the
normal one. On Ubuntu:

```sh
sudo apt-get install -y clang-18 libclang-rt-18-dev
cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBOMWERK_PRO=OFF \
      -DBOMWERK_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++-18
cmake --build build-fuzz --target fuzzers --parallel
```

Configuring with `BOMWERK_FUZZ=ON` and any other compiler stops with an error.
Then, from the repository root:

```sh
python3 scripts/run_fuzz.py --build-dir build-fuzz --budget-seconds 600 --jobs 4
python3 scripts/run_fuzz.py --build-dir build-fuzz --targets 'fuzz_conan_*' --budget-seconds 300
python3 scripts/run_fuzz.py --build-dir build-fuzz --replay
python3 scripts/run_fuzz.py --build-dir build-fuzz --merge
```

The first is the pull-request smoke run. The others fuzz a subset, re-run every
corpus input once, and minimize the corpora. Corpora live in
`build-fuzz/fuzz-corpus/<target>/` and findings in
`build-fuzz/fuzz-artifacts/<target>/`.

To run one harness by hand, give it a corpus directory under the build tree,
never a fixtures directory: libFuzzer writes every new input it finds into the
first directory it is given.

```sh
mkdir -p build-fuzz/manual-corpus/fuzz_cargo
./build-fuzz/fuzz_cargo -max_total_time=60 -dict=fixtures/fuzz/dicts/toml.dict \
    build-fuzz/manual-corpus/fuzz_cargo fixtures/golden/cargo-lock/tree
```

## When it finds something

1. Reproduce it: run the harness with the finding as its only argument, for
   example `./build-fuzz/fuzz_cargo build-fuzz/fuzz-artifacts/fuzz_cargo/crash-...`.
   The sanitizer report names the line.
2. Fix the parser. A timeout is a real bug (usually a quadratic loop), never a
   reason to raise the 10 s limit. An aborted invariant is triaged like a crash;
   if the input really is legitimate, narrow that one check, never remove it.
3. Keep the input as a regression. For a text format, copy it unchanged to
   `fixtures/<parser>/hostile/<what-it-probes>.<file name>` (the suffix names
   the format, for example `separator-only-name.uv.lock`) and add a row to that
   directory's README. The `<target>_seeds` ctest and the producer contract test
   (`tests/unit/test_producer_contract.cpp`) replay it from then on. For an ELF
   or `ar` finding, add the shape as a builder case in `test_elf_read.cpp` or
   `test_archive_read.cpp` instead, since binary blobs are not committed. Also
   add a Given/When/Then test to the parser's own `test_<parser>.cpp` that states
   what the input should now produce.
4. Add a `### Fixed` line to the changelog that says what input used to
   misbehave and how it behaves now.

## Adding a parser

1. Give it an in-memory entry point that runs the same per-file code as the
   path version (for a manifest producer: `parse_bytes`, through
   `core::for_manifest_bytes`).
2. Write `tests/fuzz/fuzz_<parser>.cpp` and list one target per format in
   `scripts/fuzz_targets.json`, with seed paths and a dictionary. The
   `fuzz_targets_manifest` ctest fails until source, seeds and dictionary agree.
3. For a manifest producer, add it to `tests/unit/test_parse_bytes.cpp` and
   `tests/unit/test_producer_contract.cpp`.
