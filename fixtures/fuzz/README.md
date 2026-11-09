# Fuzzing inputs

Inputs for the libFuzzer harnesses in `tests/fuzz/` (T40). `scripts/fuzz_targets.json`
says which of these, and which other fixtures, seed each target.

- `seeds/<name>/`: hand-written seeds for inputs no other fixture provides (purls,
  conan references, CVSS vectors, OSV/NVD/registry responses, conan graph output).
  They are synthetic, written to the shapes the unit tests use, and carry no real
  advisory data beyond public identifiers.
- `dicts/*.dict`: libFuzzer dictionaries, one per input syntax. Each line is one
  token the mutator splices in, in libFuzzer's `"token"` form.

ELF and `ar` seeds are not here: `tests/fuzz/write_binary_seeds.cpp` generates them,
because `fixtures/binscan/SOURCES.md` keeps binary blobs out of the repository.

A crash input found by fuzzing is not added here. It goes into the parser's own
`fixtures/<parser>/hostile/` directory as a regression; see `docs/fuzzing.md`.
