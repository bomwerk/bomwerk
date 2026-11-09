# Hostile CMake fixtures

Hand-written adversarial inputs for the FetchContent/CPM parser
(`parsers/cpp/cmake_deps` + `cmake_scanner`). The producer must **warn and
continue** on every one: never crash, never return exit-2. These double as the
libFuzzer seed corpus (`fuzz_cmake_deps`, see `docs/fuzzing.md`).

| File | Probes |
|------|--------|
| `unbalanced-parens.cmake` | command `(` never closed -> scanner stops at EOF, warns |
| `unterminated-quote.cmake` | quoted argument never closed |
| `unterminated-bracket-arg.cmake` | `[==[ … ]==]` bracket argument never closed |
| `unterminated-bracket-comment.cmake` | `#[[ … ]]` bracket comment never closed |
| `hash-in-url.cmake` | `#` inside a URL / CPM shorthand ref must NOT be treated as a comment |
| `deep-nesting.cmake` | nested generator expressions + deep `(( … ))` (paren-depth bound) |
| `url-hash-binary-algorithm.cmake` | `URL_HASH` whose algorithm holds a NUL byte: the digest is valid hex, but the algorithm is written into the purl `checksum` qualifier verbatim, so the checksum is ignored with a warning (found by fuzzing, T40) |
| `pervasive-vars.cmake` | `${var}` in every field -> declarations dropped with a warning; no purl carries a variable |

Byte-level edge cases (CRLF line endings, embedded NUL, a UTF-8 BOM, an empty
file and a file over the size cap) are generated from a real CMakeLists.txt by
`tests/unit/test_producer_contract.cpp` rather than committed here, and the
`fuzz_cmake_deps` harness explores the rest.
