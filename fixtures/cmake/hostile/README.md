# Hostile CMake fixtures

Hand-written adversarial inputs for the FetchContent/CPM parser
(`parsers/cpp/cmake_deps` + `cmake_scanner`). The producer must **warn and
continue** on every one: never crash, never return exit-2. These double as the
libFuzzer seed corpus once a fuzz harness exists.

| File | Probes |
|------|--------|
| `unbalanced-parens.cmake` | command `(` never closed -> scanner stops at EOF, warns |
| `unterminated-quote.cmake` | quoted argument never closed |
| `unterminated-bracket-arg.cmake` | `[==[ … ]==]` bracket argument never closed |
| `unterminated-bracket-comment.cmake` | `#[[ … ]]` bracket comment never closed |
| `hash-in-url.cmake` | `#` inside a URL / CPM shorthand ref must NOT be treated as a comment |
| `deep-nesting.cmake` | nested generator expressions + deep `(( … ))` (paren-depth bound) |
| `pervasive-vars.cmake` | `${var}` in every field -> emitted at low confidence, warned |

Byte-level edge cases (CRLF line endings, embedded NUL, a UTF-8 BOM, and a
file larger than the 1 MiB cap) are covered by the inline `test_cmake_scanner`
unit (NUL + high bytes) and the size/line bounds; add them here as generated
binary fixtures when a fuzz harness lands.
