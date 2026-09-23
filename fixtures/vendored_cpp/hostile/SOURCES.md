# Hostile fixtures: `heuristics::vendored_cpp`

Hand-crafted, adversarial content for the version-header/LICENSE/README sniffers.
`test_vendored_cpp.cpp`'s hostile-corpus loop writes each file
here under a synthetic `third_party/hostile-case/<same filename>` and asserts the
scan always completes (`result.complete`): never a crash, never an
out-of-bounds read, regardless of what the content actually does or doesn't
match. Mirrors `fixtures/conan/hostile/`'s convention (own corpus per producer,
loaded by filename, no directory-structure trickery needed since every file
here is self-contained content).

| File | Exercises |
| --- | --- |
| `zlib.h` | `extract_quoted_macro_value`'s unterminated-quote path: a version macro with no closing `"` |
| `version.h` | The "macro name is only a prefix of a longer identifier" rejection, and, since this filename collides with two table entries (mbedtls, xz-liblzma), that a filename collision with neither macro present fails both cleanly |
| `LICENSE` | A bounded license read/scan over content well past `max_license_bytes`, with no recognizable license phrase anywhere in it |
| `README` | The first-lines reader with no newline at all in the file, past `max_readme_bytes` |

Not covered here (already has direct unit coverage elsewhere): a symlinked or
escaping `.git` inside a vendor root is `core::resolve_git_dir`'s job, proven
safe in `test_git_dir.cpp`: this heuristic only calls that function, it does
not reimplement the containment check.
