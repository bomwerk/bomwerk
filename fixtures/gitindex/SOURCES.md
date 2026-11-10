# fixtures/gitindex: where the index files come from

Every `.index` file here is a `.git/index` written by **real git**, from the
recipe in [`scripts/make_gitindex_fixtures.py`](../../scripts/make_gitindex_fixtures.py).
The submodules producer reads these files to find the commit a superproject
pins for a submodule that was never checked out (T110), and the reader is only
worth something if it agrees with what git actually writes. An index built by
hand would only prove that the reader agrees with its own author.

`fixtures/binscan/SOURCES.md` keeps ELF and `ar` binaries out of the
repository. Its three reasons do not hold here, so these binaries are
committed:

1. **Same bytes on every runner.** An index is not a build product: git writes
   the same file on macOS and Linux. The recipe uses only
   `git update-index --cacheinfo` and `--index-info`, which record no stat data
   (all zeros), so the bytes depend on the recipe alone, not on the machine,
   the clock or inode numbers. Global and system git config are ignored while
   building.
2. **Reviewable through the recipe.** The script states every entry (mode,
   object id, path) and every git command that follows. The ctest
   `gitindex_fixtures_reproducible` runs `make_gitindex_fixtures.py --check`,
   which rebuilds every file and fails on any byte of difference, so a blob
   cannot drift from its recipe unnoticed. It is skipped where git is absent.
3. **These are the shapes git writes.** Each file is one shape git really
   produces, rather than one only a generator would invent.

Every object id is synthetic, as in `fixtures/golden/SOURCES.md`: a gitlink
needs no object to exist, so nothing here resolves to a real commit.

| File | Shape | Reader's answer |
|---|---|---|
| `v2-sha1.index` | the default format: two regular files and three gitlinks (`libs/mbedtls`, `libs/zlib`, `third_party/openssl`) | the three pins, sorted by path |
| `v3-skip-worktree.index` | the same entries with `--skip-worktree` on `src/main.c`, an extended flag, so git writes version 3 | the same three pins |
| `v4-sha1.index` | the same entries after `--index-version 4` (`feature.manyFiles` turns this on): paths are prefix-compressed | the same three pins |
| `v2-sha256.index` | the same layout in a `--object-format=sha256` repository: 32-byte ids | the three 64-hex pins when read as SHA-256; refused when read as SHA-1 |
| `split.index` | after `--split-index`: a `link` extension, the entries live in a shared index | refused (`BW-GIT-007`) |
| `conflict.index` | `third_party/openssl` at stage 0, `libs/zlib` only at merge stages 1 to 3 | only the openssl pin, no warning |
| `long-path.index` | one gitlink whose path is exactly 0xFFF bytes, which saturates the 12-bit name-length field | the full path, found by its NUL |
| `path-over-limit.index` | one gitlink whose path is 4200 bytes, over the reader's 4096-byte cap | refused |

The golden case `nightmare-shallow-clone` carries one more index from the same
script, at `fixtures/golden/nightmare-shallow-clone/tree/_git/index`.

Hostile variants (a wrong signature, every truncated prefix, an absurd entry
count, a name running past the file, non-NUL padding, a gitlink path with `..`,
and more) are not committed. `tests/unit/test_git_index.cpp` derives each one
from `v2-sha1.index` by breaking exactly one field, so each case states what it
probes. The `fuzz_git_index_*` harnesses start from these files as seeds.
