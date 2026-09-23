# CMake fixtures: sources & vendoring recipe

These are meant to be the **real, unmodified** CMake files of well-known public
C/C++ projects that use `FetchContent` or CPM, vendored so the CMake parser
(`parsers/cpp/cmake_deps`) is tested against inputs it did not author: same
rationale as [`fixtures/gitmodules/SOURCES.md`](../gitmodules/SOURCES.md): *"a
fixture the author writes only encodes the author's assumptions."* Each should
be pinned to a specific commit so it never drifts. Only the CMake file(s) below
are vendored: none of the projects' source. See [`hostile/`](hostile/) for the
hand-written adversarial corpus (already in place).

**Not yet vendored.** The table below is a recipe, not a manifest: fetch each
`raw.githubusercontent.com/<repo>/<pinned-commit>/<path>` URL, save it under
`fixtures/cmake/` at the given filename, and fill in the pinned-commit column
here in the same change (mirroring the gitmodules table's format). `git log -1
--format=%H` on the file's history at fetch time gives you a commit to pin.

| Fixture | Source repo | File to fetch | Exercises |
|---|---|---|---|
| `nlohmann-json.CMakeLists.txt` | [nlohmann/json](https://github.com/nlohmann/json) | `CMakeLists.txt` | conditional `FetchContent_Declare` behind an option, `GIT_TAG` pinned to a released tag |
| `abseil.CMakeLists.txt` | [abseil/abseil-cpp](https://github.com/abseil/abseil-cpp) | `CMakeLists.txt` | multiple `FetchContent_Declare` calls in one file (googletest, etc.) |
| `googletest-user.CMakeLists.txt` | any small public project vendoring googletest via FetchContent (e.g. search GitHub for `FetchContent_Declare(googletest`) | `CMakeLists.txt` | canonical `GIT_REPOSITORY` + `GIT_TAG` + `FetchContent_MakeAvailable` triple |
| `cpm-user.cmake` | a project using [`cpm.cmake`](https://github.com/cpm-cmake/CPM.cmake): check its own `README.md` "Users" / "Adopters" section for examples | `cmake/*.cmake` containing `CPMAddPackage(...)` | CPM keyword form (`NAME`/`GITHUB_REPOSITORY`/`VERSION`) in a helper module, not the root `CMakeLists.txt` |
| `cpm-shorthand-user.cmake` | same search as above, looking for the `"gh:owner/repo@version"` one-line form | `cmake/*.cmake` or `CMakeLists.txt` | CPM single-argument shorthand |

To refresh a fixture, re-fetch the same path at a **new** pinned commit and
update this table in the same change.

## Why the recipe instead of the files

Per this repo's workflow rules, adding real vendored upstream content is a
step best driven by you (network fetch + license/provenance judgment call per
file), rather than generated sight-unseen. The hostile corpus and every inline
`TempTree`-based test case in `tests/unit/test_cmake_deps.cpp` do not depend on
this table: they already cover the parser's behavior end-to-end. This table
only adds the same "tested against inputs the parser's author did not write"
guarantee that `fixtures/gitmodules/` has for submodules.
