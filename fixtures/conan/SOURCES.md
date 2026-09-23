# Real-world conan manifests: provenance

Recipe for vendoring (human step; pin the commit you fetched from). Until
fetched, `test_conan.cpp` skips these via an `fs::exists` guard.

| Target file | Upstream | Pinned commit |
|---|---|---|
| `openssl-conanfile.py` | github.com/conan-io/conan-center-index `recipes/openssl/3.x.x/conanfile.py` | (fill on fetch) |
| `docopt-demo-conanfile.txt` | github.com/conan-io/examples2 `tutorial/consuming_packages/simple_cmake_project/conanfile.txt` | (fill on fetch) |
| `cci-lock.conan.lock` | any conan-2 project's committed `conan.lock` | (fill on fetch) |

Hostile corpus: see `hostile/README.md` (hand-written, no upstream).
