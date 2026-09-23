# Hostile conan corpus

Adversarial inputs the parser must survive (Hard Rule 1: warn, never crash,
never exit-2). File naming maps to the manifest each byte-stream impersonates:
`*.conanfile.txt` -> `conanfile.txt`, `*.conanfile.py` -> `conanfile.py`,
`*.conan.lock` -> `conan.lock`; `test_conan.cpp` copies each into a TempTree
under that canonical name. All files are hand-written for this repo.
