# Hostile vcpkg corpus

Adversarial inputs the parser must survive (Hard Rule 1: warn, never crash,
never exit-2). File naming maps to the manifest each byte-stream impersonates:
`*.vcpkg.json` -> `vcpkg.json`; `test_vcpkg.cpp` copies each into a TempTree
under that canonical name. All files are hand-written for this repo.

| File | What it attacks |
|---|---|
| `bom.vcpkg.json` | a leading UTF-8 byte-order mark before valid JSON |
| `wrong-types.vcpkg.json` | wrong-typed `dependencies`/`overrides` entries mixed with one valid dependency |
