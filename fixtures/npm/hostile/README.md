# Hostile npm fixtures

Inputs for the `package-lock.json` reader (`parsers/lockfiles/npm`) that once
broke or could break an invariant. The producer must **warn and continue** on
every one: never crash, never return exit-2, never emit a purl that does not
parse. Each file is named `<what-it-probes>.<canonical file name>`, so
`tests/unit/test_producer_contract.cpp` and the `fuzz_npm` harness feed it
under the right name.

| File | Probes |
|------|--------|
| `link-not-boolean.package-lock.json` | a `packages` entry whose `link` field is a string, not a boolean: `entry.value("link", false)` threw `nlohmann::json::type_error` (302) instead of treating the entry as not-a-link, crashing `bomwerk scan` on an otherwise ordinary lockfile. Found by fuzzing (T40) |
| `dev-not-boolean.package-lock.json` | the same shape for `dev`: a non-boolean value no longer crashes, and the entry still parses with `scope` left at its default |
