# Hostile Python fixtures

Inputs for the requirements.txt, uv.lock and poetry.lock readers
(`parsers/lockfiles/python`) that once broke or could break an invariant. The
producer must **warn and continue** on every one: never crash, never return
exit-2, never emit a purl that does not parse. Each file is named
`<what-it-probes>.<canonical file name>`, so `tests/unit/test_producer_contract.cpp`
and the `fuzz_python_*` harnesses feed it under the right name.

| File | Probes |
|------|--------|
| `separator-only-name.requirements.txt` | a requirement whose name is only separators (`_`, `._.`) normalizes to nothing: skipped, the real package beside it kept (found by fuzzing, T40) |
| `separator-only-name.uv.lock` | the same in a `uv.lock` `[[package]]` entry |
| `separator-only-name.poetry.lock` | the same in a `poetry.lock` `[[package]]` entry |
