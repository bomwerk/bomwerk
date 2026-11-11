# Hostile scan_config fixtures

Inputs for the `bomwerk.toml` reader (`core/scan_config`) that once broke or
could break an invariant. The loader must **warn and continue** on every
one: never crash, never return exit-2. Each file is named
`<what-it-probes>.<canonical file name>`, so the `fuzz_scan_config` harness
feeds it under the right name (`scripts/fuzz_targets.json`).

| File | Probes |
|------|--------|
| `max-packages-float-overflow.bomwerk.toml` | a `[scan].max_packages` far outside `int64_t`'s range (`8.9e87`): `node->value<std::int64_t>()` converted the TOML float by running `static_cast<int64_t>(double)` before range-checking it, undefined behavior for a double this far out of range (toml++ 3.4.0, `value.hpp:1141`). `value_exact<std::int64_t>()` only accepts a real TOML integer node, so the input is rejected by the existing "must be an integer" warning without the UB cast. Found by fuzzing (T40) |
