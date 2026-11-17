# ESP-IDF component manager fixtures: sources & attribution

The two manifests under `esp-idf-c712a0dd/` are **real, unmodified**
`idf_component.yml` files from upstream ESP-IDF, vendored so the parser is
tested against manifests it did not author. They keep their upstream paths.
Only the manifests are copied here: none of ESP-IDF's source.

| Fixture | Source repo | Pinned commit | Upstream license | Exercises |
|---|---|---|---|---|
| `esp-idf-c712a0dd/examples/peripherals/i2c/i2c_u8g2/main/idf_component.yml` | [espressif/esp-idf](https://github.com/espressif/esp-idf) | `c712a0dd` | Apache-2.0 | a `git:` dependency pinned to a full commit SHA |
| `esp-idf-c712a0dd/examples/wifi/iperf/main/idf_component.yml` | [espressif/esp-idf](https://github.com/espressif/esp-idf) | `c712a0dd` | Apache-2.0 | registry constraints in several namespaces, `rules:` conditions, a `${IDF_PATH}` local component |

ESP-IDF commits no `dependencies.lock`, so the lock fixtures are hand-written in
the exact shape the component manager writes, with synthetic hashes (valid
64-hex, deliberately patterned):

| Directory | Exercises |
|---|---|
| `lock-v1/` | a component manager 1.x lock: `service_url` sources, `version: 1.0.0` |
| `registry-mirror/` | a registry other than Espressif's, noted in the evidence detail |
| [`hostile/`](hostile/) | adversarial inputs, see its README |

The 2.x lock, the lockless manifests and the lock-covers-manifest rule are the
golden cases `esp-idf-lock`, `esp-idf-manifest-only` and
`esp-idf-lock-and-manifest` (see [`../golden/SOURCES.md`](../golden/SOURCES.md)).

To refresh the ESP-IDF manifests, re-fetch the same paths at a **new** pinned
commit, rename `esp-idf-c712a0dd/` to match and update this table in the same
change.
