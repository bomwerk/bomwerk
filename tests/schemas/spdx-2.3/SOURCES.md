# SPDX 2.3 official JSON schema: provenance

Vendored so schema validation runs offline/reproducibly (rule 3) instead of
fetching from the network on every CI run. Re-run the fetch command below
(bumping the tag) to pick up a newer patch release: review the diff before
committing it.

| Target file | Upstream | Pinned tag |
|---|---|---|
| `spdx-schema.json` | github.com/spdx/spdx-spec `schemas/spdx-schema.json` | `v2.3` |

Fetch command:
```bash
curl -fsSL -o "tests/schemas/spdx-2.3/spdx-schema.json" \
  "https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json"
```

Validated by `scripts/validate_spdx_schema.py` (draft-07, chosen from the
schema's own `$schema`), driven by the `spdx_2_3_schema_validation` ctest.
