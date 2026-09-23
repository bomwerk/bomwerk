# SPDX 3.0.1 official JSON schema: provenance

Vendored so schema validation runs offline/reproducibly (rule 3) instead of
fetching from the network on every CI run. Re-run the fetch command below
(bumping the version) to pick up a newer release: review the diff before
committing it.

| Target file | Upstream | Pinned version |
|---|---|---|
| `spdx-schema.json` | spdx.org published SPDX 3.0.1 JSON schema | `3.0.1` |

Fetch command:
```bash
curl -fsSL -o "tests/schemas/spdx-3.0.1/spdx-schema.json" \
  "https://spdx.org/schema/3.0.1/spdx-json-schema.json"
```

> **Verify the URL before committing.** The 3.0.1 JSON-LD *context* is published
> at `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` (confirmed: the writer
> emits exactly that `@context`); the JSON *schema* lives at the parallel
> `https://spdx.org/schema/3.0.1/` path, but confirm the exact filename resolves
> (curl `-fsSL` fails loudly if it does not) rather than committing a 404 body.

Validated by `scripts/validate_spdx_schema.py` (JSON Schema draft chosen from
the schema's own `$schema`), driven by the `spdx_3_0_schema_validation` ctest.
Structural validation only: the JSON-LD `@context` is not resolved, matching
the T14 acceptance criterion ("SPDX output schema-valid").
