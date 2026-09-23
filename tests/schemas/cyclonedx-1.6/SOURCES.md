# CycloneDX 1.6 official JSON schema: provenance

Vendored so schema validation runs offline/reproducibly (rule 3) instead of
fetching from the network on every CI run. Re-run the fetch command below
(bumping the tag) to pick up a newer patch release: review the diff before
committing it.

| Target file | Upstream | Pinned tag |
|---|---|---|
| `bom-1.6.schema.json` | github.com/CycloneDX/specification `schema/bom-1.6.schema.json` | `1.6.2` |
| `spdx.schema.json` | github.com/CycloneDX/specification `schema/spdx.schema.json` | `1.6.2` |
| `jsf-0.82.schema.json` | github.com/CycloneDX/specification `schema/jsf-0.82.schema.json` | `1.6.2` |

Fetch command:
```bash
for f in bom-1.6.schema.json spdx.schema.json jsf-0.82.schema.json; do
  curl -fsSL -o "tests/schemas/cyclonedx-1.6/$f" \
    "https://raw.githubusercontent.com/CycloneDX/specification/1.6.2/schema/$f"
done
```
