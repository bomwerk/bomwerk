# Hostile GitHub Actions workflow fixtures

Hand-written adversarial inputs. A scanner is a security product: on **any**
of these the producer must warn (or silently skip, where noted) and continue:
never crash, hang, read out of bounds, or exit with code 2 for a
merely-malformed file (rule 1). These double as a future libFuzzer seed corpus.

| File | What it probes |
|---|---|
| `unresolved-ref.yml` | `uses: owner/repo@${{ ... }}`: ref-only unresolved: Low confidence, warning, no `@` segment and no `${{` anywhere in the emitted purl |
| `unresolved-owner-repo.yml` | `uses: ${{ inputs.action }}` and `uses: ${{ matrix.owner }}/${{ matrix.repo }}@v1`: no resolvable owner/repo in either shape: no component, warning, the exact `pkg:github/%24/...`-shaped bug this producer must not reproduce |
| `no-ref.yml` | `uses: actions/checkout` with no `@ref` at all: Low confidence, warning, no `@` in the purl |
| `local-action.yml` | `uses: ./...` and `uses: ../...`: both skipped silently, no component, no warning |
| `local-reusable-workflow.yml` | job-level `uses: ./.github/workflows/reusable.yml`: same local-path rule applies at job level too |
| `docker-action.yml` | `uses: docker://alpine:3.19`: the URI scheme, skipped silently |
| `docker-owner-name.yml` | `uses: docker/build-push-action@v6`: `docker` as a GitHub *owner name*, not the `docker://` scheme; must NOT be skipped |
| `commented-out.yml` | `# uses: ...` and indented `# - uses: ...` inside an unrelated step: must not be picked up |
| `sequence-item-form.yml` | `- uses: ...` with no preceding `- name:` step: the shape `core::yaml_subset` cannot parse but most real workflows use |
| `subpath-action.yml` | `github/codeql-action/init@v3`: subpath dropped from the purl (`pkg:github/github/codeql-action@v3`) |
| `reusable-workflow-call.yml` | job-level `uses: octo-org/example-repo/.github/workflows/shared.yml@main`: subpath dropped the same way |
| `crlf.yml` | Windows CRLF line endings throughout |
| `bom.yml` | UTF-8 BOM before the first line |
| `nul.yml` | embedded NUL byte inside a `uses:` value |
| `long-line.yml` | one ~100 KiB comment line ahead of a real `uses:` line |
| `many-uses-lines.yml` | 25,000 `uses:` lines: exceeds `ParseOptions::max_total_uses_references` (default 20,000); `result.complete` must stay `true` with exactly one budget warning |
| `no-trailing-newline.yml` | last line (a real `uses:` reference) has no trailing `\n` |
| `malformed-yaml.yml` | broken brackets/indentation elsewhere in the file: a `uses:` line elsewhere must still be read, since this is a line scanner, not a structural parser |
| `block-scalar-fake-uses.yml` | `run: \|` and `run: >` bodies each contain a line that looks like `uses: fake/fake@v1`: both must be skipped as part of the block scalar body; only the real `- uses: acme/real@v1` step outside them is read |
