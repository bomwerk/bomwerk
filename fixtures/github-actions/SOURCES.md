# GitHub Actions workflow fixtures: sources & attribution

These are **real, unmodified `.github/workflows/*.yml`** files, vendored so the
GitHub Actions dependency producer is tested against
inputs it did not author (a fixture the author writes only encodes the
author's assumptions). Each is pinned to a specific commit so it never drifts.
See [`hostile/`](hostile/) for hand-written adversarial inputs.

| Fixture | Source repo | Pinned commit | Upstream license | Exercises |
|---|---|---|---|---|
| `bomwerk-ci.yml` | an earlier revision of this repo's own `.github/workflows/ci.yml`, with job and image names generalised | `274886c12f78f0a7c0c0b8fb58b78bdad1ad16ca` | Apache-2.0 | `- uses:` sequence form and nested `uses:` after `- name:`; tag-only refs (`v4.1.0`, `v4`, `v5`, `v3`, `v6`): no SHA-pinned ref and no `${{ }}` inside any `uses:` line; the `docker/setup-buildx-action`/`docker/build-push-action` owner-literally-named-`docker` trap, twice |
| `checkout-test.yml` | [actions/checkout](https://github.com/actions/checkout) `.github/workflows/test.yml` | `f548e57e544e1ff5a4c46bf1e1b8685f8e4a348a` | MIT | Local actions (`./`, `./actions-checkout`, `./localClone`): all must be skipped silently; a real `docker://bitnami/git:latest` reference: also skipped silently; tag-pinned `actions/checkout@v7` and `actions/setup-node@v6` |
| `scorecard-lint.yml` | [ossf/scorecard](https://github.com/ossf/scorecard) `.github/workflows/lint.yml` | `f92023a3f77879f96e0c9c1305f289d755be4bb6` | Apache-2.0 | Every reference SHA-pinned (40-hex) with a trailing `# vX.Y.Z` inline comment: the comment must be stripped so the ref reads as the bare SHA (High confidence), not `"<sha> # v8.0.0"` |

Retrieved 2026-09-13 via `gh api repos/<repo>/contents/<path>?ref=<commit>`.

To refresh a fixture, re-fetch the same path at a **new** pinned commit and
update the commit column here in the same change.
