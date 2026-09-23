# Open-core build and release boundary

## Current state

This repository is the Apache-2.0 Community edition. `BOMWERK_PRO` defaults to `OFF`, and that
configuration does not compile, link, or register registry, triage/VEX state, any monitor
implementation (including CISA KEV refresh/cache logic), the paid report renderer, or the Ed25519
entitlement verifier. The Community target does not link `OpenSSL::Crypto` for entitlement
verification; its HTTPS dependency may still bring a TLS implementation transitively through curl.
Community exposes no `monitor`, `registry`, `triage`, `license`, or `report` command.

The paid implementation lives in a separate private repository, composed on top of this one at
build time rather than copied into it. CMake rejects a private-source path that lives inside this
repository's own source tree. This is code separation and release governance, not obfuscation and
not a claim that a customer-controlled executable is tamper-proof.

Pro test fixtures, report templates, deployment documentation, packaging harnesses, and their
CTest registrations also live only in the private repository.

## Contributing to Community versus the extension

All Community development happens here: fork this repository, branch, and open a pull request, as
[CONTRIBUTING.md](CONTRIBUTING.md) describes. A Community fix lands here first, and the private
extension adopts it afterward through a reviewed pin bump (below); a fix never travels the other
way, and the private repository is never merged into this one.

## Public history

This repository's history begins at one root commit, created from a reviewed source snapshot. It
is not the development history that preceded the open release: that history contained the paid
extension's source, so no commit, branch, tag, or object from it was carried over. It is preserved
privately.

Two consequences are load-bearing:

- Nothing is ever pushed, merged, or cherry-picked from that archive into this repository. Work
  that predates the cut is re-applied as a reviewed patch.
- `scripts/audit_public_history.py`, part of this repository, checks the whole repository: every
  ref, every commit, and every object in the object database, including objects a deleted branch
  left behind, against the public layout defined here. It runs in CI on every change.

## Pinning Community from the extension

The private extension records the exact Community commit it composes, the way this repository's
vcpkg submodule records an exact upstream commit. A paid release therefore names two commit ids,
and a Community fix reaches a paid artifact only through a reviewed pin bump, never implicitly by
rebuilding.

## Extension points

Three surfaces used to enumerate paid causes inside Community, which made the free binary describe
a product it does not contain and made `--endpoints` over-report. Each is now a registration point
instead, and Community ships an empty one:

| Surface | Community | A composed build |
| --- | --- | --- |
| warning codes | `core::WarningCode` lists only causes Community raises | registers its own ids through `Result::warn(WarningCodeInfo, ...)`; `core::code_info_of` resolves both alike |
| outbound endpoints | `vuln::kFeedEndpoints`, printed verbatim by `bomwerk --endpoints` | adds rows before any request, so the allowlist and the printed list still cannot drift apart |
| vulnerability cache tables | the migration creates only tables Community reads and writes | creates its own, additively, on a cache Community may have created first |

The ids are the operator-facing contract and do not change when a cause moves across the boundary:
a code means the same thing it always did, it is simply defined by the component that can raise
it.

## Build contracts

Community build:

```bash
cmake -S . -B build -DBOMWERK_PRO=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

A build composed with the private extension additionally sets `-DBOMWERK_PRO=ON` and points
`-DBOMWERK_PRO_SOURCE_DIR` at that extension's checkout, which must live outside this repository's
own source tree. `BOMWERK_PRO` is a configure-time switch only: the Community executable has no
Pro command, and setting an environment variable named `BOMWERK_PRO`, changing a config file, or
supplying a license token cannot add code or commands that were not linked. `monitor
--check-config` exists only in the Pro artifact, but it runs without a valid entitlement so
installation and entitlement failures remain diagnosable without opening or mutating finding
state.

| Surface | Community | Pro |
| --- | --- | --- |
| `scan`, `observe`, `trim`, `binscan` | yes | yes |
| registry commands and `triage` | absent | included in Pro artifact |
| `monitor --check-config` | absent | entitlement-free diagnostic |
| monitor cycle/daemon/notifications | absent | entitlement required |
| `report` renderer | absent | entitlement required |
| entitlement verification and its direct `OpenSSL::Crypto` link | absent | included |

## Packaging and release checks

The `pro_boundary` CTest checks this checkout's tracked paths, the configured compilation
database, the CLI command tree, runtime flag behavior, and the final binary's namespaces. Every
one of those checks is a positive allowlist: a path, a translation unit, a command, or a namespace
is acceptable because this repository declares it, so a module nobody here has heard of is a
finding rather than an omission. `public_history_audit_tests` and `pro_boundary_validator` keep
both checkers honest against repositories built for the purpose.

A public release must be produced only from a clean public checkout with `BOMWERK_PRO=OFF`, and
the boundary check must run on the exact candidate artifact. Never make a formerly private
repository public if its Git history contains paid source: generate a new public history instead,
which is what this repository did.

Packaging and signing for the paid artifact happen entirely in a private pipeline. Public CI never
receives credentials for the private extension, and never needs them.

## Entitlement

A signed entitlement is an offline authorization control, not DRM. Paid commands verify a signed,
exactly scoped product entitlement before any paid effect and reject a missing, invalid,
out-of-scope, or expired one. There is no phone-home, no hardware lock, and no silent grace period.
Signing prevents a customer from minting an authentic entitlement; it does not make local software
unmodifiable, and Bomwerk does not claim otherwise. The entitlement format, its threat model, and
the commercial policy around issuance and non-payment are customer and contract material,
delivered with the paid artifact rather than published here.

Community is unaffected: it contains no entitlement code, no gate, and nothing to unlock.
