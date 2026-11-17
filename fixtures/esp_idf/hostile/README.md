# Hostile ESP-IDF component manager fixtures

Hand-written adversarial inputs. On **any** of these the ESP-IDF producer must
warn (or stay silent, where noted) and continue: never crash, hang, guess a
version or claim a path outside the repository, and never exit with code 2 for
a merely malformed file (rule 1). They double as fuzz seeds. Inputs whose exact
bytes git could rewrite (CRLF, NUL) and the oversized file are covered by the
producer contract test instead.

| Directory | What it probes |
|---|---|
| `not-a-lock/` | a `dependencies.lock` with no `manifest_hash:`: another tool's file, silently ignored |
| `unknown-major/` | lock format `version: 3.0.0`: the whole file is skipped with one `BW-CORE-013` warning, nothing guessed |
| `bad-hash/` | a `component_hash` that is not 64 hex digits, and a short one: the components are kept, with no SHA-256 |
| `climbing-subpath/` | a git source whose `path:` climbs with `..`: the component is kept with no purl subpath |
| `unknown-source-type/` | an unknown `source.type`, an entry with no source, and a scalar entry: all three counted as malformed |
| `variable-name/` | a `${VAR}` in a dependency name and in a git url: skipped with one `BW-CORE-015` warning |
| `list-form/` | `dependencies:` written as a list: outside the format, counted as malformed, nothing emitted |
| `bad-registry-name/` | names with a second `/`, an empty namespace, an empty name, an empty key: counted as malformed |
| `block-scalar-fake-entry/` | a `description: \|` body holding a `dependencies:` block: skipped as one unit, so no `injected` component |
| `tabs/` | tab indentation: nothing below `dependencies:` is recognized, no component |
| `git-no-url/` | `git: ""`: skipped with a `BW-CORE-016` warning |
| `git-no-version/` | a git source with no `version`, and one with `*`: reported version-less at Low with a `BW-CORE-017` warning |
| `flow-dependencies/` | a one-line `dependencies: {...}`: not read, counted as malformed |
