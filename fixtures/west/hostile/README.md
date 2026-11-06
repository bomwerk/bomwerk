# Hostile west manifest fixtures

Hand-written adversarial inputs. A scanner is a security product: on **any**
of these the west producer must warn (or stay silent, where noted) and
continue: never crash, hang, guess a url, or exit with code 2 for a
merely-malformed manifest (rule 1). These double as a future libFuzzer seed
corpus (T40). Inputs whose exact bytes git could rewrite (CRLF, NUL) and the
oversized file are synthesized in `tests/unit/test_west.cpp` instead.

| Directory | What it probes |
|---|---|
| `missing-remote/` | a project naming a remote that does not exist: skipped with a warning naming it, never resolved through the only remote; its sibling still resolves |
| `ambiguous-remotes/` | two remotes, no `defaults.remote`, a project with no `remote`: west itself refuses it, so it is skipped with a warning; the sibling naming its remote resolves |
| `block-scalar-fake-url/` | a `userdata: \|` body holding `url:` and `- name:` lines: skipped as one unit, so no `injected` project and no evil url |
| `tabs/` | tab indentation: nothing below `manifest:` is recognized, counted as unsupported lines, no component |
| `self-url/` | `manifest.self` carrying a url and revision: never a component |
| `flow-mapping-item/` | a `- {name: ..., revision: ...}` item: outside the subset, counted, and still marks a new item so nothing leaks into its neighbours |
| `not-a-manifest/` | a file called `west.yml` with no top-level `manifest:` key: silently ignored, no warning |
| `nameless-project/` | a lone `-` item with no `name` and a bare `- scalar` item: both counted as malformed, the named sibling resolves |
