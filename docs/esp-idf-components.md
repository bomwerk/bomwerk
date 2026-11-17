# ESP-IDF component manager files

Bomwerk reads the two files the ESP-IDF component manager works from and emits
one component per dependency. It never runs `idf.py` or the component manager,
and it needs no build: a checked-out project is enough. The rules below are
tested against real upstream ESP-IDF manifests
([fixture sources](../fixtures/esp_idf/SOURCES.md)).

## Which file is read

- **`dependencies.lock`** is the component manager's resolver output, the
  exact version of every component the project builds with. Each entry under
  `dependencies:` is reported at its locked version, High confidence. A file
  by that name is read only when it has the top-level `dependencies:` and
  `manifest_hash:` keys the component manager writes; any other file called
  `dependencies.lock` is ignored without a warning. Lock format 1.x and 2.x
  are read. A lock declaring another major format version is skipped with a
  warning rather than half-understood.
- **`idf_component.yml`** declares what a component needs, as constraints
  (`^2.4.1`, `>=5.0`, `~1`). It is read only where no `dependencies.lock`
  sits in its own directory or any directory above it inside the scan: the
  lock lives at the project root while manifests live in `main/` and
  `components/<name>/`, and the lock has already resolved everything they
  declare.

Files under `managed_components/` (where the component manager unpacks what it
downloads) and under installed-dependency directories are another component's
own declaration and are never read.

## How an entry resolves

- **Registry components.** `<namespace>/<name>` becomes
  `pkg:generic/<namespace>/<name>`; a name written without a namespace is in
  `espressif`, the component manager's default. The namespace is reported as
  the supplier. A lock entry carries its version (`@2.5.5`) and its
  `component_hash`, a SHA-256, as the component hash. A component from a
  registry other than Espressif's keeps the same identity, with the registry
  named in its evidence.
- **The framework.** The `idf` entry is ESP-IDF itself, reported as
  `pkg:generic/espressif/esp-idf`. The name is `esp-idf` because that is the
  product name NVD files ESP-IDF advisories under, so the CPE fallback can
  find them.
- **Git components.** A `git:` source becomes `pkg:github/<owner>/<repo>` for
  github.com and `pkg:generic` with the clone URL as `vcs_url` for any other
  host. Its `path:` inside the repository becomes the purl subpath, so two
  components from one repository stay apart. A full commit SHA is High
  confidence, a tag or branch Medium. A git dependency with no version (or
  `*`) is reported without one, at Low, with a warning.
- **Local components.** A `path:` or `override_path:` entry without `git:`,
  or a lock entry whose source type is `local`, is code that lives in the
  project. It is part of what is being scanned, not a dependency, and is not
  reported.

## Constraints are not versions

A manifest constraint says which versions a project accepts, not which one it
builds with. A component known only from a manifest is therefore reported
without a version, at Medium confidence, with the constraint kept in its
evidence (`main/idf_component.yml -> espressif/led_strip (requires ^2.4.1)`).
This is the rule bomwerk applies to a lockless `composer.json`. A purl carrying
`^2.4.1` would never match an advisory, and picking a version from the range
would be a guess.

Where one project has a lock and another in the same scan only declares the
same component, the version-less entry is dropped: the lock already reports it
with its version. Entries gated by `rules:` or `matches:` are reported whatever
the build target, and their evidence says they are conditional.

## Vulnerability matching

`pkg:generic` and these `pkg:github` identities have no OSV ecosystem, so the
match coverage line counts them as unmatched unless the NVD CPE fallback
(`--cpe-fallback`) finds them. That is deliberate: an ESP-IDF component with no
advisory feed is reported as unchecked, never as clean.

## Limits

Each file is read whole, up to 1 MiB, and a larger one is skipped with a
warning. Lines outside the YAML subset bomwerk reads (anchors, tags, tab
indentation) are counted in one warning per file. A `${VAR}` in a dependency
name or git URL cannot be resolved without the build environment, so that
entry is skipped with a warning; `${IDF_PATH}` in a local `path:` needs no
warning, because local components are not reported anyway.
