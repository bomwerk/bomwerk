# Zephyr west manifests

Bomwerk reads Zephyr's `west.yml` (and the `west.yaml` spelling) directly and
emits one component per `manifest.projects[]` entry. It never runs `west`, and
it needs no workspace: a checked-out application or the Zephyr repository on
its own is enough. The rules below are tested against upstream Zephyr's own
manifest ([fixture sources](../fixtures/west/SOURCES.md)).

## How a project resolves

The rules are west's own:

- **URL.** An explicit `url:` wins. Otherwise the project's `remote:`, else
  `defaults.remote`, else the only remote when exactly one is declared,
  supplies its `url-base`, joined with the project's `repo-path:` or, without
  one, its `name:`. A project whose URL resolves to nothing (an unknown remote,
  or two remotes and no default) is skipped with a warning.
- **Revision.** The project's `revision:`, else `defaults.revision`, kept
  exactly as written: tags and SHAs both occur. A project with neither is
  reported without a version, at Low confidence, with a warning. West's
  implicit `master` is never assumed.
- **Identity.** A github.com project becomes `pkg:github/<owner>/<repo>@<revision>`;
  any other host becomes `pkg:generic` with the clone URL as `vcs_url`. A full
  commit SHA is High confidence, a tag or branch Medium. The west project name
  is the component name, so `repo-path: CMSIS_6` under `name: cmsis_6` reports
  `cmsis_6`.
- **Location.** Project `path:` values are relative to the workspace top
  directory, the parent of the repository holding the manifest. When that
  directory is inside the scan (scanning a workspace whose manifest is
  `zephyr/west.yml`), the path becomes the component's location, which is what
  `observe` uses to mark it as compiled. When the manifest is at the scan root,
  the workspace lies above it and no location is claimed.

`manifest.self` describes the manifest repository itself and is never a
component.

## What is not followed

`import:` on a project or on `self` pulls in projects from another manifest.
Bomwerk does not follow imports: the importing project is still reported, and
one warning per manifest names every importer, so the gap is visible rather
than guessed. `import: false` is not an import.

`groups`, `group-filter`, allowlists, `userdata`, `submodules` and
`west-commands` are read past and do not change the result: every declared
project is reported, whichever groups a given workspace enables. A west
manifest's own submodules are already covered by the `.gitmodules` reader, and
a project that is also a submodule merges with it on its purl.

## Limits

A manifest is read whole, up to 1 MiB. A larger file is skipped with a warning
rather than half-read, because a truncated prefix could lose the `remotes:`
later projects resolve against. Lines outside the YAML subset bomwerk reads
(anchors, tags, tab indentation, flow-mapping items) are counted in one
warning per file. A file called `west.yml` with no top-level `manifest:` key is
not a west manifest and is ignored.
