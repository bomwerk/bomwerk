# West manifest fixtures: sources & attribution

`zephyr-v4.5.0/zephyr/west.yml` is the **real, unmodified** manifest of
upstream Zephyr, vendored so the west parser is tested against a manifest it
did not author. It sits under `zephyr/` the way a west workspace checks it out,
so the workspace top directory is the fixture directory and project `path:`
values map to checkout roots inside it. Only the manifest is copied here: none
of Zephyr's source.

Retrieved 2026-11-06 from
`github.com/zephyrproject-rtos/zephyr/blob/<commit>/west.yml`.

| Fixture | Source repo | Pinned commit | Upstream license | Exercises |
|---|---|---|---|---|
| `zephyr-v4.5.0/zephyr/west.yml` | [zephyrproject-rtos/zephyr](https://github.com/zephyrproject-rtos/zephyr) (tag `v4.5.0`) | `41d10b59730406bbab4ca9f1fbbe9e96aafb4966` | Apache-2.0 | 81 projects pinned to full SHAs; two remotes with `defaults.remote`; `repo-path` renames; block and flow `groups`; `group-filter`; `west-commands`; `self.import` |

The other directories are hand-written, one rule each, with synthetic commit
ids:

| Directory | Exercises |
|---|---|
| `default-remote/` | `defaults.remote` for every project; `defaults.revision` for a project with none of its own |
| `explicit-url/` | an explicit `url` winning over `remote`; a non-forge host becoming `pkg:generic`; a trailing-slash `url-base`; tag and branch revisions (Medium) |
| `repo-path/` | the single remote used when there is no `defaults.remote`; `repo-path` in the url, the project name kept as the component name |
| `import/` | `import:` on a project (a mapping) and on `self`: the importing project is emitted, the import is a warning; `import: false` is not |
| [`hostile/`](hostile/) | adversarial inputs, see its README |

To refresh the Zephyr fixture, re-fetch the same path at a **new** pinned
commit, rename its directory to the new tag and update this table in the same
change.
