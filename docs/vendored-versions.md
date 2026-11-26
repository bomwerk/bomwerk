# Versions of vendored C/C++ code

A copied-in library has no manifest and no lockfile, so `scan` reports each
directory under `third_party/`, `thirdparty/`, `3rdparty/`, `vendor/`,
`external/`, `extern/`, `deps/` or `libs/` from whatever the tree says about it.
This page describes where the version of such a directory comes from, and what
bomwerk does when two sources disagree.

## Where the version comes from

The sources are tried in this order, and the first one that states a version
wins:

1. **A leftover `.git` directory** inside the vendored folder whose `HEAD`
   resolves. The version is that commit and the purl is the origin
   repository's, for example `pkg:github/mbed-tls/mbedtls@<commit>`.
2. **The library's own files**: a header or build file from the library itself,
   matched against a table of named libraries. Every row has been checked
   against an upstream release.
   - A quoted macro, as in `#define ZLIB_VERSION "1.3.1"`.
   - A bare dotted macro, as in `#define UTHASH_VERSION 2.4.0`.
   - A release split across three macros, as in cJSON's `CJSON_VERSION_MAJOR`,
     `_MINOR` and `_PATCH`.
   - The library's own top-level `CMakeLists.txt`. libjpeg-turbo writes
     `set(VERSION 3.1.2)`, and openjpeg splits its release across
     `set(OPENJPEG_VERSION_MAJOR 2)`, `_MINOR 5` and `_BUILD 3`. Only the
     `CMakeLists.txt` directly in the vendored folder is read; one in a
     subdirectory belongs to something else.
   - One encoded integer. protobuf writes `#define PROTOBUF_VERSION 3019001`
     in `port_def.inc` and `GOOGLE_PROTOBUF_VERSION` in `stubs/common.h`.
     The number decodes as `MAJOR * 1000000 + MINOR * 1000 + PATCH`, so
     `3019001` is 3.19.1. It needs at least seven digits. This is the
     version of the C++ runtime: up to 3.21 that is also the release tag,
     while from 22.0 on the repository is tagged `v22.0` and the runtime it
     ships is 4.22.0.

   Every row except the quoted macros applies only when the folder's name
   contains the library's name, ignoring case and punctuation. That is how
   `libktx`, which bundles `uthash.h`, keeps its own name. The version is
   reported as `pkg:generic/<library>@<version>`.
3. **A vendoring record**: a note the project keeps beside the copied code,
   saying which upstream release or commit it came from (see below).
4. **Nothing but the folder name.** The component is reported as
   `pkg:generic/<folder>` with no version, at Low confidence. bomwerk would
   rather report a library vaguely than drop it.

Every source that was found is kept as evidence on the component, including
those that lost.

## Vendoring records

Two layouts are read.

**An index next to the vendored folders.** This is the `README.md` in the
directory that holds them, with one Markdown section per folder, in the
layout Godot keeps in `thirdparty/README.md`:

```markdown
## zlib

- Upstream: https://github.com/madler/zlib
- Version: 1.3.2 (da607da739fa6047df13e66a2af6b8bec7c2a498, 2026)
- License: Zlib
```

- A `#` or `##` heading whose text is exactly a folder's name opens that
  folder's section, and the next such heading closes it.
- Only top-level `- Version:` and `- Upstream:` bullets count. The indented
  items of a collection section describe its single files, not the folder.
- A section with two `- Version:` lines describes two libraries in one folder,
  so it gives no version. The same is true of a folder name that has two
  sections.
- A `README.md` anywhere else, such as the repository's own, is not read as an
  index.

**A `README.chromium` inside the vendored folder.** These are the `Key: value`
fields at the top of the file, before `Description:`. The file must start
with a `Name:` field. `Version:` is read like an index's Version value, a 40-
or 64-hex `Revision:` is the commit, and `URL:` is the upstream. A field
written twice is ignored. A `README.chromium` deeper inside the folder belongs
to a sub-library and is not read. When the folder has its own
`README.chromium`, that record is used before the parent's index.

A Version value is read as `<head> (<part>, <part>, ...)`:

- The head, up to its first comma, is the release, for example `0.22.3`,
  `1.1.1+git` or `vulkan-sdk-1.4.335.0`. It must be 1 to 64 characters from
  `A-Z a-z 0-9 . _ + ~ -` and contain a digit.
- `git`, `main`, `master`, `trunk`, `HEAD`, `unknown`, `N/A`, `none`, `?`
  and `0` are not releases. Neither is a commit, whether written in full or
  abbreviated.
- The commit is the one 40- or 64-hex object id among the head and the parts.
  When two different ones are written, no commit is stated.
- A record that states neither a release nor a commit gives no version.

How a record becomes a component:

| The record states | Version | Purl |
| --- | --- | --- |
| a release | the release | `pkg:generic/<folder>@<release>` |
| only a commit, and the upstream is `https://github.com/<owner>/<repo>` (or GitLab, Bitbucket) | the commit | `pkg:github/<owner>/<repo>@<commit>`, the same purl a leftover `.git` gives |
| only a commit, and any other upstream | the commit | `pkg:generic/<folder>@<commit>` |

- A release keeps the generic purl because the record does not say how the
  upstream spells its tag (`0.22.3` or `v0.22.3`).
- A commit version is sent to OSV's commit index whatever the purl type.
- An upstream that points inside a repository (`/blob/master/src/file.cpp`),
  at a homepage, or at more than one place is not treated as a repository.
- The forge owner becomes the component's supplier, as with a leftover `.git`.

## When a record and the library disagree

A record is a person's note about the copy and can go stale when someone
updates the files and not the README. The library's own files win.

When a record states a different release than the header or build file, the
component keeps the library's version and the scan raises `BW-VENDORED-001`
(see [warning codes](warning-codes.md)). The warning names both files and
both values. A leading `v` does not count as a difference, and a record that
states only a commit has no release to disagree with.

## Limits

- A record file is read up to 128 KiB. Godot's index is about 41 KB.
- A line longer than 512 characters is ignored.
- Libraries that are not in a table and have no record are still reported
  without a version.
- Matching vendored code by the content of its files is a separate, opt-in
  pass (`scan --fingerprint-index`).
