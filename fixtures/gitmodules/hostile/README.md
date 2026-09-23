# Hostile `.gitmodules` fixtures

Hand-written adversarial inputs. A scanner is a security product: on **any** of
these the parser must warn and continue: never crash, hang, read out of
bounds, escape the repo, or exit with code 2 for a merely-malformed file
(rule 1). These double as the libFuzzer seed corpus once a fuzz harness exists.

| File | What it probes |
|---|---|
| `unterminated-header.gitmodules` | section header with no closing `]` |
| `path-escape.gitmodules` | `path = ../../evil` (CVE-2018-11235 shape): must be rejected |
| `path-absolute.gitmodules` | absolute `path`: must be rejected |
| `missing-url.gitmodules` | submodule with a path but no `url` |
| `empty-url.gitmodules` | `url =` with an empty value |
| `duplicate-paths.gitmodules` | two submodules claiming the same path |
| `entry-outside-section.gitmodules` | a `key = value` before any `[section]` |
| `no-trailing-newline.gitmodules` | last line has no `\n` |
| `crlf.gitmodules` | Windows CRLF line endings |
| `bom.gitmodules` | UTF-8 BOM before the first header |
| `nul.gitmodules` | embedded NUL byte inside a value |
| `long-line.gitmodules` | one ~100 KiB line: exceeds the per-line cap |
| `many-sections.gitmodules` | ~10000 sections: exceeds the section cap |
