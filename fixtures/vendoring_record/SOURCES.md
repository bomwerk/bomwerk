# Fixtures: `heuristics::vendoring_record`

Vendoring records written for bomwerk's tests: every library name, version,
commit and URL here is invented, laid out in the two formats the reader
understands. No upstream record text is copied. `test_vendoring_record.cpp`
reads each file and pins what it yields; the `fuzz_vendoring_record_index` and
`fuzz_vendoring_record_chromium` targets use them as seeds (their names end in
`README.md` / `README.chromium` without being exactly that name, which the seed
runner skips).

| File | Exercises |
| --- | --- |
| `godot.README.md` | Every Version shape Godot's `thirdparty/README.md` uses: release with commit, `git (<sha>)`, `git (<branch>, <sha>)`, `main (<sha>)`, a bare `<sha>, <year>`, a release with no commit, `1.1.1+git`, a tag-like release, a section holding two libraries, indented per-file bullets, a `#` heading, an upstream that is a file inside a repository, and `?` |
| `chromium.README.chromium` | A Chromium record whose Version names no release (`git (see METADATA)`) and whose `Revision:` is the commit; a `Version:` after `Description:` that must not be read |
| `hostile/two-versions.README.md` | Two Version lines in one section, a repeated section name, two different commits in one value, a bare `##`, a heading with a `/`, a `#hashtag` line, a heading with spaces, and malformed Version values; yields no record at all |
| `hostile/long-lines.README.md` | An over-long heading must still close the section before it, and an over-long Version or Upstream line is ignored |
| `hostile/prose.README.chromium` | Prose under the record's file name: the first line is not `Name:`, so nothing is read |
| `hostile/duplicate-fields.README.chromium` | A Version written twice is ignored, a URL line naming two URLs is not one upstream, and a line that is not a field ends the header |
| `hostile/long-line.README.chromium` | A header line longer than `kMaxLineChars` ends the header |
