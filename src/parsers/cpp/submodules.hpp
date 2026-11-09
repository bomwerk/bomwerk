#pragma once
#include <filesystem>
#include <string_view>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"

namespace bomwerk::parsers::cpp::submodules
{

/// The universal producer entry point (docs/CONTRIBUTING.md module law). Reads `root`'s
/// `.gitmodules`, resolves each submodule's pinned commit by READING git's ref
/// files: `.git` -> gitdir -> `HEAD` -> `refs/…`/`packed-refs`: and returns one
/// Component per declared submodule with a `pkg:github|gitlab|bitbucket|generic`
/// purl. It never runs `git` (a subprocess would honor the scanned repo's own
/// config and is a remote-code-execution vector on untrusted code: see the
/// engineering ADR) and never throws (rule 1): a hostile or partial
/// `.gitmodules` yields warnings plus whatever resolved cleanly.
///
/// Each Component's `root` holds the submodule's working-tree path relative to
/// `root`; `scan` uses it to skip that subtree during its file walk. A repo
/// with no `.gitmodules` is not an error: the result is simply empty.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

/// Parse a `.gitmodules` held in memory exactly as `parse` parses `root`'s
/// own, with nothing outside that text: no superproject origin (relative URLs
/// stay relative and warn) and no checkout (every submodule is reported
/// uninitialized). Bounded as `core::parse_git_config` bounds any git config,
/// and never touches the filesystem: this is the entry point of the
/// `fuzz_submodules` harness.
[[nodiscard]] core::Result<std::vector<core::Component>> parse_bytes(
    std::string_view gitmodules_bytes);

}  // namespace bomwerk::parsers::cpp::submodules
