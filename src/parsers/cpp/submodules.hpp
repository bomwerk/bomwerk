#pragma once
#include <filesystem>
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

}  // namespace bomwerk::parsers::cpp::submodules
