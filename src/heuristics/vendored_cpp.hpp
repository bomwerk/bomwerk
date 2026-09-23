#pragma once
#include <cstddef>
#include <filesystem>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"

namespace bomwerk::heuristics::vendored_cpp
{

/// Byte caps for the bounded reads this heuristic performs on files it does
/// not control the size or shape of (rule 1: a crafted file must never make a
/// scan read or search an unbounded amount).
struct ParseLimits
{
  std::size_t max_header_bytes = 16u * 1024u;  ///< version-header search window
  std::size_t max_license_bytes = 4u * 1024u;  ///< LICENSE/COPYING sniff window
  std::size_t max_readme_bytes = 1024u;        ///< README first-lines window
};

/// Heuristic C/C++ vendored-code detection: walk
/// `file_index` for `third_party|thirdparty|vendor|external|deps|libs`
/// folders and emit one component per immediate subfolder ("vendor root"),
/// except that triggers beneath test/fixture directories are ignored, and a
/// DNS namespace container (`github.com`, `k8s.io`, ...) is ignored as a
/// vendor root regardless of which trigger word led to it. Ecosystem
/// lockfile producers provide the authoritative identities for trees such as
/// `vendor/github.com/owner/repository` or `thirdparty/github.com/owner/repository`;
/// this heuristic must not fabricate a `pkg:generic/github.com` placeholder
/// for the namespace. Retained roots are
/// built from whatever identity clues are present there: a recognized
/// version-defining header, a LICENSE/COPYING file, a README, or a leftover
/// `.git` directory. This is heuristic evidence (`core::Source::Heuristic`),
/// never a manifest, so a component from here is never `core::Confidence::High`.
/// `root` must be the same directory `file_index` was built from. Never
/// throws (rule 1); a vendor root with no recognizable clue at all still
/// yields a Low-confidence component named from its folder: silently
/// dropping an unrecognized vendored library is worse than reporting it
/// vaguely.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               ParseLimits limits = {});

/// Every SPDX id the LICENSE-file recognizer can produce. This heuristic
/// keeps its own small license table separate from `output/spdx_license_ids`
/// (a producer may not include `output`, module dependency law), so nothing
/// enforces at compile time that the two stay in sync: exposed only so a
/// test can assert every id here still round-trips through
/// `output::canonical_spdx_license_id`, catching drift a future edit to
/// either table could otherwise introduce silently.
[[nodiscard]] std::vector<std::string_view> recognized_license_spdx_ids();

}  // namespace bomwerk::heuristics::vendored_cpp
