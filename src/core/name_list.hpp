#pragma once
#include <filesystem>
#include <set>
#include <string>
#include <string_view>

#include "core/result.hpp"

namespace bomwerk::core
{

/// Load a set of names from a text file: one per line, blank lines and
/// `#`-comments ignored, surrounding whitespace trimmed. Shared by the
/// manifest-name and directory-exclusion lists so both are configurable the
/// same way.
///
/// Never throws (rule 1): an unreadable or empty file returns `fallback`
/// with a warning naming `subject` (e.g. "manifest list", "exclude list"),
/// so a scan always has something usable.
Result<std::set<std::string>> load_name_list(const std::filesystem::path& list_path,
                                             std::string_view subject,
                                             const std::set<std::string>& fallback);

}  // namespace bomwerk::core
