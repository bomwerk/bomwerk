#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "core/file_index.hpp"
#include "core/result.hpp"

namespace bomwerk::core
{

/// One manifest file found and read within the configured safety budgets.
struct WalkedManifestFile
{
  std::string label;       ///< root-relative path in generic_string() form
  std::string bytes;       ///< readable contents, possibly truncated
  bool truncated = false;  ///< true when bytes is only a readable prefix
};

/// Limits and warning identity used by walk_bounded_manifest_files.
struct ManifestWalkOptions
{
  std::size_t max_scanned_files = 0;
  std::size_t max_file_bytes = 0;
  std::string producer_name;
  std::string file_label;
  /// Line-based formats retain complete lines; whole-document formats skip
  /// oversized files instead.
  bool truncate_at_last_newline = true;
};

/// Find and bounded-read every matching file in an existing FileIndex.
/// Unreadable and oversized files produce warnings and are skipped or
/// truncated according to the options; this helper does not change complete.
[[nodiscard]] Result<std::vector<WalkedManifestFile>> walk_bounded_manifest_files(
    const FileIndex& file_index, const std::filesystem::path& root, std::string_view filename,
    const ManifestWalkOptions& options);

}  // namespace bomwerk::core
