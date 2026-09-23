#pragma once
#include <cstddef>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::parsers::lockfiles::pub
{

/// Generated pub lockfiles are line-based and use the shared 8 MiB lockfile
/// safety tier; an oversized file still yields its complete-line prefix.
inline constexpr std::size_t kMaxPubspecLockBytes = 8u * 1024u * 1024u;

/// Runtime safety limits for pubspec.lock discovery and package emission.
struct ParseOptions
{
  std::size_t max_file_bytes = kMaxPubspecLockBytes;  ///< per-lockfile read cap
  std::size_t max_scanned_files = core::kDefaultMaxScannedFilesPerEcosystem;
  std::size_t max_total_packages = core::kDefaultMaxPackagesPerEcosystem;
  std::set<std::filesystem::path> excluded_subtrees;
};

/// Scan all Dart/Flutter pubspec.lock files under root.
[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root);

[[nodiscard]] core::Result<std::vector<core::Component>> parse(const std::filesystem::path& root,
                                                               const ParseOptions& options);

[[nodiscard]] core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                               const std::filesystem::path& root,
                                                               const ParseOptions& options);

}  // namespace bomwerk::parsers::lockfiles::pub
