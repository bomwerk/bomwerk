#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "core/result.hpp"

namespace bomwerk::observe
{

/// A prepared shim directory and the environment a build must run under to be
/// observed by it.
struct ShimSetup
{
  std::filesystem::path shim_directory;          ///< absolute; holds the symlinks and sidecars
  std::filesystem::path trace_path;              ///< absolute; the build may chdir at will
  std::vector<std::string> environment_overlay;  ///< "KEY=VALUE", sorted (rule 3)
  std::vector<std::string> shimmed_tool_names;   ///< tools actually found and shimmed, sorted
};

/// Resolve `tool_name` against a PATH-style colon-separated `search_path`,
/// returning the first executable match or an empty path.
///
/// `excluded_directory` is skipped, and skipping it is a safety requirement,
/// not an optimisation: the shim directory is itself on PATH during an observe
/// run, so resolving `cc` without the exclusion would find the shim and record
/// it as its own real tool: a fork bomb the moment a build ran.
[[nodiscard]] std::filesystem::path find_executable_in_path(
    std::string_view tool_name, std::string_view search_path,
    const std::filesystem::path& excluded_directory);

/// Path of the `bomwerk-shim` executable shipped beside this binary.
/// `BOMWERK_SHIM_BINARY` overrides it (used by tests and unusual installs).
/// Empty when it cannot be located.
[[nodiscard]] std::filesystem::path locate_shim_binary();

/// Create or refresh `shim_directory`: one symlink per resolvable tool plus a
/// `<tool>.real` sidecar recording the real absolute path, and build the
/// environment overlay (PATH prefix, CC/CXX/LD/AR, BOMWERK_TRACE and one
/// BOMWERK_REAL_* per shimmed tool).
///
/// Tools missing from PATH are skipped rather than shimmed: a machine without
/// clang is normal, not degraded, and shimming an absent tool would turn a
/// clean "command not found" into a confusing exec failure.
///
/// `complete` is false only when nothing could be shimmed at all, which makes
/// observation impossible.
[[nodiscard]] core::Result<ShimSetup> prepare_shim_directory(
    const std::filesystem::path& shim_directory, const std::filesystem::path& shim_binary_path,
    const std::filesystem::path& trace_path, std::string_view search_path);

/// Apply `environment_overlay` ("KEY=VALUE" entries) to this process, so the
/// child spawned next inherits it. This process exists only to run that child,
/// so mutating our own environment is simpler and safer than hand-building an
/// envp array that would have to re-merge everything already inherited.
void apply_environment_overlay(const std::vector<std::string>& environment_overlay);

}  // namespace bomwerk::observe
