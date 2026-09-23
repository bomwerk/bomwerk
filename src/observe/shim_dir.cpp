#include "observe/shim_dir.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <fstream>
#include <system_error>

#include "core/warning_code.hpp"
#include "observe/shim_names.hpp"

#if defined(__APPLE__)
#include <mach-o/dyld.h>

#include <cstdint>
#endif

namespace fs = std::filesystem;

namespace bomwerk::observe
{
namespace
{

constexpr std::string_view kShimBinaryName = "bomwerk-shim";
constexpr std::string_view kShimBinaryOverrideEnvVar = "BOMWERK_SHIM_BINARY";
constexpr char kPathSeparator = ':';

/// Environment variables build systems read to pick a tool, paired with the
/// shim that should answer for them (a build may check `CC`/`CXX` directly).
struct ToolEnvironmentAlias
{
  std::string_view variable_name;
  std::string_view tool_name;
};

constexpr std::array<ToolEnvironmentAlias, 4> kToolEnvironmentAliases{
    ToolEnvironmentAlias{"CC", "cc"}, ToolEnvironmentAlias{"CXX", "c++"},
    ToolEnvironmentAlias{"LD", "ld"}, ToolEnvironmentAlias{"AR", "ar"}};

/// Absolute, symlink-resolved form of `path`, or the input unchanged when it
/// cannot be resolved. Used only to compare directories, never to open them.
fs::path normalized_directory(const fs::path& path)
{
  std::error_code error;
  const fs::path resolved = fs::weakly_canonical(path, error);
  if (error)
  {
    return path;
  }
  return resolved;
}

bool is_executable_file(const fs::path& candidate)
{
  std::error_code error;
  // status() follows symlinks: /usr/bin/cc is one on most systems.
  const fs::file_status status = fs::status(candidate, error);
  if (error || !fs::is_regular_file(status))
  {
    return false;
  }
  return ::access(candidate.c_str(), X_OK) == 0;
}

/// Directory holding the currently running executable.
fs::path own_executable_directory()
{
#if defined(__APPLE__)
  std::uint32_t buffer_size = 0;
  _NSGetExecutablePath(nullptr, &buffer_size);
  if (buffer_size == 0)
  {
    return fs::path();
  }
  std::string buffer(buffer_size, '\0');
  if (_NSGetExecutablePath(buffer.data(), &buffer_size) != 0)
  {
    return fs::path();
  }
  return normalized_directory(fs::path(buffer.c_str())).parent_path();
#else
  std::error_code error;
  const fs::path self = fs::read_symlink("/proc/self/exe", error);
  if (error)
  {
    return fs::path();
  }
  return self.parent_path();
#endif
}

/// Record the real tool path beside its shim, so a build that later runs
/// WITHOUT observe (a CMake cache remembers the shim's absolute path) still
/// finds its way to the real compiler instead of failing.
bool write_real_tool_sidecar(const fs::path& shim_path, const fs::path& real_tool_path)
{
  fs::path sidecar_path = shim_path;
  sidecar_path += std::string(kRealToolSidecarSuffix);
  std::ofstream sidecar_stream(sidecar_path, std::ios::binary | std::ios::trunc);
  if (!sidecar_stream)
  {
    return false;
  }
  sidecar_stream << real_tool_path.string() << '\n';
  return sidecar_stream.good();
}

}  // namespace

fs::path find_executable_in_path(std::string_view tool_name, std::string_view search_path,
                                 const fs::path& excluded_directory)
{
  if (tool_name.empty())
  {
    return fs::path();
  }
  const fs::path normalized_exclusion = normalized_directory(excluded_directory);

  std::size_t entry_start = 0;
  while (entry_start <= search_path.size())
  {
    std::size_t separator_position = search_path.find(kPathSeparator, entry_start);
    if (separator_position == std::string_view::npos)
    {
      separator_position = search_path.size();
    }
    const std::string_view entry =
        search_path.substr(entry_start, separator_position - entry_start);
    entry_start = separator_position + 1;

    // An empty PATH entry means "current directory" to a shell; resolving a
    // compiler out of the scanned tree's cwd is never what we want here.
    if (entry.empty())
    {
      continue;
    }
    const fs::path directory(entry);
    if (normalized_directory(directory) == normalized_exclusion)
    {
      continue;  // never resolve a shim as its own real tool
    }
    const fs::path candidate = directory / tool_name;
    if (is_executable_file(candidate))
    {
      return candidate;
    }
  }
  return fs::path();
}

fs::path locate_shim_binary()
{
  const char* override_path = std::getenv(std::string(kShimBinaryOverrideEnvVar).c_str());
  if (override_path != nullptr && *override_path != '\0')
  {
    return fs::path(override_path);
  }
  const fs::path executable_directory = own_executable_directory();
  if (executable_directory.empty())
  {
    return fs::path();
  }
  return executable_directory / kShimBinaryName;
}

core::Result<ShimSetup> prepare_shim_directory(const fs::path& shim_directory,
                                               const fs::path& shim_binary_path,
                                               const fs::path& trace_path,
                                               std::string_view search_path)
{
  core::Result<ShimSetup> outcome;

  if (!is_executable_file(shim_binary_path))
  {
    outcome.warn(core::WarningCode::kObserveShimBinaryMissing,
                 "shim binary not found or not executable: " + shim_binary_path.string() +
                     " (set BOMWERK_SHIM_BINARY to override)");
    outcome.complete = false;
    return outcome;
  }

  std::error_code error;
  fs::create_directories(shim_directory, error);
  if (error && !fs::is_directory(shim_directory))
  {
    outcome.warn(
        core::WarningCode::kObserveShimDirectoryUnwritable,
        "cannot create shim directory " + shim_directory.string() + ": " + error.message());
    outcome.complete = false;
    return outcome;
  }

  // Absolute from here on: the build is free to chdir, and every path we hand
  // it through the environment or a CMake cache must survive that.
  outcome.value.shim_directory = normalized_directory(shim_directory);
  outcome.value.trace_path = fs::absolute(trace_path, error);
  if (error)
  {
    outcome.value.trace_path = trace_path;
  }

  for (const std::string_view tool_name : kShimmedToolNames)
  {
    const fs::path real_tool_path =
        find_executable_in_path(tool_name, search_path, outcome.value.shim_directory);
    if (real_tool_path.empty())
    {
      continue;  // absent tool: normal, not degraded
    }

    const fs::path shim_path = outcome.value.shim_directory / tool_name;
    fs::remove(shim_path, error);  // a stale shim from an earlier run
    fs::create_symlink(shim_binary_path, shim_path, error);
    if (error)
    {
      outcome.warn(core::WarningCode::kObserveShimCreationFailed,
                   "cannot create shim for " + std::string(tool_name) + ": " + error.message());
      continue;
    }
    if (!write_real_tool_sidecar(shim_path, real_tool_path))
    {
      outcome.warn(core::WarningCode::kObserveShimCreationFailed,
                   "cannot record the real path of " + std::string(tool_name) +
                       "; a later build outside `bomwerk observe` would fail on this shim");
    }

    outcome.value.environment_overlay.push_back(shim_env_var_name(tool_name) + "=" +
                                                real_tool_path.string());
    outcome.value.shimmed_tool_names.emplace_back(tool_name);
  }

  if (outcome.value.shimmed_tool_names.empty())
  {
    outcome.warn(core::WarningCode::kObserveNoToolchainFound,
                 "no compiler, linker or archiver found on PATH, nothing to observe");
    outcome.complete = false;
    return outcome;
  }

  const char* current_search_path = std::getenv("PATH");
  std::string path_value = outcome.value.shim_directory.string();
  if (current_search_path != nullptr && *current_search_path != '\0')
  {
    path_value.push_back(kPathSeparator);
    path_value += current_search_path;
  }
  outcome.value.environment_overlay.push_back("PATH=" + path_value);
  outcome.value.environment_overlay.push_back(std::string(kTraceEnvVarName) + "=" +
                                              outcome.value.trace_path.string());

  for (const ToolEnvironmentAlias& alias : kToolEnvironmentAliases)
  {
    const bool tool_was_shimmed =
        std::find(outcome.value.shimmed_tool_names.begin(), outcome.value.shimmed_tool_names.end(),
                  alias.tool_name) != outcome.value.shimmed_tool_names.end();
    if (tool_was_shimmed)
    {
      outcome.value.environment_overlay.push_back(
          std::string(alias.variable_name) + "=" +
          (outcome.value.shim_directory / alias.tool_name).string());
    }
  }

  std::sort(outcome.value.environment_overlay.begin(), outcome.value.environment_overlay.end());
  std::sort(outcome.value.shimmed_tool_names.begin(), outcome.value.shimmed_tool_names.end());
  return outcome;
}

void apply_environment_overlay(const std::vector<std::string>& environment_overlay)
{
  for (const std::string& entry : environment_overlay)
  {
    const std::size_t equals_position = entry.find('=');
    if (equals_position == std::string::npos || equals_position == 0)
    {
      continue;
    }
    const std::string variable_name = entry.substr(0, equals_position);
    const std::string variable_value = entry.substr(equals_position + 1);
    ::setenv(variable_name.c_str(), variable_value.c_str(), 1 /* overwrite */);
  }
}

}  // namespace bomwerk::observe
