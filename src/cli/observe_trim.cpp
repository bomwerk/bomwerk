#include "cli/observe_trim.hpp"

#include <cstdlib>
#include <filesystem>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "core/warning_code.hpp"
#include "observe/shim_names.hpp"
#include "observe/trace_read.hpp"

namespace fs = std::filesystem;

namespace bomwerk::cli
{
namespace
{

bool is_trace_file_candidate(const fs::path& path)
{
  std::error_code stat_error;
  const bool regular = fs::is_regular_file(path, stat_error);
  return regular && !stat_error;
}

template <typename Value>
void append_warnings(core::Result<ObserveTraceApplication>& destination,
                     core::Result<Value>& source)
{
  destination.warnings.insert(destination.warnings.end(),
                              std::make_move_iterator(source.warnings.begin()),
                              std::make_move_iterator(source.warnings.end()));
}

}  // namespace

core::Result<std::optional<fs::path>> resolve_scan_trace_path(const fs::path& scan_root,
                                                              const fs::path& explicit_trace_path)
{
  core::Result<std::optional<fs::path>> result;
  if (!explicit_trace_path.empty())
  {
    result.value = explicit_trace_path;
    return result;
  }

  const char* environment_trace = std::getenv(observe::kTraceEnvVarName.data());
  if (environment_trace != nullptr && environment_trace[0] != '\0')
  {
    const fs::path environment_trace_path = environment_trace;
    if (is_trace_file_candidate(environment_trace_path))
    {
      result.value = environment_trace_path;
    }
    else
    {
      result.warn(core::WarningCode::kObserveTraceNotWritten,
                  std::string(observe::kTraceEnvVarName) + " points to an unreadable trace file: " +
                      environment_trace_path.string() + "; build usage was not applied");
    }
    return result;
  }

  const fs::path root_candidate = scan_root / kDefaultObserveTracePath;
  if (is_trace_file_candidate(root_candidate))
  {
    result.value = root_candidate;
    return result;
  }

  std::error_code current_directory_error;
  const fs::path current_directory = fs::current_path(current_directory_error);
  if (current_directory_error)
  {
    return result;
  }
  const fs::path current_directory_candidate = current_directory / kDefaultObserveTracePath;
  if (current_directory_candidate.lexically_normal() != root_candidate.lexically_normal() &&
      is_trace_file_candidate(current_directory_candidate))
  {
    result.value = current_directory_candidate;
  }
  return result;
}

core::Result<ObserveTraceApplication> apply_observe_trace(const fs::path& trace_path,
                                                          const fs::path& scan_root,
                                                          std::vector<core::Component>& components)
{
  core::Result<ObserveTraceApplication> result;
  core::Result<std::vector<observe::TraceRecord>> trace = observe::read_trace(trace_path);
  append_warnings(result, trace);
  if (!trace.complete || trace.value.empty())
  {
    result.complete = false;
    return result;
  }

  const std::set<fs::path> component_roots = observe::component_roots_of(components);
  core::Result<observe::CompileMap> compile_map =
      observe::map_compiles_to_roots(trace.value, scan_root, component_roots);
  core::Result<observe::LinkMap> link_map =
      observe::map_links_to_roots(trace.value, scan_root, component_roots);
  append_warnings(result, compile_map);
  append_warnings(result, link_map);
  if (!compile_map.complete || !link_map.complete)
  {
    result.complete = false;
    return result;
  }

  observe::merge_link_evidence(compile_map.value, link_map.value);
  result.value.summary = observe::mark_used_in_build(components, compile_map.value);
  result.value.compile_map = std::move(compile_map.value);
  result.value.link_map = std::move(link_map.value);
  return result;
}

}  // namespace bomwerk::cli
