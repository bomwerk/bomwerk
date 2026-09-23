#include "cli/observe_command.hpp"

#include <spdlog/spdlog.h>

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

#include "cli/warning_recorder.hpp"
#include "core/exit_codes.hpp"
#include "core/result.hpp"
#include "core/warning_code.hpp"
#include "observe/run_build.hpp"
#include "observe/shim_dir.hpp"
#include "observe/trace_check.hpp"

namespace fs = std::filesystem;

namespace bomwerk::cli
{
namespace
{

// User-facing strings kept together (future --lang de|es, docs/CONTRIBUTING.md style).

constexpr const char* kObserveDescription =
    "Run a build under bomwerk's compiler shims and record what it actually compiled and linked.";

constexpr const char* kDefaultTracePath = ".bomwerk/trace.jsonl";
constexpr const char* kDefaultShimDirectory = ".bomwerk/shims";

/// What an empty trace almost always means. CMake stores the compiler's
/// absolute path in CMakeCache.txt at CONFIGURE time, so building an
/// already-configured tree never consults PATH and the shims are never
/// reached. Saying so plainly is worth more than the warning itself.
constexpr const char* kEmptyTraceExplanation =
    "no compiler invocations were recorded. The usual cause is a build tree configured before "
    "this run: CMake bakes the compiler's absolute path into CMakeCache.txt, so `cmake --build` "
    "never looks at PATH. Re-run the CONFIGURE step under `bomwerk observe` too, or delete the "
    "build directory and start it under observe.";

/// Remove the shim directory. Only ever on explicit request: a build tree
/// configured under observe holds the shim path in its CMake cache, so
/// deleting the shims breaks that tree until it is reconfigured.
void remove_shim_directory(const fs::path& shim_directory)
{
  std::error_code error;
  fs::remove_all(shim_directory, error);
  if (error)
  {
    spdlog::warn("could not remove the shim directory {}: {}", shim_directory.string(),
                 error.message());
    return;
  }
  spdlog::info(
      "removed the shim directory {}. A build tree configured under observe must be "
      "reconfigured before it will build again",
      shim_directory.string());
}

/// Start each run from an empty trace, so one run means one build.
bool reset_trace_file(const fs::path& trace_path)
{
  std::error_code error;
  if (trace_path.has_parent_path())
  {
    fs::create_directories(trace_path.parent_path(), error);
    if (error && !fs::is_directory(trace_path.parent_path()))
    {
      spdlog::error("cannot create the trace directory {}: {}", trace_path.parent_path().string(),
                    error.message());
      return false;
    }
  }
  std::ofstream trace_stream(trace_path, std::ios::binary | std::ios::trunc);
  if (!trace_stream)
  {
    spdlog::error("cannot write the trace file {}", trace_path.string());
    return false;
  }
  return true;
}

/// Summarise what was recorded, per tool, in a stable order.
void log_trace_summary(const observe::TraceStats& stats)
{
  std::string per_tool_summary;
  for (const auto& [tool_name, invocation_count] : stats.invocations_by_tool)
  {
    if (!per_tool_summary.empty())
    {
      per_tool_summary += ", ";
    }
    per_tool_summary += tool_name + " x" + std::to_string(invocation_count);
  }
  spdlog::info("recorded {} tool invocations ({})", stats.total_lines - stats.malformed_lines,
               per_tool_summary.empty() ? std::string("none") : per_tool_summary);
}

}  // namespace

CLI::App* register_observe_command(CLI::App& application, ObserveOptions& options)
{
  CLI::App* observe_command = application.add_subcommand("observe", kObserveDescription);
  // Everything after `--` lands here as positionals. It is passed to the
  // operating system as an argv vector and never to a shell, so a repo cannot
  // inject a word, expand a glob or chain a second command (rule 9's intent).
  observe_command
      ->add_option("command", options.build_command,
                   "The build command to run, after `--` (e.g. -- cmake --build build)")
      ->required();
  observe_command
      ->add_option("--trace", options.trace_path,
                   "Where to write the JSONL trace; each run starts a fresh file")
      ->default_val(kDefaultTracePath)
      ->capture_default_str();
  // An early design sketched `--keep-shims` back when the shim directory was a
  // per-run temp dir. It now persists by design: that is what keeps a CMake
  // cache configured under observe valid, and the shims are inert without
  // BOMWERK_TRACE: so removal is the option worth spelling.
  observe_command->add_flag("--clean-shims", options.clean_shims,
                            "Delete the shim directory when the build finishes (debug); a build "
                            "tree configured under observe must then be reconfigured");
  return observe_command;
}

int run_observe(const ObserveOptions& options)
{
  if (options.build_command.empty())
  {
    spdlog::error("no build command given, try: bomwerk observe -- cmake --build build");
    return core::kExitIncomplete;
  }

  const fs::path shim_binary_path = observe::locate_shim_binary();
  if (shim_binary_path.empty())
  {
    spdlog::error("cannot locate the bomwerk-shim executable; set BOMWERK_SHIM_BINARY to its path");
    return core::kExitIncomplete;
  }

  if (!reset_trace_file(options.trace_path))
  {
    return core::kExitIncomplete;
  }

  WarningRecorder recorder;
  const char* search_path = std::getenv("PATH");
  core::Result<observe::ShimSetup> shim_setup =
      observe::prepare_shim_directory(kDefaultShimDirectory, shim_binary_path, options.trace_path,
                                      search_path != nullptr ? search_path : "");
  recorder.record_all(shim_setup.warnings);
  if (!shim_setup.complete)
  {
    spdlog::error("could not prepare the compiler shims, nothing was observed");
    return core::kExitIncomplete;
  }

  spdlog::info("shimming {} tools from {}", shim_setup.value.shimmed_tool_names.size(),
               shim_setup.value.shim_directory.string());
  observe::apply_environment_overlay(shim_setup.value.environment_overlay);

  const observe::BuildOutcome build_outcome = observe::run_build_command(options.build_command);

  if (options.clean_shims)
  {
    remove_shim_directory(shim_setup.value.shim_directory);
  }

  if (!build_outcome.started)
  {
    spdlog::error("{}", build_outcome.failure_detail);
    return core::kExitIncomplete;
  }

  // The trace is worth validating even when the build failed: a partial trace
  // still says what got as far as compiling.
  core::Result<observe::TraceStats> trace_stats =
      observe::validate_and_sort_trace(shim_setup.value.trace_path);
  recorder.record_all(trace_stats.warnings);
  log_trace_summary(trace_stats.value);
  spdlog::info("trace written to {}", shim_setup.value.trace_path.string());

  if (build_outcome.terminating_signal != 0)
  {
    spdlog::error("the build was killed by signal {}", build_outcome.terminating_signal);
    return core::kExitIncomplete;
  }
  if (build_outcome.exit_status != 0)
  {
    // Exit codes are a contract (rule 2), so the child's own code cannot be
    // passed through; a failed build is an incomplete observation. The real
    // code is logged so CI logs still show it.
    spdlog::error("the build command exited {}, observation is incomplete",
                  build_outcome.exit_status);
    return core::kExitIncomplete;
  }

  const std::size_t usable_lines =
      trace_stats.value.total_lines - trace_stats.value.malformed_lines;
  if (usable_lines == 0)
  {
    recorder.record(core::WarningCode::kObserveNoCompilerInvocations, kEmptyTraceExplanation);
  }

  return recorder.degraded() ? core::kExitCompletedWithWarnings : core::kExitClean;
}

}  // namespace bomwerk::cli
