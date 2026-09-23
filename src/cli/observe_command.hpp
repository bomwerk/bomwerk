#pragma once
#include <CLI/CLI.hpp>
#include <filesystem>
#include <string>
#include <vector>

namespace bomwerk::cli
{

/// User-facing options of `bomwerk observe`.
struct ObserveOptions
{
  std::vector<std::string> build_command;  ///< everything after `--`; never shell-interpreted
  std::filesystem::path trace_path;        ///< --trace; default `.bomwerk/trace.jsonl`
  bool clean_shims = false;                ///< --clean-shims: remove the shim directory afterwards
};

/// Register the `observe` subcommand on `application`. `options` receives the
/// parsed values and must outlive parsing. Returns the subcommand pointer so
/// main() can dispatch on `->parsed()`.
CLI::App* register_observe_command(CLI::App& application, ObserveOptions& options);

/// Run the wrapped build under the shims and write the trace. Returns an exit
/// code per core/exit_codes.hpp; never throws.
int run_observe(const ObserveOptions& options);

}  // namespace bomwerk::cli
