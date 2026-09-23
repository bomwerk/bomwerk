#pragma once
#include <CLI/CLI.hpp>
#include <filesystem>

namespace bomwerk::cli
{

/// User-facing options of `bomwerk trim`.
struct TrimOptions
{
  std::filesystem::path sbom_path;         ///< positional: the CycloneDX document to judge
  std::filesystem::path trace_path;        ///< --trace; default `.bomwerk/trace.jsonl`
  std::filesystem::path root_directory;    ///< --root: the repo the SBOM describes; default `.`
  std::filesystem::path output_path;       ///< -o/--output: empty => report only, write nothing
  std::filesystem::path html_report_path;  ///< --html: empty => no HTML report
  bool quiet = false;                      ///< -q/--quiet: skip the per-component listing
  bool all_cpes = false;  ///< --all-cpes: synthesize CPEs for every safely convertible
                          ///< versioned component (see cli/scan_command.hpp); requires
                          ///< --output, since a report-only run has nowhere to publish them
};

/// Register the `trim` subcommand on `application`. `options` receives the
/// parsed values and must outlive parsing. Returns the subcommand pointer so
/// main() can dispatch on `->parsed()`.
CLI::App* register_trim_command(CLI::App& application, TrimOptions& options);

/// Map a build trace onto an SBOM's components and report which of them the
/// build actually used. Returns an exit code per core/exit_codes.hpp; never
/// throws.
int run_trim(const TrimOptions& options);

}  // namespace bomwerk::cli
