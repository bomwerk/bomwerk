#pragma once
#include <CLI/CLI.hpp>
#include <filesystem>

namespace bomwerk::cli
{

/// User-facing options of `bomwerk binscan`.
struct BinscanOptions
{
  std::filesystem::path sbom_path;       ///< positional: the CycloneDX document to enrich
  std::filesystem::path trace_path;      ///< --trace; default `.bomwerk/trace.jsonl`
  std::filesystem::path root_directory;  ///< --root: the repo the SBOM describes; default `.`
  std::filesystem::path sidecar_path;    ///< --sidecar; default `.bomwerk/binscan.json`
  std::filesystem::path output_path;     ///< -o/--output: empty => report only, write no SBOM
  bool no_sidecar = false;               ///< --no-sidecar: report only, store no sample
  bool quiet = false;                    ///< -q/--quiet: skip the per-artifact listing
  bool all_cpes = false;  ///< --all-cpes: synthesize CPEs for every safely convertible
                          ///< versioned component (see cli/scan_command.hpp); requires
                          ///< --output, since a report-only run has nowhere to publish them
};

/// Register the `binscan` subcommand on `application`. `options` receives the
/// parsed values and must outlive parsing. Returns the subcommand pointer so
/// main() can dispatch on `->parsed()`.
CLI::App* register_binscan_command(CLI::App& application, BinscanOptions& options);

/// Open the binaries a recorded build produced, attribute their dynamic
/// dependencies and archive contents to the SBOM's components as
/// `core::Source::Binary` evidence, and store the symbol sample. Returns an
/// exit code per core/exit_codes.hpp; never throws.
int run_binscan(const BinscanOptions& options);

}  // namespace bomwerk::cli
