#pragma once
#include <CLI/CLI.hpp>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "core/exit_codes.hpp"
#include "core/model.hpp"
#include "core/sbom_format.hpp"
#include "core/scan_limits.hpp"

namespace bomwerk::cli
{

/// User-facing options of `bomwerk scan`, bound to CLI11 flags by
/// register_scan_command(). Defaults here are the documented defaults.
/// A bomwerk.toml at the scanned root (or --config) fills the fields the
/// command line left untouched: run_scan() merges it with CLI-beats-config
/// precedence, tracked per flag in `cli_provided`.
struct ScanOptions
{
  /// Which flags the user actually typed, set by register_scan_command()'s
  /// per-option callbacks. The merge only lets bomwerk.toml fill a field
  /// whose flag is false here, so an explicit flag always wins.
  struct CliProvided
  {
    bool output_path = false;
    bool format = false;
    bool spdx_version = false;
    bool html_report_path = false;
    bool report_config_path = false;
    bool coverage_path = false;
    bool warnings_path = false;
    bool manifest_list_path = false;
    bool exclude_list_path = false;
    bool scan_all_directories = false;
    bool include_submodule_contents = false;
    bool max_packages = false;
    bool product_id = false;
    bool product_version = false;
  };

  std::filesystem::path root_directory = ".";
  std::filesystem::path output_path = "sbom.cdx.json";
  bool quiet = false;  ///< -q/--quiet: skip the per-component console listing (every
                       ///< summary line: coverage, manifest files found, vulnerabilities :
                       ///< still prints); the SBOM file at output_path is unaffected
  core::SbomFormat format = core::SbomFormat::CycloneDx;
  core::SpdxVersion spdx_version =
      core::SpdxVersion::V3_0;               ///< --spdx-version; only for --format spdx
  std::filesystem::path html_report_path;    ///< --html: empty => no HTML report
  std::filesystem::path report_config_path;  ///< --report-config: empty => no report branding
  std::filesystem::path coverage_path;       ///< --coverage: empty => no coverage file
  std::filesystem::path warnings_path;       ///< --warnings: empty => no machine-readable
                                             ///< warnings manifest
  std::filesystem::path trace_path;          ///< --trace: empty => auto-detect build trace
  std::filesystem::path manifest_list_path;  ///< empty => built-in list
  std::filesystem::path exclude_list_path;   ///< empty => built-in list
  bool scan_all_directories = false;         ///< --all: skip directory exclusions entirely
  bool include_submodule_contents = false;   ///< --include-submodule-contents: walk into submodule
                                             ///< working trees instead of reporting each as one
                                             ///< pinned component
  std::size_t max_packages = core::kDefaultMaxPackagesPerEcosystem;  ///< --max-packages: package
                                                                     ///< entries per ecosystem
  std::size_t max_files =
      core::kDefaultMaxScannedFilesPerEcosystem;  ///< --max-files: manifest/lockfile files
                                                  ///< scanned per producer (CLI-only, no
                                                  ///< bomwerk.toml counterpart)
  std::filesystem::path conan_graph_path;         ///< empty => no --conan-graph ingestion
  core::ReleaseMeta release_meta;  ///< --product/--product-version; empty product_id => omitted
  bool vuln_enabled = true;        ///< --vuln/--no-vuln: OSV match on/off
  bool offline = false;            ///< --offline: network enrichments use cache only
  core::FailOnThreshold fail_on = core::FailOnThreshold::Warnings;  ///< --fail-on: which
                                                                    ///< outcomes exit non-zero.
                                                                    ///< CLI-only, deliberately not
                                                                    ///< bomwerk.toml-configurable :
                                                                    ///< same reasoning as
                                                                    ///< --vuln/--offline: the repo
                                                                    ///< under audit must not be
                                                                    ///< able to silence its own
                                                                    ///< audit.
  bool license_fallback = false;  ///< --license-fallback: query crates.io, PyPI and
                                  ///< RubyGems for missing component licenses. Opt-in,
                                  ///< cached, and independent of vulnerability matching.
  std::uint64_t license_fallback_timeout_seconds = 0;  ///< --license-fallback-timeout:
                                                       ///< stop registry lookups after N
                                                       ///< seconds, keep the SBOM as-is. 0
                                                       ///< with license_fallback_timeout_given
                                                       ///< == false means unbounded.
  bool license_fallback_timeout_given = false;         ///< true when --license-fallback-timeout was
                                                       ///< typed; 0 is a meaningful value ("fetch
                                                       ///< nothing beyond cache").
  std::uint64_t license_cache_max_age_seconds = 0;     ///< --license-cache-max-age:
                                                       ///< override how long a cached registry
                                                       ///< license answer stays fresh, in
                                                       ///< seconds. 0 with
                                                       ///< license_cache_max_age_given == false
                                                       ///< means "use the module's own default".
  bool license_cache_max_age_given = false;  ///< true when --license-cache-max-age was typed;
                                             ///< 0 is meaningful ("always refetch").
  bool cpe_fallback = false;                 ///< --cpe-fallback: additionally query NVD by CPE for
                                             ///< components no OSV ecosystem covers. Opt-in: it
  ///< reaches a second host and NVD's rate limit makes an
  ///< uncached run slow. Findings are lower-confidence.
  bool all_cpes = false;              ///< --all-cpes: synthesize CPEs for every safely
                                      ///< convertible versioned component, not just types with
                                      ///< no OSV ecosystem mapping (adds npm, Go, commit-pinned,
                                      ///< ...); each synthesized identifier is marked
                                      ///< bomwerk:cpe-provenance=wildcard-vendor-guess.
                                      ///< CycloneDX only: rejected with --format spdx.
                                      ///< Independent of --cpe-fallback, which controls NVD
                                      ///< network matching, not what this SBOM publishes.
                                      ///< Deliberately not bomwerk.toml-configurable, same
                                      ///< reason as --cpe-fallback above.
  std::filesystem::path config_path;  ///< --config: explicit bomwerk.toml; empty => auto-discover
  bool load_repo_config = true;       ///< --no-config sets false: ignore any repo bomwerk.toml
  std::vector<std::filesystem::path> include_paths;  ///< bomwerk.toml [scan] include (config-only)
  std::vector<std::filesystem::path> exclude_paths;  ///< bomwerk.toml [scan] exclude (config-only)
  std::set<std::string> manifest_names;      ///< bomwerk.toml [scan] manifest_names (config-only)
  std::set<std::string> excluded_dir_names;  ///< bomwerk.toml [scan] exclude_dir_names
                                             ///< (config-only)
  core::CraMetadata cra_metadata;            ///< bomwerk.toml [cra] (config-only): drives
                                             ///< metadata.manufacturer and the .cra.json sidecar
  std::set<std::string> suppressed_warning_codes;  ///< bomwerk.toml [warnings] suppress
                                                   ///< (config-only); bare codes or
                                                   ///< CODE:ecosystem pairs
  CliProvided cli_provided;                        ///< see CliProvided
};

/// Register the `scan` subcommand on `application`. `options` receives the
/// parsed values and must outlive parsing. Returns the subcommand pointer so
/// main() can dispatch on `->parsed()`.
CLI::App* register_scan_command(CLI::App& application, ScanOptions& options);

/// Execute a scan. Merges a repo-level bomwerk.toml (auto-discovered at
/// the scanned root, or --config) into `options` first: an explicitly typed
/// CLI flag always wins. Returns an exit code per core/exit_codes.hpp,
/// remapped through `options.fail_on` as the very last step; never
/// throws.
int run_scan(const ScanOptions& options);

}  // namespace bomwerk::cli
