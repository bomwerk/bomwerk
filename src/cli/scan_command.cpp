#include "cli/scan_command.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "cli/app.hpp"
#include "cli/observe_trim.hpp"
#include "cli/warning_recorder.hpp"
#include "core/cvss.hpp"
#include "core/exclusions.hpp"
#include "core/exit_codes.hpp"
#include "core/file_index.hpp"
#include "core/joining_thread.hpp"
#include "core/manifest_names.hpp"
#include "core/match_coverage.hpp"
#include "core/model.hpp"
#include "core/scan_config.hpp"
#include "core/submodule_paths.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "heuristics/vendored_cpp.hpp"
#include "output/coverage.hpp"
#include "output/cra_sidecar.hpp"
#include "output/cyclonedx.hpp"
#include "output/html.hpp"
#include "output/spdx.hpp"
#include "output/warnings_report.hpp"
#include "parsers/ci/github_actions.hpp"
#include "parsers/cpp/cmake_deps.hpp"
#include "parsers/cpp/conan.hpp"
#include "parsers/cpp/submodules.hpp"
#include "parsers/cpp/vcpkg.hpp"
#include "parsers/lockfiles/cargo.hpp"
#include "parsers/lockfiles/composer.hpp"
#include "parsers/lockfiles/go.hpp"
#include "parsers/lockfiles/maven.hpp"
#include "parsers/lockfiles/npm.hpp"
#include "parsers/lockfiles/nuget.hpp"
#include "parsers/lockfiles/pnpm.hpp"
#include "parsers/lockfiles/pub.hpp"
#include "parsers/lockfiles/python.hpp"
#include "parsers/lockfiles/rubygems.hpp"
#include "parsers/lockfiles/yarn.hpp"
#include "vuln/cpe.hpp"
#include "vuln/finding.hpp"
#include "vuln/http_curl.hpp"
#include "vuln/license_enrichment.hpp"
#include "vuln/nvd.hpp"
#include "vuln/osv.hpp"

namespace fs = std::filesystem;

namespace bomwerk::cli
{
namespace
{

/// How many manifest paths to list before collapsing into "… and N more".
constexpr std::size_t kMaxListedManifests = 20;

/// Column width every top-level "label: value" summary line aligns its label
/// to: the length of the longest one, "vulnerabilities:" (16 characters
/// including the colon). A narrower width was tried and rejected: below 16,
/// "submodules:", "components:" and "coverage-file:" also exceed it and print
/// unpadded, producing a table that is mostly aligned with a few conspicuous
/// exceptions, worse than either full alignment or none. `%-*s` reads this as
/// a runtime width so every site stays in sync if a label's length changes.
constexpr int kSummaryLabelWidth = 16;

/// Construct one lockfile parser's options with the resolved per-ecosystem
/// package budget and scanned-file budget while preserving every other
/// producer-specific default.
template <typename ParseOptions>
ParseOptions lockfile_parse_options(std::size_t max_packages, std::size_t max_files)
{
  ParseOptions options;
  options.max_total_packages = max_packages;
  options.max_scanned_files = max_files;
  return options;
}

/// Construct one non-lockfile producer's options/limits with the resolved
/// scanned-file budget while preserving every other producer-specific
/// default. Works for both a `ParseOptions` (vcpkg, conan, github_actions)
/// and a `ParseLimits` (cmake_deps) since both simply carry a
/// `max_scanned_files` member.
template <typename Options>
Options parse_options_with_max_scanned_files(std::size_t max_files)
{
  Options options;
  options.max_scanned_files = max_files;
  return options;
}

/// Fold a loaded bomwerk.toml into the parsed command line, field by
/// field, with CLI-beats-config precedence (`cli_provided`). Pure: the loader
/// already validated and warned about every value, so this only copies and :
/// for the output/html/report paths: resolves against the scanned root,
/// which confines every config-driven write to the tree being scanned
/// (the loader guarantees the paths are relative with no "..").
ScanOptions apply_repo_config(const ScanOptions& parsed_options,
                              const core::ScanConfig& repo_config)
{
  ScanOptions merged_options = parsed_options;
  if (!parsed_options.cli_provided.format && repo_config.format.has_value())
  {
    merged_options.format = *repo_config.format;
  }
  if (!parsed_options.cli_provided.spdx_version && repo_config.spdx_version.has_value())
  {
    merged_options.spdx_version = *repo_config.spdx_version;
  }
  if (!parsed_options.cli_provided.output_path && !repo_config.output_path.empty())
  {
    merged_options.output_path =
        (parsed_options.root_directory / repo_config.output_path).lexically_normal();
  }
  if (!parsed_options.cli_provided.html_report_path && !repo_config.html_report_path.empty())
  {
    merged_options.html_report_path =
        (parsed_options.root_directory / repo_config.html_report_path).lexically_normal();
  }
  if (!parsed_options.cli_provided.report_config_path && !repo_config.report_config_path.empty())
  {
    merged_options.report_config_path =
        (parsed_options.root_directory / repo_config.report_config_path).lexically_normal();
  }
  if (!parsed_options.cli_provided.coverage_path && !repo_config.coverage_path.empty())
  {
    merged_options.coverage_path =
        (parsed_options.root_directory / repo_config.coverage_path).lexically_normal();
  }
  if (!parsed_options.cli_provided.scan_all_directories &&
      repo_config.scan_all_directories.has_value())
  {
    merged_options.scan_all_directories = *repo_config.scan_all_directories;
  }
  if (!parsed_options.cli_provided.include_submodule_contents &&
      repo_config.include_submodule_contents.has_value())
  {
    merged_options.include_submodule_contents = *repo_config.include_submodule_contents;
  }
  if (!parsed_options.cli_provided.max_packages && repo_config.max_packages.has_value())
  {
    merged_options.max_packages = *repo_config.max_packages;
  }
  // An explicit --manifest-list/--exclude-list keeps naming a file; the config
  // carries its lists inline instead (the config file supersedes those side files).
  if (!parsed_options.cli_provided.manifest_list_path)
  {
    merged_options.manifest_names = repo_config.manifest_names;
  }
  if (!parsed_options.cli_provided.exclude_list_path)
  {
    merged_options.excluded_dir_names = repo_config.excluded_dir_names;
  }
  if (!parsed_options.cli_provided.product_id && !repo_config.product_id.empty())
  {
    merged_options.release_meta.product_id = repo_config.product_id;
  }
  if (!parsed_options.cli_provided.product_version && !repo_config.product_version.empty())
  {
    merged_options.release_meta.version = repo_config.product_version;
  }
  // Include/exclude subtrees have no CLI flag today: the config is their only
  // source, so there is no cli_provided guard here (unlike every field
  // above): if a --include-path/--exclude-path flag is ever added, it needs
  // one too, following the same pattern as the fields above it. A "." entry
  // naming the whole tree is already rejected with a warning by
  // core::load_scan_config (core/scan_config.cpp's read_subtree_array), so
  // both lists here only ever contain meaningful subtree entries.
  merged_options.exclude_paths = repo_config.exclude_paths;
  merged_options.include_paths = repo_config.include_paths;
  // No CLI flag exists for any [cra] field: bomwerk.toml is its only
  // source, same as include/exclude subtrees above.
  merged_options.cra_metadata = repo_config.cra_metadata;
  // [warnings] suppress has no CLI flag either: same reasoning.
  merged_options.suppressed_warning_codes = repo_config.suppressed_warning_codes;
  return merged_options;
}

}  // namespace

CLI::App* register_scan_command(CLI::App& application, ScanOptions& options)
{
  CLI::App* scan_command =
      application.add_subcommand("scan", "Scan a directory and report the components it declares.");
  scan_command->add_option("dir", options.root_directory, "Directory to scan")
      ->default_val(".")
      ->check(CLI::ExistingDirectory);
  // The ->each() callbacks below record which flags the user actually typed:
  // The merge lets a repo's bomwerk.toml fill only the fields the command line left
  // untouched, so given-ness (not the value) is what precedence needs. each()
  // fires once per parsed occurrence and never for a default.
  scan_command->add_option("-o,--output", options.output_path, "Where to write the SBOM")
      ->default_val("sbom.cdx.json")
      ->capture_default_str()
      ->each([&options](const std::string&) { options.cli_provided.output_path = true; });
  // Console-only: the per-component listing is redundant with the SBOM file
  // and unusable past a few hundred lines. Every summary line (coverage,
  // manifest files found, vulnerabilities) still prints, so piping to a log
  // stays informative: only the itemized inventory is skipped. Deliberately
  // not bomwerk.toml-configurable, same as --offline/--cpe-fallback below:
  // it is a terminal-display choice, not a property of the scan itself.
  scan_command->add_flag("-q,--quiet", options.quiet,
                         "Skip the per-component console listing (summary lines still print)");
  // Bound to the SbomFormat enum: CheckedTransformer rejects anything not in
  // the map, so run_scan() can never see an invalid format.
  static const std::map<std::string, core::SbomFormat> kFormatByName{
      {"cyclonedx", core::SbomFormat::CycloneDx}, {"spdx", core::SbomFormat::Spdx}};
  scan_command->add_option("-f,--format", options.format, "SBOM format")
      ->transform(CLI::CheckedTransformer(kFormatByName, CLI::ignore_case))
      ->option_text("{cyclonedx,spdx} [cyclonedx]")
      ->each([&options](const std::string&) { options.cli_provided.format = true; });
  // SPDX has two live serializations; the version is a separate axis from the
  // format (only read when --format spdx). Bound to the SpdxVersion enum the
  // same way, so run_scan() can never see an invalid version. 3.0.1 (JSON-LD)
  // is the default; 2.3 stays available for consumers not yet on 3.0.
  static const std::map<std::string, core::SpdxVersion> kSpdxVersionByName{
      {"2.3", core::SpdxVersion::V2_3}, {"3.0", core::SpdxVersion::V3_0}};
  scan_command
      ->add_option("--spdx-version", options.spdx_version, "SPDX version (only with -f spdx)")
      ->transform(CLI::CheckedTransformer(kSpdxVersionByName, CLI::ignore_case))
      ->option_text("{2.3,3.0} [3.0]")
      ->each([&options](const std::string&) { options.cli_provided.spdx_version = true; });
  // The report is a second artifact next to the SBOM, not a --format :
  // one scan can emit both (SBOM for machines, report for humans).
  scan_command
      ->add_option("--html", options.html_report_path,
                   "Also write a self-contained HTML report (summary, components, "
                   "vulnerabilities, warnings) to this path")
      ->each([&options](const std::string&) { options.cli_provided.html_report_path = true; });
  // Build evidence is a CLI/runtime input, never repository config. When
  // omitted, run_scan applies the usual BOMWERK_TRACE/root/cwd discovery order.
  scan_command
      ->add_option("--trace", options.trace_path,
                   "Apply an existing build trace before writing the SBOM and HTML report")
      ->check(CLI::ExistingFile);
  scan_command
      ->add_option("--report-config", options.report_config_path,
                   "JSON file with report branding (company_name, contact, footer_note, "
                   "accent_color, logo_path); only used with --html")
      ->check(CLI::ExistingFile)
      ->each([&options](const std::string&) { options.cli_provided.report_config_path = true; });
  // The full per-component match-coverage classification (matched /
  // unmapped-purl-type / unversioned-purl / no-identifier), machine-readable
  //: a third artifact alongside the SBOM and the HTML report.
  scan_command
      ->add_option("--coverage", options.coverage_path,
                   "Also write a machine-readable match-coverage classification "
                   "(matched/unmapped-purl-type/unversioned-purl/no-identifier per component) "
                   "to this path")
      ->each([&options](const std::string&) { options.cli_provided.coverage_path = true; });
  // a deterministic, deduplicated manifest of every warning the run produced (code,
  // ecosystem, message, count, affected paths, suppressed), for CI diffing and per-code
  // triage: a third diagnostic sidecar alongside --coverage and the HTML report.
  scan_command
      ->add_option("--warnings", options.warnings_path,
                   "Also write a machine-readable manifest of every warning this run produced "
                   "(code, ecosystem, message, count, affected paths) to this path")
      ->each([&options](const std::string&) { options.cli_provided.warnings_path = true; });
  scan_command
      ->add_option("-m,--manifest-list", options.manifest_list_path,
                   "File listing manifest filenames to look for (one per line, '#' comments); "
                   "replaces the built-in list")
      ->check(CLI::ExistingFile)
      ->each([&options](const std::string&) { options.cli_provided.manifest_list_path = true; });
  scan_command
      ->add_option("-e,--exclude-list", options.exclude_list_path,
                   "File listing directory names to skip (one per line, '#' comments); "
                   "replaces the built-in list")
      ->check(CLI::ExistingFile)
      ->each([&options](const std::string&) { options.cli_provided.exclude_list_path = true; });
  scan_command
      ->add_flag("-A,--all", options.scan_all_directories,
                 "Scan every directory, ignoring both the built-in and --exclude-list")
      ->each([&options](const std::string&) { options.cli_provided.scan_all_directories = true; });
  scan_command
      ->add_option("--max-packages", options.max_packages,
                   "Maximum package entries to parse per lockfile ecosystem")
      ->check(CLI::PositiveNumber)
      ->capture_default_str()
      ->each([&options](const std::string&) { options.cli_provided.max_packages = true; });
  // CLI-only, deliberately: unlike --max-packages, this has no bomwerk.toml counterpart (the
  // repo under audit has no legitimate reason to constrain how thoroughly it is read) and so
  // needs no cli_provided tracking, matching --offline/--cpe-fallback/--trace below.
  scan_command
      ->add_option("--max-files", options.max_files,
                   "Maximum manifest/lockfile files to scan per producer, per ecosystem")
      ->check(CLI::PositiveNumber)
      ->capture_default_str();
  // A submodule is worth ONE pinned component, so the walk skips its
  // contents by default. Deliberately a separate axis from --all, which lifts
  // only the NAME-based exclusions (see the note above build_file_index in
  // run_scan): --all does not imply this, and this does not imply --all.
  scan_command
      ->add_flag("--include-submodule-contents", options.include_submodule_contents,
                 "Walk into git submodule working trees instead of reporting each "
                 "submodule as one pinned component")
      ->each([&options](const std::string&)
             { options.cli_provided.include_submodule_contents = true; });
  scan_command
      ->add_option("--conan-graph", options.conan_graph_path,
                   "JSON written by `conan graph info . --format=json` (run by you or CI); "
                   "bomwerk reads the file and never runs conan itself")
      ->check(CLI::ExistingFile);
  scan_command
      ->add_option("--product", options.release_meta.product_id,
                   "Product identifier this SBOM describes, recorded in the output's "
                   "metadata.component")
      ->each([&options](const std::string&) { options.cli_provided.product_id = true; });
  scan_command
      ->add_option("--product-version", options.release_meta.version,
                   "Product version corresponding to --product")
      ->each([&options](const std::string&) { options.cli_provided.product_version = true; });
  // OSV matching is on by default; --offline restricts it to
  // the local cache. Findings are results, not warnings: they never change
  // the exit code; network/cache trouble does (=> exit 1). Deliberately not
  // configurable from bomwerk.toml (see core/scan_config.hpp): the repo under
  // audit must not switch off its own audit.
  scan_command->add_flag("--vuln,!--no-vuln", options.vuln_enabled,
                         "Match components against OSV vulnerability data");
  scan_command->add_flag("--offline", options.offline,
                         "Use cached network-enrichment data only; make no network requests");
  // an operator, not the repo under audit, decides which outcomes fail CI. This changes
  // only the returned exit code (core/exit_codes.hpp::apply_fail_on_threshold): the SBOM, the
  // warnings printed to stderr, and every other artifact are unaffected. Deliberately not
  // bomwerk.toml-configurable, same reasoning as --vuln/--offline above.
  static const std::map<std::string, core::FailOnThreshold> kFailOnByName{
      {"none", core::FailOnThreshold::None},
      {"warnings", core::FailOnThreshold::Warnings},
      {"incomplete", core::FailOnThreshold::Incomplete}};
  scan_command
      ->add_option("--fail-on", options.fail_on,
                   "Which outcomes exit non-zero: none never fails, warnings (default) fails on "
                   "any warning, incomplete fails only on a genuinely incomplete scan")
      ->transform(CLI::CheckedTransformer(kFailOnByName, CLI::ignore_case))
      ->option_text("{none,warnings,incomplete} [warnings]");
  // Opt-in registry enrichment. Package identity still comes entirely
  // from local scan evidence; only an empty license field may be filled.
  // Invocation-time only: a repository under audit must not make the scanner
  // contact additional hosts through its own bomwerk.toml.
  scan_command->add_flag(
      "--license-fallback", options.license_fallback,
      "Fill missing Cargo/PyPI/RubyGems licenses from their public registries (cached)");
  // a bare boolean --license-fallback had no timeout, so a large, cold
  // cargo corpus could run for tens of minutes with no way to cap it. 0 (the
  // default) stays unbounded, matching --license-fallback's behavior before
  // this flag existed. CLI-only, same reasoning as --license-fallback above.
  scan_command
      ->add_option("--license-fallback-timeout", options.license_fallback_timeout_seconds,
                   "Stop registry license lookups after N seconds and keep the SBOM as-is "
                   "(0 = unbounded); only --license-fallback enrichment is cut short, never "
                   "the scan itself")
      ->each([&options](const std::string&) { options.license_fallback_timeout_given = true; });
  // exact-version registry license answers are immutable (crates.io/
  // PyPI/RubyGems do not allow mutating a published release), so the module
  // default is now 60 days rather than OSV's 24h cadence -- this override
  // exists for an operator who wants to force a shorter refresh or refetch
  // (0) on a specific run. CLI-only, same reasoning as --license-fallback.
  scan_command
      ->add_option("--license-cache-max-age", options.license_cache_max_age_seconds,
                   "Override how long a cached crates.io/PyPI/RubyGems license answer stays "
                   "fresh, in seconds (default: 60 days -- these answer an exact, immutable "
                   "package version; 0 forces a refresh on every run)")
      ->each([&options](const std::string&) { options.license_cache_max_age_given = true; });
  // Opt-in on purpose. It reaches a SECOND host (NVD, see --endpoints)
  // and NVD's rate limit makes an uncached run slow, so no existing scan
  // changes behavior or gets slower unless the operator asks. Also not
  // configurable from bomwerk.toml, for the same reason as --vuln/--offline.
  scan_command->add_flag("--cpe-fallback", options.cpe_fallback,
                         "Also query NVD by CPE for components no OSV ecosystem covers "
                         "(Conan/vcpkg/generic): lower-confidence findings");
  // Opt-in on purpose, same reasoning as --cpe-fallback above: a plain scan's
  // SBOM bytes must not change unless the operator asks. Independent of
  // --cpe-fallback -- this controls what the SBOM PUBLISHES, not whether NVD
  // is queried over the network. CycloneDX only (validated below, once
  // bomwerk.toml has had its say on --format) since SPDX has no property
  // taxonomy to carry the provenance marker.
  scan_command->add_flag(
      "--all-cpes", options.all_cpes,
      "Synthesize CPE identifiers for every safely convertible versioned component, not just "
      "types with no OSV ecosystem mapping (adds npm, Go, commit-pinned, ...); CycloneDX only. "
      "Each synthesized identifier is marked bomwerk:cpe-provenance=wildcard-vendor-guess.");
  // Repo-level scan config. Without either flag, <dir>/bomwerk.toml is
  // auto-discovered; --config points at an explicit file, --no-config refuses
  // the repo's file entirely (e.g. when scanning untrusted code). Combining
  // them is contradictory, so CLI11 rejects it at parse time.
  CLI::Option* config_option =
      scan_command
          ->add_option("--config", options.config_path,
                       "Scan config file (TOML; default: bomwerk.toml in the scanned directory)")
          ->check(CLI::ExistingFile);
  CLI::Option* no_config_flag = scan_command->add_flag_callback(
      "--no-config", [&options]() { options.load_repo_config = false; },
      "Ignore any bomwerk.toml in the scanned directory");
  config_option->excludes(no_config_flag);
  return scan_command;
}

namespace
{

// The exit code run_scan() would return before the --fail-on remap is applied. Every early
// `return core::kExitIncomplete;`/`kExitCompletedWithWarnings` composition below is exactly what
// existed before --fail-on: the remap happens once, at run_scan()'s single call site below,
// rather than at each of these return statements.
int run_scan_ignoring_fail_on(const ScanOptions& parsed_options)
{
  // Printed before anything else in the function can warn: every producer
  // below logs through spdlog (stderr, flushed as each warning happens),
  // while the rest of this function's stdout summary is only printed once,
  // in one burst, at the very end. Without this line first, a scan that hits
  // early warnings shows them before the program has said who it is.
  std::printf("bomwerk %s, scanning %s\n", version(),
              parsed_options.root_directory.string().c_str());

  bool lockfile_scan_complete = true;

  // The HTML report replays every warning the run produced (including suppressed
  // ones: suppression only affects the exit code), so warnings are collected as well as
  // logged; one path keeps log, report and the --warnings manifest in sync.
  WarningRecorder warning_recorder(parsed_options.suppressed_warning_codes);
  const auto record_warning =
      [&warning_recorder](core::WarningCode code, std::string message, std::string ecosystem = {})
  { warning_recorder.record(code, std::move(message), std::move(ecosystem)); };
  const auto record_warnings = [&warning_recorder](const std::vector<core::Warning>& warnings)
  { warning_recorder.record_all(warnings); };

  std::error_code walk_error;
  if (!fs::is_directory(parsed_options.root_directory, walk_error))
  {
    spdlog::error("not a directory: {}", parsed_options.root_directory.string());
    return core::kExitIncomplete;
  }

  // Repo-level scan config, loaded before anything else so everything
  // below sees the merged (CLI-beats-config) view. The file lives inside the
  // scanned repo, i.e. it is untrusted input: loading is bounded and no-throw
  // (rule 1), its paths are confined to the scanned tree, and the vuln
  // toggles are not configurable from it (see core/scan_config.hpp). A broken
  // config degrades the run to exit 1: silently scanning with defaults the
  // author did not choose would be worse than a loud warning.
  core::Result<core::ScanConfig> repo_config;
  std::string repo_config_display;  // what the summary prints; empty => no config loaded
  if (!parsed_options.config_path.empty())
  {
    repo_config = core::load_scan_config(parsed_options.config_path);
    repo_config_display = parsed_options.config_path.string();
  }
  else if (parsed_options.load_repo_config)
  {
    const fs::path discovered_config = parsed_options.root_directory / core::kScanConfigFileName;
    std::error_code config_stat_error;
    if (fs::is_regular_file(discovered_config, config_stat_error) && !config_stat_error)
    {
      repo_config = core::load_scan_config(discovered_config);
      // Root-relative on purpose: stable across machines and temp dirs.
      repo_config_display = core::kScanConfigFileName;
    }
  }
  record_warnings(repo_config.warnings);
  const ScanOptions options = apply_repo_config(parsed_options, repo_config.value);

  // --all-cpes publishes a CycloneDX-only property (component.properties has
  // no SPDX equivalent bomwerk emits into today); reject the combination
  // before any producer runs rather than silently dropping the provenance
  // marker or, worse, the flag itself.
  if (options.all_cpes && options.format != core::SbomFormat::CycloneDx)
  {
    spdlog::error(
        "--all-cpes requires --format cyclonedx (SPDX carries no bomwerk:cpe-provenance field)");
    return core::kExitIncomplete;
  }

  // Producer: git submodules. Each one is reported as a single component
  // pinned to its checked-out commit.
  core::Result<std::vector<core::Component>> submodules =
      parsers::cpp::submodules::parse(options.root_directory);
  record_warnings(submodules.warnings);
  if (!submodules.complete)
  {
    return core::kExitIncomplete;
  }

  // Their contents are then skipped during the file walk below, so a
  // vendored submodule counts as ONE component and not thousands of files (a
  // repo with vcpkg as a submodule otherwise reports ~2,959 components from
  // `vcpkg/ports/*`). The set comes from core::submodule_subtrees rather than
  // from the components above because every producer's standalone
  // parse(root, …) overload consults that same function: one rule, one
  // definition, so a caller that bypasses run_scan cannot silently walk in.
  const std::set<fs::path> submodule_roots = options.include_submodule_contents
                                                 ? std::set<fs::path>{}
                                                 : core::submodule_subtrees(options.root_directory);

  // [scan] include/exclude applies to every producer's output, not just
  // the ones that consume the shared file_index below: submodules::parse
  // reads .gitmodules directly against the whole root and never sees these
  // subtrees otherwise, so its components need the same scope filter applied
  // explicitly here.
  const std::set<fs::path> config_included_subtrees(options.include_paths.begin(),
                                                    options.include_paths.end());
  const std::set<fs::path> config_excluded_subtrees(options.exclude_paths.begin(),
                                                    options.exclude_paths.end());
  submodules.value.erase(
      std::remove_if(
          submodules.value.begin(), submodules.value.end(),
          [&config_excluded_subtrees, &config_included_subtrees](const core::Component& component)
          {
            return !core::path_in_scan_scope(component.root.lexically_normal(),
                                             config_excluded_subtrees, config_included_subtrees);
          }),
      submodules.value.end());

  // Manifest names are runtime-configurable: --manifest-list names a file,
  // bomwerk.toml carries the list inline (CLI wins: see
  // apply_repo_config), and the built-in list is the fallback. Loader
  // warnings degrade the run, never abort it.
  core::Result<std::set<std::string>> manifest_names;
  if (!options.manifest_list_path.empty())
  {
    manifest_names = core::load_manifest_names(options.manifest_list_path);
  }
  else if (!options.manifest_names.empty())
  {
    manifest_names.value = options.manifest_names;
  }
  else
  {
    manifest_names.value = core::default_manifest_names();
  }
  record_warnings(manifest_names.warnings);

  // Excluded directory names are runtime-configurable the same three ways as
  // manifest names above; the built-in list is the fallback. --all skips
  // exclusion entirely, so no load is needed in that case.
  core::Result<std::set<std::string>> excluded_dir_names;
  if (!options.scan_all_directories)
  {
    if (!options.exclude_list_path.empty())
    {
      excluded_dir_names = core::load_excluded_dir_names(options.exclude_list_path);
    }
    else if (!options.excluded_dir_names.empty())
    {
      excluded_dir_names.value = options.excluded_dir_names;
    }
    else
    {
      excluded_dir_names.value = core::default_excluded_dir_names();
    }
    record_warnings(excluded_dir_names.warnings);
  }

  // Single shared walk (rule 3: deterministic: the index is pre-sorted) for
  // every producer that needs "which files exist", plus this function's own
  // file-count/manifest bookkeeping below. --all means no directory-name
  // exclusion at all, matching options.scan_all_directories's existing
  // meaning: excluded_dir_names.value is already empty in that case (see the
  // load above), so passing it through here needs no special-casing. The
  // [scan] exclude subtrees ride the same mechanism as submodule roots; note
  // they apply even under --all, which only lifts the NAME-based exclusions :
  // an explicitly configured path stays excluded.
  std::set<fs::path> excluded_subtrees = submodule_roots;
  excluded_subtrees.insert(config_excluded_subtrees.begin(), config_excluded_subtrees.end());
  const core::Result<core::FileIndex> file_index =
      core::build_file_index(options.root_directory, excluded_dir_names.value, excluded_subtrees,
                             config_included_subtrees);
  record_warnings(file_index.warnings);
  if (!file_index.complete)
  {
    spdlog::error("file index walk failed; cannot continue scanning");
    return core::kExitIncomplete;
  }

  // Producer: CMake FetchContent/CPM dependency declarations, filtered
  // from the shared file_index above instead of walking the tree again :
  // submodule roots and the resolved --exclude-list/--all set are already
  // baked into that index, so cmake_deps now honors both (previously it
  // always used the hardcoded built-in exclusion list, ignoring --all).
  core::Result<std::vector<core::Component>> cmake_dependencies = parsers::cpp::cmake_deps::parse(
      file_index.value, options.root_directory,
      parse_options_with_max_scanned_files<parsers::cpp::cmake_deps::ParseLimits>(
          options.max_files));
  record_warnings(cmake_dependencies.warnings);
  if (!cmake_dependencies.complete)
  {
    return core::kExitIncomplete;
  }

  // Producer: conan manifests (conanfile.txt/.py, conan.lock), filtered
  // from the same shared file_index: bomwerk reads these files and never
  // runs conan or python (rule 9); conan.lock carries conan's own resolved
  // graph, so runtime accuracy needs no execution.
  core::Result<std::vector<core::Component>> conan_dependencies = parsers::cpp::conan::parse(
      file_index.value, options.root_directory,
      parse_options_with_max_scanned_files<parsers::cpp::conan::ParseOptions>(options.max_files));
  record_warnings(conan_dependencies.warnings);
  if (!conan_dependencies.complete)
  {
    return core::kExitIncomplete;
  }

  // Optional runtime-resolved graph the user generated themselves.
  core::Result<std::vector<core::Component>> conan_graph_components;
  if (!options.conan_graph_path.empty())
  {
    conan_graph_components = parsers::cpp::conan::parse_graph_file(
        options.conan_graph_path, parsers::cpp::conan::ParseOptions{});
    record_warnings(conan_graph_components.warnings);
    if (!conan_graph_components.complete)
    {
      return core::kExitIncomplete;
    }
  }

  // Producer: vcpkg manifests (vcpkg.json), filtered from the same shared
  // file_index: bomwerk reads the manifest and never runs vcpkg (rule 9). An
  // `overrides` pin is vcpkg's in-manifest lock; a bare/floored dependency
  // stays Low confidence.
  core::Result<std::vector<core::Component>> vcpkg_dependencies = parsers::cpp::vcpkg::parse(
      file_index.value, options.root_directory,
      parse_options_with_max_scanned_files<parsers::cpp::vcpkg::ParseOptions>(options.max_files));
  record_warnings(vcpkg_dependencies.warnings);
  if (!vcpkg_dependencies.complete)
  {
    return core::kExitIncomplete;
  }

  // GitHub Actions workflow `uses:` references
  // (.github/workflows/*.yml), filtered from the same shared file_index :
  // bomwerk reads the workflow file directly and never shells out to git/gh
  // (rule 9). A SHA-pinned ref is High confidence, a mutable tag/branch is
  // Medium, and a ref (or owner/repo) carrying an unresolved `${{ ... }}`
  // expression degrades to Low confidence with a warning rather than ever
  // leaking `${{` into the purl.
  core::Result<std::vector<core::Component>> github_actions_dependencies =
      parsers::ci::github_actions::parse(
          file_index.value, options.root_directory,
          parse_options_with_max_scanned_files<parsers::ci::github_actions::ParseOptions>(
              options.max_files));
  record_warnings(github_actions_dependencies.warnings);
  if (!github_actions_dependencies.complete)
  {
    return core::kExitIncomplete;
  }

  // Heuristic: vendored C/C++ source with no manifest at all (third_party/
  // thirdparty/vendor/external/deps/libs), filtered from the same shared
  // file_index. Never a manifest, so every component from here is Low/Medium
  // confidence at most (see the vendored-source heuristic).
  core::Result<std::vector<core::Component>> vendored_cpp_dependencies =
      heuristics::vendored_cpp::parse(file_index.value, options.root_directory,
                                      heuristics::vendored_cpp::ParseLimits{});
  record_warnings(vendored_cpp_dependencies.warnings);
  if (!vendored_cpp_dependencies.complete)
  {
    return core::kExitIncomplete;
  }

  // Producer: npm lockfiles (package-lock.json v2/v3), filtered from the
  // same shared file_index: bomwerk reads the lockfile and never runs npm
  // (rule 9). Dev-only packages arrive with CycloneDX scope "excluded".
  core::Result<std::vector<core::Component>> npm_dependencies =
      parsers::lockfiles::npm::parse(file_index.value, options.root_directory,
                                     lockfile_parse_options<parsers::lockfiles::npm::ParseOptions>(
                                         options.max_packages, options.max_files));
  record_warnings(npm_dependencies.warnings);
  if (!npm_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: Python lockfiles (uv.lock, poetry.lock, and the
  // requirements[-_]<name>.txt family), same shared file_index: never runs
  // pip/uv/poetry (rule 9). PEP 503 name normalization merges the same package
  // across lock and requirements files.
  core::Result<std::vector<core::Component>> python_dependencies =
      parsers::lockfiles::python::parse(
          file_index.value, options.root_directory,
          lockfile_parse_options<parsers::lockfiles::python::ParseOptions>(options.max_packages,
                                                                           options.max_files));
  record_warnings(python_dependencies.warnings);
  if (!python_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: Go checksum files (go.sum), same shared file_index: never
  // runs go (rule 9). go.sum is honest-superset evidence; observe (P2)
  // narrows it to what was actually built.
  core::Result<std::vector<core::Component>> go_dependencies =
      parsers::lockfiles::go::parse(file_index.value, options.root_directory,
                                    lockfile_parse_options<parsers::lockfiles::go::ParseOptions>(
                                        options.max_packages, options.max_files));
  record_warnings(go_dependencies.warnings);
  if (!go_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: Rust lockfiles (Cargo.lock), same shared file_index: never
  // runs cargo (rule 9). Workspace members (entries without a source) are
  // first-party and never emitted; a registry checksum becomes the
  // component's sha256.
  core::Result<std::vector<core::Component>> cargo_dependencies = parsers::lockfiles::cargo::parse(
      file_index.value, options.root_directory,
      lockfile_parse_options<parsers::lockfiles::cargo::ParseOptions>(options.max_packages,
                                                                      options.max_files));
  record_warnings(cargo_dependencies.warnings);
  if (!cargo_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: JVM manifests and lockfiles (pom.xml declares -> Medium;
  // gradle.lockfile resolves -> High), same shared file_index: never runs
  // mvn/gradle (rule 9). Test-scoped dependencies arrive with CycloneDX
  // scope "excluded".
  core::Result<std::vector<core::Component>> maven_dependencies = parsers::lockfiles::maven::parse(
      file_index.value, options.root_directory,
      lockfile_parse_options<parsers::lockfiles::maven::ParseOptions>(options.max_packages,
                                                                      options.max_files));
  record_warnings(maven_dependencies.warnings);
  if (!maven_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: .NET lockfiles (packages.lock.json), same shared file_index
  //: never runs dotnet (rule 9). Project references are first-party and
  // never emitted.
  core::Result<std::vector<core::Component>> nuget_dependencies = parsers::lockfiles::nuget::parse(
      file_index.value, options.root_directory,
      lockfile_parse_options<parsers::lockfiles::nuget::ParseOptions>(options.max_packages,
                                                                      options.max_files));
  record_warnings(nuget_dependencies.warnings);
  if (!nuget_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: PHP lockfiles (composer.lock), falling back to
  // composer.json's declared require/require-dev when no sibling lock exists
  //: same shared file_index, never runs composer (rule 9).
  // packages-dev/require-dev entries arrive with CycloneDX scope "excluded".
  core::Result<std::vector<core::Component>> composer_dependencies =
      parsers::lockfiles::composer::parse(
          file_index.value, options.root_directory,
          lockfile_parse_options<parsers::lockfiles::composer::ParseOptions>(options.max_packages,
                                                                             options.max_files));
  record_warnings(composer_dependencies.warnings);
  if (!composer_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: Ruby lockfiles (Gemfile.lock), same shared file_index :
  // never runs bundler (rule 9). PATH gems are first-party and never emitted.
  core::Result<std::vector<core::Component>> rubygems_dependencies =
      parsers::lockfiles::rubygems::parse(
          file_index.value, options.root_directory,
          lockfile_parse_options<parsers::lockfiles::rubygems::ParseOptions>(options.max_packages,
                                                                             options.max_files));
  record_warnings(rubygems_dependencies.warnings);
  if (!rubygems_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: Yarn lockfiles (yarn.lock, Berry and Classic v1), same shared
  // file_index: never runs yarn (rule 9). Identity comes from each Berry
  // entry's `resolution:`, so workspace members are recognized as first-party
  // and never emitted.
  core::Result<std::vector<core::Component>> yarn_dependencies = parsers::lockfiles::yarn::parse(
      file_index.value, options.root_directory,
      lockfile_parse_options<parsers::lockfiles::yarn::ParseOptions>(options.max_packages,
                                                                     options.max_files));
  record_warnings(yarn_dependencies.warnings);
  if (!yarn_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Producer: pnpm lockfiles (pnpm-lock.yaml v6/v9), same shared file_index
  //: never runs pnpm (rule 9). Only the `packages:` section is read: the
  // `snapshots:` section repeats those keys with their resolved peer set
  // appended, and `importers:` names the workspace's own first-party members.
  core::Result<std::vector<core::Component>> pnpm_dependencies = parsers::lockfiles::pnpm::parse(
      file_index.value, options.root_directory,
      lockfile_parse_options<parsers::lockfiles::pnpm::ParseOptions>(options.max_packages,
                                                                     options.max_files));
  record_warnings(pnpm_dependencies.warnings);
  if (!pnpm_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  // Dart/Flutter pubspec.lock: never runs dart/flutter pub (rule 9).
  // hosted/git/sdk sources emit pkg:pub purls; path sources are local
  // workspace dependencies and are skipped silently.
  core::Result<std::vector<core::Component>> pub_dependencies =
      parsers::lockfiles::pub::parse(file_index.value, options.root_directory,
                                     lockfile_parse_options<parsers::lockfiles::pub::ParseOptions>(
                                         options.max_packages, options.max_files));
  record_warnings(pub_dependencies.warnings);
  if (!pub_dependencies.complete)
  {
    lockfile_scan_complete = false;
  }

  std::size_t file_count = file_index.value.files.size();
  std::vector<fs::path> manifest_paths;
  for (const fs::path& relative_path : file_index.value.files)
  {
    const std::string filename = relative_path.filename().string();
    const bool is_manifest =
        std::any_of(manifest_names.value.begin(), manifest_names.value.end(),
                    [&filename](const std::string& manifest_name)
                    { return core::matches_manifest_name(filename, manifest_name); });
    if (is_manifest)
    {
      manifest_paths.push_back(relative_path);
    }
  }
  // file_index.value.files is already sorted; filtering it preserves that
  // order, so manifest_paths needs no separate sort.

  // What bomwerk could NOT read is part of the result. A repo holding a
  // pnpm-lock.yaml we have no parser for must never print "manifest files: 0"
  // and exit clean: that silence is indistinguishable from "no dependencies",
  // which is the one thing an SBOM must never get wrong. Reuses the shared
  // file_index, so this costs no extra walk.
  const std::vector<core::UnparsedManifestReport> unparsed_manifests =
      core::find_unparsed_manifests(file_index.value.files);
  for (const core::UnparsedManifestReport& unparsed : unparsed_manifests)
  {
    const std::string found_clause = unparsed.ecosystem + ": found " + unparsed.filename + " (" +
                                     std::to_string(unparsed.paths.size()) + " file(s)) ";
    if (unparsed.is_lockfile)
    {
      record_warning(core::WarningCode::kManifestUnsupportedLockfile,
                     found_clause + "but bomwerk has no parser for it yet, so " +
                         unparsed.ecosystem + " components are missing from this SBOM",
                     unparsed.ecosystem);
    }
    else
    {
      record_warning(core::WarningCode::kManifestNoLockfileAlongside,
                     found_clause + "with no lockfile alongside: declared version ranges are " +
                         "not resolved versions, so " + unparsed.ecosystem +
                         " components are missing from this SBOM",
                     unparsed.ecosystem);
    }
  }

  std::vector<core::Component> components = std::move(submodules.value);
  components.insert(components.end(), std::make_move_iterator(cmake_dependencies.value.begin()),
                    std::make_move_iterator(cmake_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(conan_dependencies.value.begin()),
                    std::make_move_iterator(conan_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(conan_graph_components.value.begin()),
                    std::make_move_iterator(conan_graph_components.value.end()));
  components.insert(components.end(), std::make_move_iterator(vcpkg_dependencies.value.begin()),
                    std::make_move_iterator(vcpkg_dependencies.value.end()));
  components.insert(components.end(),
                    std::make_move_iterator(github_actions_dependencies.value.begin()),
                    std::make_move_iterator(github_actions_dependencies.value.end()));
  components.insert(components.end(),
                    std::make_move_iterator(vendored_cpp_dependencies.value.begin()),
                    std::make_move_iterator(vendored_cpp_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(npm_dependencies.value.begin()),
                    std::make_move_iterator(npm_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(python_dependencies.value.begin()),
                    std::make_move_iterator(python_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(go_dependencies.value.begin()),
                    std::make_move_iterator(go_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(cargo_dependencies.value.begin()),
                    std::make_move_iterator(cargo_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(maven_dependencies.value.begin()),
                    std::make_move_iterator(maven_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(nuget_dependencies.value.begin()),
                    std::make_move_iterator(nuget_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(composer_dependencies.value.begin()),
                    std::make_move_iterator(composer_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(rubygems_dependencies.value.begin()),
                    std::make_move_iterator(rubygems_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(yarn_dependencies.value.begin()),
                    std::make_move_iterator(yarn_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(pnpm_dependencies.value.begin()),
                    std::make_move_iterator(pnpm_dependencies.value.end()));
  components.insert(components.end(), std::make_move_iterator(pub_dependencies.value.begin()),
                    std::make_move_iterator(pub_dependencies.value.end()));
  components = core::merge_all(std::move(components));

  vuln::LicenseEnrichmentSummary license_enrichment_summary;
  if (options.license_fallback)
  {
    vuln::LicenseEnrichmentOptions license_options;
    license_options.offline = options.offline;
    if (options.license_cache_max_age_given)
    {
      license_options.cache_max_age =
          std::chrono::seconds(static_cast<std::int64_t>(options.license_cache_max_age_seconds));
    }
    if (options.license_fallback_timeout_given)
    {
      license_options.time_budget =
          std::chrono::seconds(static_cast<std::int64_t>(options.license_fallback_timeout_seconds));
    }
    core::Result<vuln::LicenseEnrichmentSummary> enriched_licenses =
        vuln::enrich_component_licenses(
            components, license_options,
            vuln::make_curl_http_get(std::string("bomwerk/") + version()),
            vuln::system_clock_epoch_seconds,
            [](std::chrono::milliseconds interval) { std::this_thread::sleep_for(interval); });
    record_warnings(enriched_licenses.warnings);
    license_enrichment_summary = enriched_licenses.value;
  }

  vuln::populate_cpe_identifiers(components, options.all_cpes
                                                 ? vuln::CpePopulationScope::AllVersioned
                                                 : vuln::CpePopulationScope::UnmappedOnly);

  // Apply observed-build evidence only after merge_all. Merging later
  // would flip an unused verdict back to the model's default true. A missing
  // implicit trace is the normal plain-scan path and stays silent; a trace the
  // operator selected explicitly must be usable or this requested operation is
  // incomplete.
  bool build_trace_applied = false;
  std::optional<fs::path> applied_trace_path;
  ObserveTraceApplication trace_application;
  core::Result<std::optional<fs::path>> resolved_trace_path =
      resolve_scan_trace_path(options.root_directory, options.trace_path);
  record_warnings(resolved_trace_path.warnings);
  if (resolved_trace_path.value.has_value())
  {
    core::Result<ObserveTraceApplication> application =
        apply_observe_trace(*resolved_trace_path.value, options.root_directory, components);
    record_warnings(application.warnings);
    if (!application.complete)
    {
      if (!options.trace_path.empty())
      {
        spdlog::error("no usable records in {}; build usage could not be applied",
                      resolved_trace_path.value->string());
        return core::kExitIncomplete;
      }
      record_warning(core::WarningCode::kObserveAutoDetectedTraceUnusable,
                     "no usable records in auto-detected trace " +
                         resolved_trace_path.value->string() + "; build usage was not applied");
    }
    else
    {
      trace_application = std::move(application.value);
      applied_trace_path = *resolved_trace_path.value;
      build_trace_applied = true;
      if (trace_application.summary.judged == 0)
      {
        record_warning(core::WarningCode::kObserveNoRootedComponents,
                       kNoRootedComponentsExplanation);
      }
    }
  }

  // The "bomwerk <version>" identity line already printed at function entry,
  // before any producer could warn: this is the file count, known only now.
  std::printf("%-*s %zu files under %s\n", kSummaryLabelWidth, "scanned:", file_count,
              options.root_directory.string().c_str());
  // A scan shaped by a repo config must say so: an SBOM whose scope was
  // narrowed by a file the operator never typed should never look like a
  // plain full scan.
  if (!repo_config_display.empty())
  {
    std::printf("%-*s %s\n", kSummaryLabelWidth, "config:", repo_config_display.c_str());
  }
  // A scan that deliberately did not look inside N subtrees must say so,
  // for the same reason as the "no OSV coverage" note further down: what was
  // NOT checked is part of the result. Product output on stdout, not a log
  // (this is scan scope, not program health). Counting the skip set means the
  // line disappears by construction under --include-submodule-contents.
  if (!submodule_roots.empty())
  {
    std::printf(
        "%-*s %zu subtree(s) skipped, each submodule is one pinned component "
        "(--include-submodule-contents to scan their contents)\n",
        kSummaryLabelWidth, "submodules:", submodule_roots.size());
  }
  // The producer list this line used to carry ("from .gitmodules + CMake
  // FetchContent/CPM + conan + ... + rubygems)") was static prose, identical
  // on every run regardless of the repo scanned, and grew by one clause with
  // every new producer (15 and counting): the wrong place for it, since this
  // block reports facts about THIS scan, not what bomwerk is capable of.
  std::printf("%-*s %zu\n", kSummaryLabelWidth, "components:", components.size());
  if (options.license_fallback)
  {
    // rate-limited and timed-out are independent causes and either or
    // both may be nonzero in one run, so each appends its own clause rather
    // than the two competing for one branch.
    std::string enrichment_note;
    if (license_enrichment_summary.rate_limited_components > 0)
    {
      enrichment_note += " (" + std::to_string(license_enrichment_summary.rate_limited_components) +
                         " rate-limited by a registry, rerun to complete)";
    }
    if (license_enrichment_summary.timed_out_components > 0)
    {
      enrichment_note += " (" + std::to_string(license_enrichment_summary.timed_out_components) +
                         " cut short by --license-fallback-timeout, rerun to complete)";
    }
    std::printf("%-*s %zu of %zu candidate component(s) enriched from package registries%s\n",
                kSummaryLabelWidth, "licenses:", license_enrichment_summary.enriched_components,
                license_enrichment_summary.candidate_components, enrichment_note.c_str());
  }
  if (!options.quiet)
  {
    for (const core::Component& component : components)
    {
      std::printf("  - %s  [%s]  %s\n", component.purl.c_str(),
                  core::to_string(core::highest_confidence(component)),
                  component.root.string().c_str());
    }
  }

  if (build_trace_applied)
  {
    std::printf("%-*s %s (%zu compile invocations, %zu source file(s) in this repo)\n",
                kSummaryLabelWidth, "trace:", applied_trace_path->string().c_str(),
                trace_application.compile_map.compile_invocations,
                trace_application.compile_map.compiled_sources.size());
    std::printf("%-*s %zu link invocation(s), %zu unresolved -l<name>\n", kSummaryLabelWidth,
                "links:", trace_application.link_map.link_invocations,
                trace_application.link_map.unresolved_library_names);
    std::printf("%-*s %zu of %zu located components compiled, linked, or included\n",
                kSummaryLabelWidth, "used:", trace_application.summary.used,
                trace_application.summary.judged);
    if (trace_application.summary.not_judgeable > 0)
    {
      std::printf(
          "%-*s %zu component(s) record no location in the repository; a compile trace "
          "cannot speak to them\n",
          kSummaryLabelWidth, "not judged:", trace_application.summary.not_judgeable);
    }
    if (trace_application.compile_map.out_of_tree_sources > 0)
    {
      std::printf("%-*s %zu compiled source(s) lie outside %s\n", kSummaryLabelWidth,
                  "out of tree:", trace_application.compile_map.out_of_tree_sources,
                  options.root_directory.string().c_str());
    }
  }

  // Match-coverage summary line: printed unconditionally, unlike the
  // vulnerabilities block below, since it does not depend on --vuln at all
  // (identifier quality is a fact about the SBOM, not about whether OSV ran).
  // Same predicate the CycloneDX/HTML/coverage-file surfaces use
  // (core::classify_match_coverage), so this number can never disagree with
  // theirs.
  {
    const core::MatchCoverageSummary coverage_summary = core::summarize_match_coverage(components);
    const std::size_t unmatched_component_count =
        coverage_summary.total - coverage_summary.matchable;
    std::printf("%-*s %zu components, %zu matchable", kSummaryLabelWidth,
                "coverage:", coverage_summary.total, coverage_summary.matchable);
    if (coverage_summary.total > 0)
    {
      constexpr std::size_t kPercentageTextBytes = 16;  // "100.0" plus margin, never truncates
      char percentage_text[kPercentageTextBytes];
      std::snprintf(percentage_text, sizeof(percentage_text), "%.1f",
                    (100.0 * static_cast<double>(coverage_summary.matchable)) /
                        static_cast<double>(coverage_summary.total));
      std::printf(" (%s%%)", percentage_text);
    }
    std::printf(", %zu unmatched", unmatched_component_count);
    if (unmatched_component_count > 0)
    {
      std::printf(": %zu unmapped-purl-type, %zu unversioned-purl, %zu no-identifier",
                  coverage_summary.unmapped_purl_type, coverage_summary.unversioned_purl,
                  coverage_summary.no_identifier);
    }
    std::printf("\n");
  }

  // OSV vulnerability match (on by default). Findings are
  // product RESULTS on stdout: a hit never degrades the exit code; only
  // network/cache trouble does. The SBOM file below stays vulnerability-free
  // on purpose: feed data changes daily, SBOM bytes must not (rule 3), and
  // the HTML report is where findings become a document.
  // Declared outside the vuln_enabled block: the HTML report below reads
  // it either way (an empty default simply renders as "nothing found", and
  // the report's own not-checked wording comes from options.vuln_enabled).
  core::Result<vuln::MatchOutcome> vulnerability_matches;
  // Purls OSV structurally cannot check (Conan/vcpkg/generic). Computed once
  // from the public predicate so the stdout note, the report's summary metric,
  // and the report's per-row tags all count the SAME set: the numbers can
  // never disagree (a versioned generic and a version-less vcpkg are both
  // genuinely uncoverable, so both belong here).
  std::vector<std::string> uncovered_osv_purls;
  // The subset of the above that the CPE fallback actually queried against
  // NVD. Derived from the same list, so "checked via CPE" and "not checked"
  // always partition `uncovered_osv_purls` exactly: no component can fall into
  // both or neither.
  std::vector<std::string> cpe_checked_purls;
  if (options.vuln_enabled)
  {
    for (const core::Component& component : components)
    {
      // Calls the same core predicate `vuln::has_no_known_osv_coverage`
      // is now defined in terms of, directly: one fewer indirection between
      // this list and the coverage numbers reported elsewhere.
      if (core::classify_match_coverage(component) == core::MatchCoverage::UnmappedPurlType)
      {
        uncovered_osv_purls.push_back(component.purl);
      }
    }

    // Start the NVD pass FIRST, on its own thread, then run the OSV pass
    // on this one. NVD's rate limit forces ~6 s between uncached requests (or
    // ~0.7 s with an API key), and that waiting is what would otherwise be
    // added to every scan; overlapping it with OSV's round-trips keeps the
    // fallback close to free in wall-clock terms.
    //
    // Threading buys LATENCY, never concurrency against the feed: requests
    // inside match_via_cpe stay strictly sequential and throttled, because
    // NVD's limit is per key, not per connection.
    //
    // Determinism (rule 3) is unaffected: nothing below reads the NVD result
    // before the join, and the two outcomes are folded by vuln::merge_outcomes,
    // which sorts. Which thread finished first cannot reach the output.
    core::Result<vuln::MatchOutcome> cpe_matches;
    std::optional<core::JoiningThread> cpe_fallback_thread;
    if (options.cpe_fallback)
    {
      vuln::NvdOptions nvd_options;
      nvd_options.offline = options.offline;
      // The key is an environment variable, never bomwerk.toml: that file
      // ships inside the repo under audit (core/scan_config.hpp).
      if (const char* api_key = std::getenv(vuln::kNvdApiKeyEnvironmentVariable);
          api_key != nullptr)
      {
        nvd_options.api_key = api_key;
      }
      if (nvd_options.api_key.empty() && !options.offline)
      {
        spdlog::info(
            "vuln: no {} set, so NVD allows only 5 requests per 30 s unauthenticated. The CPE "
            "fallback pauses ~6 s between uncached components",
            vuln::kNvdApiKeyEnvironmentVariable);
      }
      cpe_fallback_thread.emplace(
          [&cpe_matches, &components, nvd_options = std::move(nvd_options)]
          {
            // Belt to match_via_cpe's braces: an exception escaping a thread
            // body is std::terminate, which would break "never crash" (rule 1)
            // far more loudly than any feed problem it could be reporting.
            try
            {
              cpe_matches = vuln::match_via_cpe(
                  components, nvd_options,
                  vuln::make_curl_http_get(std::string("bomwerk/") + version()),
                  vuln::system_clock_epoch_seconds, [](std::chrono::milliseconds interval)
                  { std::this_thread::sleep_for(interval); });
            }
            catch (...)
            {
              cpe_matches = core::Result<vuln::MatchOutcome>{};
              cpe_matches.warn(core::WarningCode::kVulnCoverageIncomplete,
                               "CPE fallback failed unexpectedly: those components not checked");
            }
          });
    }

    vuln::MatchOptions vuln_options;
    vuln_options.offline = options.offline;
    vulnerability_matches = vuln::match_components(
        components, vuln_options, vuln::make_curl_http_post(std::string("bomwerk/") + version()),
        vuln::system_clock_epoch_seconds);

    if (cpe_fallback_thread.has_value())
    {
      cpe_fallback_thread->join();
      cpe_fallback_thread.reset();
      // Warnings are appended in a FIXED order: OSV's first, then NVD's :
      // rather than as each thread produced them, so the report's warning
      // section reads the same on every run (rule 3).
      vulnerability_matches.value = vuln::merge_outcomes(std::move(vulnerability_matches.value),
                                                         std::move(cpe_matches.value));
      for (core::Warning& cpe_warning : cpe_matches.warnings)
      {
        vulnerability_matches.warn(std::move(cpe_warning));
      }
      // A component counts as "checked via CPE" only when the fallback
      // resolved an answer for it; the rest of uncovered_osv_purls stays
      // genuinely unchecked. The list comes from the outcome itself rather
      // than being re-derived here, so it cannot drift from what ran.
      cpe_checked_purls = vulnerability_matches.value.cpe_checked_purls;
    }
    record_warnings(vulnerability_matches.warnings);

    // Naming the feeds keeps the line honest about where the findings came
    // from; without --cpe-fallback the text is byte-identical to before.
    std::printf("%-*s %zu affected component(s) (%s)\n", kSummaryLabelWidth,
                "vulnerabilities:", vulnerability_matches.value.hits.size(),
                options.cpe_fallback ? "OSV + NVD" : "OSV");
    for (const vuln::VulnerabilityHit& hit : vulnerability_matches.value.hits)
    {
      std::string joined_advisories;
      for (const core::ScoredAdvisory& advisory : hit.advisories)
      {
        if (!joined_advisories.empty())
        {
          joined_advisories += ", ";
        }
        joined_advisories += advisory.id;
        // Show the score inline when known: advisories are already worst-first.
        if (advisory.severity.has_score)
        {
          char score_text[32];
          std::snprintf(score_text, sizeof(score_text), " (%.1f %s)", advisory.severity.score,
                        core::to_string(advisory.severity.rating));
          joined_advisories += score_text;
        }
      }
      // A wildcard-vendor CPE match may name a different vendor's product
      // with the same name, so it must never read like a purl-exact OSV hit.
      const char* confidence_suffix = vuln::is_high_confidence_provenance(hit.provenance)
                                          ? ""
                                          : "  [cpe-fallback, lower confidence]";
      std::printf("  ✗ %s: %s%s\n", hit.purl.c_str(), joined_advisories.c_str(), confidence_suffix);
    }
    // Compliance-relevant distinction (rule: never claim more accuracy than
    // the data supports): "0 hits" must not read as "checked, clean" for
    // components OSV structurally cannot check (Conan/vcpkg/generic). The CPE fallback
    // splits the same set: what the CPE fallback reached is reported as
    // checked-but-weaker, and only the remainder as not checked at all.
    if (!cpe_checked_purls.empty())
    {
      std::printf(
          "  note: %zu component(s) have no OSV ecosystem coverage, checked via CPE fallback "
          "(NVD, lower confidence)\n",
          cpe_checked_purls.size());
    }
    if (uncovered_osv_purls.size() > cpe_checked_purls.size())
    {
      std::printf("  note: %zu component(s) have no OSV ecosystem coverage, not checked\n",
                  uncovered_osv_purls.size() - cpe_checked_purls.size());
    }
  }

  // The "no parser yet" qualifier only belongs here when that is
  // actually true for this run: otherwise every manifest listed below was
  // read by a producer, and the caption saying otherwise would be stale.
  std::printf(
      "%-*s %zu%s\n", kSummaryLabelWidth, "manifests:", manifest_paths.size(),
      unparsed_manifests.empty() ? "" : " (recognized manifests bomwerk has no parser for)");
  const std::size_t listed_count = std::min(manifest_paths.size(), kMaxListedManifests);
  for (std::size_t manifest_index = 0; manifest_index < listed_count; ++manifest_index)
  {
    std::printf("  - %s\n", manifest_paths[manifest_index].string().c_str());
  }
  if (manifest_paths.size() > kMaxListedManifests)
  {
    // "- " prefix, matching the bullets above: without it this line's text
    // starts two columns to the left of every filename it is listed under.
    std::printf("  - … and %zu more\n", manifest_paths.size() - kMaxListedManifests);
  }

  // The same finding the warnings above carry, repeated as product output
  // on stdout: an operator who discards stderr must still see that an
  // ecosystem went unread. Silent when there is nothing to report, so a fully
  // covered repo's output is byte-identical to before.
  if (!unparsed_manifests.empty())
  {
    std::printf("%-*s %zu ecosystem(s): recognized, no parser yet\n", kSummaryLabelWidth,
                "unparsed:", unparsed_manifests.size());
    for (const core::UnparsedManifestReport& unparsed : unparsed_manifests)
    {
      std::printf("  - %s: %s (%zu file(s))\n", unparsed.ecosystem.c_str(),
                  unparsed.filename.c_str(), unparsed.paths.size());
      const std::size_t listed_unparsed_count =
          std::min(unparsed.paths.size(), kMaxListedManifests);
      for (std::size_t path_index = 0; path_index < listed_unparsed_count; ++path_index)
      {
        std::printf("      %s\n", unparsed.paths[path_index].string().c_str());
      }
      if (unparsed.paths.size() > kMaxListedManifests)
      {
        std::printf("      … and %zu more\n", unparsed.paths.size() - kMaxListedManifests);
      }
    }
  }
  // Both writers return the whole document as a string and never touch the
  // filesystem (rule 1: no throw across the boundary); the CLI owns the file
  // I/O and the exit-code contract, so the open/write/error block is shared.
  std::string document;
  if (options.format == core::SbomFormat::CycloneDx)
  {
    document = output::write_cyclonedx(components, output::ToolInfo{"bomwerk", version()},
                                       options.release_meta, options.cra_metadata);
  }
  else
  {
    document = output::write_spdx(components, output::ToolInfo{"bomwerk", version()},
                                  options.spdx_version, options.release_meta);
  }
  std::ofstream output_stream(options.output_path, std::ios::binary);
  if (!output_stream)
  {
    spdlog::error("failed to open output file: {}", options.output_path.string());
    return core::kExitIncomplete;
  }
  output_stream << document;
  if (!output_stream)
  {
    spdlog::error("failed to write output file: {}", options.output_path.string());
    return core::kExitIncomplete;
  }
  if (options.format == core::SbomFormat::Spdx)
  {
    std::printf("%-*s %s (format=spdx-%s)\n", kSummaryLabelWidth,
                "output:", options.output_path.string().c_str(),
                core::to_string(options.spdx_version));
  }
  else
  {
    std::printf("%-*s %s (format=%s)\n", kSummaryLabelWidth,
                "output:", options.output_path.string().c_str(), core::to_string(options.format));
  }

  // The CRA compliance sidecar, a sibling artifact to the SBOM: named
  // and placed so `sbom-tools validate --standard cra`'s own auto-discovery
  // finds it with no extra flag (see cra_sidecar_path_for). Written only when
  // bomwerk.toml's [cra] table or the release metadata actually carries
  // something: a plain scan with neither configured gets no sidecar file at
  // all, same precedent as --coverage below. A failed write is exit-2 like a
  // failed SBOM write: no partial sidecar is ever left as the result.
  if (output::has_cra_sidecar_content(options.release_meta, options.cra_metadata))
  {
    const std::string sidecar_document =
        output::write_cra_sidecar(options.release_meta, options.cra_metadata);
    const fs::path sidecar_path = output::cra_sidecar_path_for(options.output_path);
    std::ofstream sidecar_stream(sidecar_path, std::ios::binary);
    if (!sidecar_stream)
    {
      spdlog::error("failed to open CRA sidecar file: {}", sidecar_path.string());
      return core::kExitIncomplete;
    }
    sidecar_stream << sidecar_document;
    if (!sidecar_stream)
    {
      spdlog::error("failed to write CRA sidecar file: {}", sidecar_path.string());
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s\n", kSummaryLabelWidth, "cra-sidecar:", sidecar_path.string().c_str());
  }

  // The match-coverage file, a sibling artifact to the SBOM: written
  // right alongside it since, like the SBOM, it depends only on `components`
  // and never on the vulnerability run below. A failed write is exit-2 like a
  // failed SBOM write: no partial coverage file is ever left as the result.
  if (!options.coverage_path.empty())
  {
    const std::string coverage_document = output::write_coverage_report(
        components, output::ToolInfo{"bomwerk", version()}, options.release_meta);
    std::ofstream coverage_stream(options.coverage_path, std::ios::binary);
    if (!coverage_stream)
    {
      spdlog::error("failed to open coverage file: {}", options.coverage_path.string());
      return core::kExitIncomplete;
    }
    coverage_stream << coverage_document;
    if (!coverage_stream)
    {
      spdlog::error("failed to write coverage file: {}", options.coverage_path.string());
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s\n", kSummaryLabelWidth,
                "coverage-file:", options.coverage_path.string().c_str());
  }

  // The report is written LAST so it replays every warning the scan
  // produced. A failed report write is exit-2 like a failed SBOM write: no
  // partial report file is ever left as the result.
  if (!options.html_report_path.empty())
  {
    // Branding is optional (--report-config); a load problem degrades the run
    // to a warning (which the report itself then replays) but never blocks the
    // report: an unbranded report still opens clean.
    output::ReportBranding report_branding;
    if (!options.report_config_path.empty())
    {
      core::Result<output::ReportBranding> loaded_branding =
          output::load_report_branding(options.report_config_path);
      record_warnings(loaded_branding.warnings);
      report_branding = std::move(loaded_branding.value);
    }

    output::ReportContext report_context;
    report_context.tool = output::ToolInfo{"bomwerk", version()};
    report_context.release_meta = options.release_meta;
    report_context.branding = std::move(report_branding);
    report_context.scanned_root = options.root_directory.string();
    report_context.scanned_file_count = file_count;
    report_context.build_trace_applied = build_trace_applied;
    report_context.vulnerability_check_enabled = options.vuln_enabled;
    report_context.vulnerability_check_offline = options.offline;
    // Same set the stdout note counted: the report tags exactly these rows and
    // derives its metric/notice from the list size, so numbers and tags agree.
    report_context.components_without_osv_coverage_purls = uncovered_osv_purls;
    // The subset of the above the CPE fallback reached. The report swaps
    // the row badge and subtracts this from the "not checked" figure, again
    // from one list rather than a parallel count.
    report_context.components_checked_via_cpe_fallback_purls = cpe_checked_purls;
    report_context.vulnerabilities.reserve(vulnerability_matches.value.hits.size());
    for (const vuln::VulnerabilityHit& hit : vulnerability_matches.value.hits)
    {
      // Copy into the output-owned mirror type: the writer may only include
      // core (module dependency law), so it cannot see vuln::. The advisories
      // are already a core type (`ScoredAdvisory`), so they copy straight over.
      // Map the vuln-module provenance onto the output-module mirror: the two
      // enums exist separately only because `output` may not include `vuln`.
      report_context.vulnerabilities.push_back(
          output::ReportVulnerability{hit.purl, hit.advisories,
                                      vuln::is_high_confidence_provenance(hit.provenance)
                                          ? output::FindingSource::OsvPurlMatch
                                          : output::FindingSource::NvdCpeMatch});
    }
    report_context.warnings = warning_recorder.collected();

    const std::string report_document = output::write_html_report(components, report_context);
    std::ofstream report_stream(options.html_report_path, std::ios::binary);
    if (!report_stream)
    {
      spdlog::error("failed to open report file: {}", options.html_report_path.string());
      return core::kExitIncomplete;
    }
    report_stream << report_document;
    if (!report_stream)
    {
      spdlog::error("failed to write report file: {}", options.html_report_path.string());
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s (self-contained HTML)\n", kSummaryLabelWidth,
                "report:", options.html_report_path.string().c_str());
  }

  // written LAST, like the HTML report above (and after it, since --html can still
  // record report-config warnings of its own) so the manifest reflects every warning the
  // run produced, not just the ones recorded before some later artifact's own diagnostics.
  if (!options.warnings_path.empty())
  {
    const std::string warnings_document = output::write_warnings_report(
        warning_recorder.collected(), options.suppressed_warning_codes,
        output::ToolInfo{"bomwerk", version()}, options.release_meta);
    std::ofstream warnings_stream(options.warnings_path, std::ios::binary);
    if (!warnings_stream)
    {
      spdlog::error("failed to open warnings file: {}", options.warnings_path.string());
      return core::kExitIncomplete;
    }
    warnings_stream << warnings_document;
    if (!warnings_stream)
    {
      spdlog::error("failed to write warnings file: {}", options.warnings_path.string());
      return core::kExitIncomplete;
    }
    std::printf("%-*s %s\n", kSummaryLabelWidth,
                "warnings-file:", options.warnings_path.string().c_str());
  }

  if (!lockfile_scan_complete)
  {
    return core::kExitIncomplete;
  }
  return warning_recorder.degraded() ? core::kExitCompletedWithWarnings : core::kExitClean;
}

}  // namespace

int run_scan(const ScanOptions& options)
{
  return core::apply_fail_on_threshold(run_scan_ignoring_fail_on(options), options.fail_on);
}

}  // namespace bomwerk::cli
