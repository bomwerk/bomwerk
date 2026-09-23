#pragma once
#include <cstddef>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "core/sbom_format.hpp"

namespace bomwerk::core
{

/// Filename of the repo-level scan config, looked up at the scanned
/// directory's root when `bomwerk scan` runs without `--config`/`--no-config`.
inline constexpr const char* kScanConfigFileName = "bomwerk.toml";

/// Repo-level scan configuration: what a `bomwerk.toml` at the scanned
/// repo's root can decide, so a bare `bomwerk scan` needs no flags. Every
/// field is optional; an absent field (empty container/string, disengaged
/// optional) means "not set" and the caller keeps its default. An explicitly
/// given CLI flag always wins over the corresponding config value.
///
/// The file lives inside the repo being scanned, i.e. it is untrusted input
/// loading is bounded and never throws (rule 1), and
/// every path in it must be relative with no `..` component so a hostile
/// config can neither read nor write outside the scanned tree. The
/// vulnerability toggles (`--vuln`/`--offline`) are deliberately not
/// representable here: the repo under audit must not be able to switch off
/// its own audit. `include_submodule_contents` is safe to expose by the same
/// test: it can only widen what the scan looks at, never hide anything.
struct ScanConfig
{
  std::vector<std::filesystem::path> include_paths;  ///< [scan] include: restrict the walk to
                                                     ///< these root-relative subtrees
  std::vector<std::filesystem::path> exclude_paths;  ///< [scan] exclude: root-relative subtrees
                                                     ///< to skip
  std::set<std::string> excluded_dir_names;  ///< [scan] exclude_dir_names: replaces the built-in
                                             ///< basename list (supersedes --exclude-list)
  std::set<std::string> manifest_names;      ///< [scan] manifest_names: replaces the built-in
                                             ///< list (supersedes --manifest-list)
  std::optional<bool> scan_all_directories;  ///< [scan] all: like --all
  std::optional<bool> include_submodule_contents;  ///< [scan] include_submodule_contents: like
                                                   ///< --include-submodule-contents
  std::optional<std::size_t> max_packages;         ///< [scan] max_packages: per-lockfile-ecosystem
                                                   ///< package-entry budget
  std::optional<SbomFormat> format;                ///< [output] format: "cyclonedx" or "spdx"
  std::optional<SpdxVersion> spdx_version;         ///< [output] spdx_version: "2.3" or "3.0"
  std::filesystem::path output_path;         ///< [output] path, resolved against the scanned root
  std::filesystem::path html_report_path;    ///< [output] html, resolved against the scanned root
  std::filesystem::path report_config_path;  ///< [output] report_config, resolved against the
                                             ///< scanned root
  std::filesystem::path coverage_path;       ///< [output] coverage, resolved against the scanned
                                             ///< root
  std::string product_id;                    ///< [product] id -> ReleaseMeta::product_id
  std::string product_version;               ///< [product] version -> ReleaseMeta::version
  CraMetadata cra_metadata;                  ///< [cra]: manufacturer_name, manufacturer_email,
                                             ///< security_contact, vulnerability_disclosure_url.
  ///< No CLI flag exists for any of these: bomwerk.toml is
  ///< their only source, same as include/exclude subtrees
  ///< below.
  std::set<std::string> suppressed_warning_codes;  ///< [warnings] suppress : bare
                                                   ///< WarningCode ids (e.g. "BW-CORE-004") or
                                                   ///< "CODE:ecosystem" entries this repo has
                                                   ///< reviewed and accepts. Never removes the
                                                   ///< warning from any artifact: only from the
                                                   ///< exit-code/attention decision. Config-only,
                                                   ///< same reasoning as [cra] above.
};

/// Load `config_path` as a `ScanConfig`. Never throws (rule 1): an
/// unreadable, oversized or malformed file degrades to an empty config with
/// one warning; a wrong-typed or invalid value degrades to a warning for that
/// key while the rest of the file still applies; unknown tables and keys warn
/// by name so a typo is never silently ignored. `complete` stays true: a
/// broken config degrades the run (exit 1), it never aborts it.
[[nodiscard]] Result<ScanConfig> load_scan_config(const std::filesystem::path& config_path);

}  // namespace bomwerk::core
