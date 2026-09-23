#include "core/scan_config.hpp"

#include <toml++/toml.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "core/file_index.hpp"
#include "core/file_io.hpp"
#include "core/git_dir.hpp"
#include "core/scan_limits.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::core
{
namespace
{

/// Upper bound for a config read; a real bomwerk.toml is a few hundred bytes,
/// so anything near this cap is hostile or a mistake, never a valid config.
constexpr std::size_t kMaxScanConfigBytes = 1 * 1024 * 1024;

/// Every warning names the file it came from so a run over nested projects
/// stays diagnosable.
std::string warning_prefix(const fs::path& config_path)
{
  return "scan config " + config_path.string() + ": ";
}

/// Parse the TOML shell. vcpkg's tomlplusplus port ships a precompiled,
/// exceptions-enabled build (see the note in CMakeLists.txt), so
/// `toml::parse` throws `toml::parse_error` on malformed input; the catch is
/// confined here so nothing propagates across the module boundary (rule 1) :
/// same pattern as parsers/lockfiles/cargo.cpp and python.cpp.
std::optional<toml::table> parse_toml_or_warn(std::string_view bytes, const fs::path& config_path,
                                              Result<ScanConfig>& result)
{
  try
  {
    return toml::parse(bytes, std::string_view{config_path.string()});
  }
  catch (const toml::parse_error&)
  {
    result.warn(WarningCode::kConfigNotValidToml,
                warning_prefix(config_path) + "not valid TOML, config ignored");
    return std::nullopt;
  }
}

/// Read `[table_name].key` as a string, warning (and yielding nothing) when
/// present with any other type.
std::optional<std::string> read_string(const toml::table& table, const char* table_name,
                                       const char* key, const fs::path& config_path,
                                       Result<ScanConfig>& result)
{
  const toml::node* node = table.get(key);
  if (node == nullptr)
  {
    return std::nullopt;
  }
  if (const std::optional<std::string> value = node->value<std::string>())
  {
    return value;
  }
  result.warn(WarningCode::kConfigKeyWrongType, warning_prefix(config_path) + "[" + table_name +
                                                    "]." + key + " must be a string, ignored");
  return std::nullopt;
}

/// Read `[table_name].key` as a boolean, warning (and yielding nothing) when
/// present with any other type.
std::optional<bool> read_bool(const toml::table& table, const char* table_name, const char* key,
                              const fs::path& config_path, Result<ScanConfig>& result)
{
  const toml::node* node = table.get(key);
  if (node == nullptr)
  {
    return std::nullopt;
  }
  if (const std::optional<bool> value = node->value<bool>())
  {
    return value;
  }
  result.warn(WarningCode::kConfigKeyWrongType, warning_prefix(config_path) + "[" + table_name +
                                                    "]." + key + " must be true or false, ignored");
  return std::nullopt;
}

/// Read the repository-configured per-ecosystem package limit. Unlike an
/// explicit CLI value, this untrusted value has an upper bound so automatic
/// config discovery cannot disable the scanner's resource-safety posture.
std::optional<std::size_t> read_package_limit(const toml::table& table, const fs::path& config_path,
                                              Result<ScanConfig>& result)
{
  const toml::node* node = table.get("max_packages");
  if (node == nullptr)
  {
    return std::nullopt;
  }
  const std::optional<std::int64_t> value = node->value<std::int64_t>();
  if (!value || *value < 1 ||
      static_cast<std::uint64_t>(*value) > kMaxConfiguredPackagesPerEcosystem)
  {
    result.warn(WarningCode::kConfigValueInvalidFormat,
                warning_prefix(config_path) +
                    "[scan].max_packages must be an integer from 1 "
                    "through " +
                    std::to_string(kMaxConfiguredPackagesPerEcosystem) + ", ignored");
    return std::nullopt;
  }
  return static_cast<std::size_t>(*value);
}

/// Upper bound on the number of entries in one `[table].key` array. A real
/// bomwerk.toml lists a handful of subtrees or names; this only exists to cap
/// the per-file/per-directory scan cost the walk pays for each entry (an
/// array this large is hostile or a mistake, never a valid config).
constexpr std::size_t kMaxArrayEntries = 256u;

/// Read `[table_name].key` as an array of strings, warning per non-string
/// element, warning (yielding an empty list) when the key is not an array,
/// and warning + truncating once `kMaxArrayEntries` is reached.
std::vector<std::string> read_string_array(const toml::table& table, const char* table_name,
                                           const char* key, const fs::path& config_path,
                                           Result<ScanConfig>& result)
{
  std::vector<std::string> values;
  const toml::node* node = table.get(key);
  if (node == nullptr)
  {
    return values;
  }
  const toml::array* array = node->as_array();
  if (array == nullptr)
  {
    result.warn(WarningCode::kConfigKeyWrongType, warning_prefix(config_path) + "[" + table_name +
                                                      "]." + key +
                                                      " must be an array of strings, ignored");
    return values;
  }
  bool truncated = false;
  for (const toml::node& element : *array)
  {
    if (values.size() >= kMaxArrayEntries)
    {
      truncated = true;
      break;
    }
    if (const std::optional<std::string> value = element.value<std::string>())
    {
      values.push_back(*value);
    }
    else
    {
      result.warn(WarningCode::kConfigArrayEntryInvalid,
                  warning_prefix(config_path) + "[" + table_name + "]." + key +
                      " has a non-string entry, that entry is ignored");
    }
  }
  if (truncated)
  {
    result.warn(WarningCode::kConfigArrayEntryInvalid,
                warning_prefix(config_path) + "[" + table_name + "]." + key + " has more than " +
                    std::to_string(kMaxArrayEntries) + " entries, the rest are ignored");
  }
  return values;
}

/// Read `[table_name].key` as a list of repo-relative subtree paths, dropping
/// (with a warning) any entry that could escape the scanned tree, and any
/// entry naming ".": the walk's include/exclude filter only ever matches
/// strict descendants of the scanned root (see file_index.cpp), so a "."
/// entry can never match anything: for `include` it would be a no-op restriction
/// anyway (already the "everything" default), but for `exclude` it would
/// silently fail to exclude anything at all, which is surprising enough to
/// warn about explicitly rather than let it pass through inert.
std::vector<fs::path> read_subtree_array(const toml::table& table, const char* table_name,
                                         const char* key, const fs::path& config_path,
                                         Result<ScanConfig>& result)
{
  std::vector<fs::path> subtrees;
  for (const std::string& entry : read_string_array(table, table_name, key, config_path, result))
  {
    const fs::path normalized = normalized_subtree_path(fs::path(entry));
    if (normalized == fs::path("."))
    {
      result.warn(WarningCode::kConfigArrayEntryInvalid,
                  warning_prefix(config_path) + "[" + table_name + "]." + key + " entry \"" +
                      entry +
                      "\" names the whole scanned tree, which this per-subtree filter can never "
                      "match, ignored");
      continue;
    }
    if (!is_contained_relative_path(normalized))
    {
      result.warn(WarningCode::kConfigArrayEntryInvalid,
                  warning_prefix(config_path) + "[" + table_name + "]." + key + " entry \"" +
                      entry +
                      "\" must be a relative path inside the repo (no absolute, no \"..\"), "
                      "ignored");
      continue;
    }
    subtrees.push_back(normalized);
  }
  return subtrees;
}

/// Read `[table_name].key` as one repo-relative path with the same escape
/// guard as read_subtree_array.
fs::path read_repo_relative_path(const toml::table& table, const char* table_name, const char* key,
                                 const fs::path& config_path, Result<ScanConfig>& result)
{
  const std::optional<std::string> value = read_string(table, table_name, key, config_path, result);
  if (!value)
  {
    return {};
  }
  const fs::path normalized = normalized_subtree_path(fs::path(*value));
  if (!is_contained_relative_path(normalized))
  {
    result.warn(WarningCode::kConfigArrayEntryInvalid,
                warning_prefix(config_path) + "[" + table_name + "]." + key + " \"" + *value +
                    "\" must be a relative path inside the repo (no absolute, no \"..\"), ignored");
    return {};
  }
  return normalized;
}

/// Warn about any key of `table` that is not in `known_keys`: a typo in a
/// config must never be silently ignored.
template <std::size_t known_key_count>
void warn_unknown_keys(const toml::table& table, const char* table_name,
                       const char* const (&known_keys)[known_key_count],
                       const fs::path& config_path, Result<ScanConfig>& result)
{
  for (const auto& [key, node] : table)
  {
    bool key_is_known = false;
    for (const char* known_key : known_keys)
    {
      if (key.str() == known_key)
      {
        key_is_known = true;
        break;
      }
    }
    if (!key_is_known)
    {
      result.warn(WarningCode::kConfigUnknownKey, warning_prefix(config_path) + "unknown key [" +
                                                      table_name + "]." + std::string(key.str()) +
                                                      ", ignored");
    }
  }
}

void apply_scan_table(const toml::table& scan_table, const fs::path& config_path,
                      Result<ScanConfig>& result)
{
  static constexpr const char* kKnownKeys[] = {
      "include",        "exclude", "exclude_dir_names",
      "manifest_names", "all",     "include_submodule_contents",
      "max_packages"};
  warn_unknown_keys(scan_table, "scan", kKnownKeys, config_path, result);

  result.value.include_paths =
      read_subtree_array(scan_table, "scan", "include", config_path, result);
  result.value.exclude_paths =
      read_subtree_array(scan_table, "scan", "exclude", config_path, result);
  for (const std::string& name :
       read_string_array(scan_table, "scan", "exclude_dir_names", config_path, result))
  {
    result.value.excluded_dir_names.insert(name);
  }
  for (const std::string& name :
       read_string_array(scan_table, "scan", "manifest_names", config_path, result))
  {
    result.value.manifest_names.insert(name);
  }
  result.value.scan_all_directories = read_bool(scan_table, "scan", "all", config_path, result);
  result.value.include_submodule_contents =
      read_bool(scan_table, "scan", "include_submodule_contents", config_path, result);
  result.value.max_packages = read_package_limit(scan_table, config_path, result);
}

void apply_output_table(const toml::table& output_table, const fs::path& config_path,
                        Result<ScanConfig>& result)
{
  static constexpr const char* kKnownKeys[] = {"format", "spdx_version",  "path",
                                               "html",   "report_config", "coverage"};
  warn_unknown_keys(output_table, "output", kKnownKeys, config_path, result);

  if (const std::optional<std::string> format =
          read_string(output_table, "output", "format", config_path, result))
  {
    if (*format == to_string(SbomFormat::CycloneDx))
    {
      result.value.format = SbomFormat::CycloneDx;
    }
    else if (*format == to_string(SbomFormat::Spdx))
    {
      result.value.format = SbomFormat::Spdx;
    }
    else
    {
      result.warn(WarningCode::kConfigValueInvalidFormat,
                  warning_prefix(config_path) + "[output].format \"" + *format +
                      "\" is not \"cyclonedx\" or \"spdx\", ignored");
    }
  }
  if (const std::optional<std::string> spdx_version =
          read_string(output_table, "output", "spdx_version", config_path, result))
  {
    if (*spdx_version == to_string(SpdxVersion::V2_3))
    {
      result.value.spdx_version = SpdxVersion::V2_3;
    }
    else if (*spdx_version == to_string(SpdxVersion::V3_0))
    {
      result.value.spdx_version = SpdxVersion::V3_0;
    }
    else
    {
      result.warn(WarningCode::kConfigValueInvalidFormat,
                  warning_prefix(config_path) + "[output].spdx_version \"" + *spdx_version +
                      "\" is not \"2.3\" or \"3.0\", ignored");
    }
  }
  result.value.output_path =
      read_repo_relative_path(output_table, "output", "path", config_path, result);
  result.value.html_report_path =
      read_repo_relative_path(output_table, "output", "html", config_path, result);
  result.value.report_config_path =
      read_repo_relative_path(output_table, "output", "report_config", config_path, result);
  result.value.coverage_path =
      read_repo_relative_path(output_table, "output", "coverage", config_path, result);
}

void apply_product_table(const toml::table& product_table, const fs::path& config_path,
                         Result<ScanConfig>& result)
{
  static constexpr const char* kKnownKeys[] = {"id", "version"};
  warn_unknown_keys(product_table, "product", kKnownKeys, config_path, result);

  result.value.product_id =
      read_string(product_table, "product", "id", config_path, result).value_or("");
  result.value.product_version =
      read_string(product_table, "product", "version", config_path, result).value_or("");
}

/// CRA compliance metadata (`CraMetadata`): a snake_case bomwerk.toml
/// key per camelCase sidecar field, so a config author sees the same
/// vocabulary this table feeds into `output::write_cra_sidecar`. No CLI flag
/// exists for any of these; the config is their only source, same as
/// `include`/`exclude` below.
void apply_cra_table(const toml::table& cra_table, const fs::path& config_path,
                     Result<ScanConfig>& result)
{
  static constexpr const char* kKnownKeys[] = {"manufacturer_name", "manufacturer_email",
                                               "security_contact", "vulnerability_disclosure_url"};
  warn_unknown_keys(cra_table, "cra", kKnownKeys, config_path, result);

  result.value.cra_metadata.manufacturer_name =
      read_string(cra_table, "cra", "manufacturer_name", config_path, result).value_or("");
  result.value.cra_metadata.manufacturer_email =
      read_string(cra_table, "cra", "manufacturer_email", config_path, result).value_or("");
  result.value.cra_metadata.security_contact =
      read_string(cra_table, "cra", "security_contact", config_path, result).value_or("");
  result.value.cra_metadata.vulnerability_disclosure_url =
      read_string(cra_table, "cra", "vulnerability_disclosure_url", config_path, result)
          .value_or("");
}

/// Which warning codes this repo accepts. Entries may be bare codes
/// (all ecosystems) or `CODE:ecosystem` pairs. Suppression never removes a
/// warning from any artifact (SBOM, HTML report, `--warnings` manifest): it
/// only stops that warning from setting `degraded`, so `--fail-on warnings`
/// (the default) stops failing on a cause the repo owner has reviewed and
/// accepted. Config-only, like `[cra]` above: this is a per-repo policy
/// decision that belongs in a reviewed, version-controlled file.
void apply_warnings_table(const toml::table& warnings_table, const fs::path& config_path,
                          Result<ScanConfig>& result)
{
  static constexpr const char* kKnownKeys[] = {"suppress"};
  warn_unknown_keys(warnings_table, "warnings", kKnownKeys, config_path, result);

  for (const std::string& code_id :
       read_string_array(warnings_table, "warnings", "suppress", config_path, result))
  {
    result.value.suppressed_warning_codes.insert(code_id);
  }
}

/// Dispatch one top-level entry to its table applier; warn on anything else.
/// The vuln toggles are deliberately absent (see scan_config.hpp): a config
/// carrying a [vuln] table gets the same unknown-table warning as a typo.
void apply_top_level_entry(std::string_view key, const toml::node& node,
                           const fs::path& config_path, Result<ScanConfig>& result)
{
  const toml::table* table = node.as_table();
  if (table == nullptr)
  {
    result.warn(WarningCode::kConfigTopLevelKeyNotTable, warning_prefix(config_path) +
                                                             "top-level key \"" + std::string(key) +
                                                             "\" is not a table, ignored");
    return;
  }
  if (key == "scan")
  {
    apply_scan_table(*table, config_path, result);
  }
  else if (key == "output")
  {
    apply_output_table(*table, config_path, result);
  }
  else if (key == "product")
  {
    apply_product_table(*table, config_path, result);
  }
  else if (key == "cra")
  {
    apply_cra_table(*table, config_path, result);
  }
  else if (key == "warnings")
  {
    apply_warnings_table(*table, config_path, result);
  }
  else
  {
    result.warn(WarningCode::kConfigUnknownTable,
                warning_prefix(config_path) + "unknown table [" + std::string(key) + "], ignored");
  }
}

}  // namespace

Result<ScanConfig> load_scan_config(const fs::path& config_path)
{
  Result<ScanConfig> result;

  const BoundedFileRead read = read_file_bounded(config_path, kMaxScanConfigBytes);
  if (!read.readable)
  {
    result.warn(WarningCode::kConfigFileUnreadable,
                warning_prefix(config_path) + "cannot read file, config ignored");
    return result;
  }
  if (read.truncated)
  {
    // A truncated TOML document could half-parse into something the author
    // never wrote; refusing it entirely is the honest degradation.
    result.warn(WarningCode::kConfigFileTooLarge,
                warning_prefix(config_path) + "larger than the 1 MiB cap, config ignored");
    return result;
  }

  const std::optional<toml::table> document = parse_toml_or_warn(read.bytes, config_path, result);
  if (!document)
  {
    return result;
  }

  for (const auto& [key, node] : *document)
  {
    apply_top_level_entry(key.str(), node, config_path, result);
  }
  return result;
}

}  // namespace bomwerk::core
