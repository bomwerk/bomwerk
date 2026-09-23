#include "parsers/lockfiles/go.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::lockfiles::go
{
namespace
{

constexpr std::string_view kGoSumName = "go.sum";

/// The `/go.mod` line variant: metadata for a module already covered (or
/// deliberately not covered: see the header) by its zip line.
constexpr std::string_view kGoModVersionSuffix = "/go.mod";

/// Known forge hosts a go module path can open with, where the second
/// path segment is a real owner/organization name rather than an arbitrary
/// namespacing convention (`golang.org/x/text`, `gopkg.in/yaml.v2` and
/// similar proxy/vanity paths are deliberately excluded: their second
/// segment is not a publisher).
constexpr std::string_view kGoForgeHosts[] = {"github.com", "gitlab.com", "bitbucket.org"};

/// NTIA/CRA supplier evidence from a module path hosted on a known
/// forge: the owner segment right after the host. Any other host (a proxy,
/// a vanity import path, a private GOPRIVATE host) states no publisher this
/// parser can trust, and stays empty rather than guessing one.
std::string go_supplier_from_module_path(const std::string& module_path)
{
  const std::size_t first_slash = module_path.find('/');
  if (first_slash == std::string::npos)
  {
    return {};
  }
  const std::string_view host = std::string_view(module_path).substr(0, first_slash);
  bool host_is_known_forge = false;
  for (const std::string_view forge_host : kGoForgeHosts)
  {
    if (core::to_lower_ascii(host) == forge_host)
    {
      host_is_known_forge = true;
      break;
    }
  }
  if (!host_is_known_forge)
  {
    return {};
  }
  const std::size_t second_slash = module_path.find('/', first_slash + 1);
  const std::size_t owner_length =
      (second_slash == std::string::npos) ? std::string::npos : second_slash - first_slash - 1;
  return module_path.substr(first_slash + 1, owner_length);
}

/// Build the `pkg:golang` purl for a module path and version. The purl-spec
/// `golang` type lower-cases namespace and name; the version keeps its exact
/// case (and its `v` prefix: it is part of Go's version identity).
std::string build_golang_purl(const std::string& module_path, const std::string& version)
{
  const std::string lowered_module_path = core::to_lower_ascii(module_path);
  std::string purl = "pkg:golang/";
  const std::size_t last_slash = lowered_module_path.rfind('/');
  if (last_slash == std::string::npos)
  {
    purl += core::percent_encode(lowered_module_path);
  }
  else
  {
    purl += core::percent_encode_purl_namespace(lowered_module_path.substr(0, last_slash));
    purl += "/";
    purl += core::percent_encode(lowered_module_path.substr(last_slash + 1));
  }
  purl += "@" + core::percent_encode(version);
  return purl;
}

/// Parse one go.sum's lines into components. `label` is the root-relative path
/// used in warnings and evidence details. Malformed lines are counted and
/// reported once per file (rule 1: degrade, never abort).
void parse_go_sum(std::string_view bytes, const std::string& label, std::size_t package_limit,
                  std::size_t& package_budget, std::vector<core::Component>& components,
                  core::Result<std::vector<core::Component>>& result)
{
  std::size_t malformed_line_count = 0;
  std::size_t line_start = 0;
  while (line_start <= bytes.size())
  {
    const std::size_t line_end = bytes.find('\n', line_start);
    const std::string_view raw_line =
        bytes.substr(line_start, (line_end == std::string_view::npos) ? std::string_view::npos
                                                                      : line_end - line_start);
    line_start = (line_end == std::string_view::npos) ? bytes.size() + 1 : line_end + 1;

    const std::string_view line = core::trimmed_view(raw_line);
    if (line.empty())
    {
      continue;
    }

    // A well-formed line is exactly `module version hash`.
    const std::size_t first_space = line.find(' ');
    const std::size_t second_space = (first_space == std::string_view::npos)
                                         ? std::string_view::npos
                                         : line.find(' ', first_space + 1);
    if (first_space == std::string_view::npos || second_space == std::string_view::npos ||
        line.find(' ', second_space + 1) != std::string_view::npos)
    {
      ++malformed_line_count;
      continue;
    }
    const std::string_view module_field = line.substr(0, first_space);
    std::string_view version_field = line.substr(first_space + 1, second_space - first_space - 1);
    const std::string_view hash_field = line.substr(second_space + 1);
    if (module_field.empty() || version_field.empty() || hash_field.empty())
    {
      ++malformed_line_count;
      continue;
    }

    if (version_field.size() >= kGoModVersionSuffix.size() &&
        version_field.substr(version_field.size() - kGoModVersionSuffix.size()) ==
            kGoModVersionSuffix)
    {
      continue;  // metadata line for a module; the zip line carries the component
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "go: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "go");
      result.complete = false;
      break;
    }
    --package_budget;

    core::Component component;
    component.name = std::string(module_field);
    component.version = std::string(version_field);
    component.purl = build_golang_purl(component.name, component.version);
    component.supplier = go_supplier_from_module_path(component.name);
    // High: versions are Go's exact resolver output. The honesty note travels
    // with the evidence, not the identity: go.sum is a superset of the build.
    component.evidence.push_back(
        {core::Source::Manifest,
         label + " (go.sum lists the module download set, which can exceed what is built)",
         core::Confidence::High});

    const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
    if (!parsed_purl.complete)
    {
      result.warn(core::WarningCode::kPurlValidationFailed,
                  "go: produced purl failed validation: " + component.purl, "go");
    }
    else
    {
      component.purl = parsed_purl.value.canonical();
    }
    components.push_back(std::move(component));
  }

  if (malformed_line_count > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "go: " + std::to_string(malformed_line_count) + " malformed line(s) skipped: " + label,
        "go");
  }
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  std::vector<core::Component> components;
  std::size_t scanned_file_count = 0;
  std::size_t package_budget = options.max_total_packages;

  for (const fs::path& relative_path : file_index.files)
  {
    if (relative_path.filename().string() != kGoSumName)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "go: file limit reached; remaining go.sum files skipped", "go");
      break;
    }
    if (package_budget == 0 && !result.complete)
    {
      // An additional valid entry already proved exhaustion and warned once;
      // stop opening files after that proof, but not merely because an earlier
      // file ended exactly at the configured limit.
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "go: unreadable file: " + label, "go");
      continue;
    }
    std::string_view bytes = file_read.bytes;
    if (file_read.truncated)
    {
      // Line-based format: the readable prefix still parses; only the cut-off
      // tail line is dropped so it cannot count as malformed.
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "go: file exceeds size limit, parsing first part only: " + label, "go");
      const std::size_t last_newline = bytes.rfind('\n');
      bytes = (last_newline == std::string_view::npos) ? std::string_view{}
                                                       : bytes.substr(0, last_newline + 1);
    }
    parse_go_sum(bytes, label, options.max_total_packages, package_budget, components, result);
  }

  result.value = core::merge_all(std::move(components));
  return result;
}

core::Result<std::vector<core::Component>> parse(const fs::path& root, const ParseOptions& options)
{
  const core::Result<core::FileIndex> file_index =
      core::build_file_index(root, core::default_excluded_dir_names(),
                             core::with_submodule_subtrees(root, options.excluded_subtrees));
  core::Result<std::vector<core::Component>> result = parse(file_index.value, root, options);
  for (const core::Warning& warning : file_index.warnings)
  {
    result.warn(warning);
  }
  if (!file_index.complete)
  {
    result.complete = false;
  }
  return result;
}

core::Result<std::vector<core::Component>> parse(const fs::path& root)
{
  return parse(root, ParseOptions{});
}

}  // namespace bomwerk::parsers::lockfiles::go
