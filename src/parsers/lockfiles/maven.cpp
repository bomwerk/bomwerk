#include "parsers/lockfiles/maven.hpp"

#include <cstddef>
#include <filesystem>
#include <map>
#include <optional>
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

namespace bomwerk::parsers::lockfiles::maven
{
namespace
{

constexpr std::string_view kPomName = "pom.xml";
constexpr std::string_view kGradleLockfileName = "gradle.lockfile";

constexpr std::string_view kCommentOpen = "<!--";
constexpr std::string_view kCommentClose = "-->";
constexpr std::string_view kCdataOpen = "<![CDATA[";
constexpr std::string_view kCdataClose = "]]>";

/// The one maven scope that means "not part of the shipped product".
constexpr std::string_view kMavenTestScope = "test";

/// Gradle configuration-name prefix marking test-only classpaths
/// (`testCompileClasspath`, `testRuntimeClasspath`, …).
constexpr std::string_view kTestConfigurationPrefix = "test";

/// The gradle.lockfile pseudo-coordinate listing configurations that resolved
/// to no dependencies at all.
constexpr std::string_view kGradleEmptyCoordinate = "empty";

/// True for the ASCII whitespace XML allows inside tags.
bool is_xml_whitespace(char character)
{
  return character == ' ' || character == '\t' || character == '\r' || character == '\n';
}

/// Remove XML comments and unwrap CDATA sections so the tag scanner below
/// never trips over commented-out or escaped markup. An unterminated comment
/// or CDATA section swallows the rest of the file: degrading, never throwing.
std::string strip_comments_and_unwrap_cdata(std::string_view xml)
{
  std::string cleaned;
  cleaned.reserve(xml.size());
  std::size_t position = 0;
  while (position < xml.size())
  {
    if (xml.compare(position, kCommentOpen.size(), kCommentOpen) == 0)
    {
      const std::size_t comment_close = xml.find(kCommentClose, position + kCommentOpen.size());
      if (comment_close == std::string_view::npos)
      {
        break;
      }
      position = comment_close + kCommentClose.size();
      continue;
    }
    if (xml.compare(position, kCdataOpen.size(), kCdataOpen) == 0)
    {
      const std::size_t cdata_close = xml.find(kCdataClose, position + kCdataOpen.size());
      if (cdata_close == std::string_view::npos)
      {
        break;
      }
      cleaned.append(xml, position + kCdataOpen.size(), cdata_close - position - kCdataOpen.size());
      position = cdata_close + kCdataClose.size();
      continue;
    }
    cleaned.push_back(xml[position]);
    ++position;
  }
  return cleaned;
}

/// One matched XML element: where its span starts, its inner text, and where
/// scanning may resume after the closing tag.
struct ElementMatch
{
  std::size_t span_start = 0;
  std::string_view inner_text;
  std::size_t resume_position = 0;
};

/// Find the next `<tag …>…</tag>` element at or after `search_start`. The
/// opening tag may carry attributes; a self-closing `<tag …/>` yields empty
/// inner text. The closing tag must be the literal `</tag>`: anything the
/// scanner cannot pair is treated as absent (degrade, never guess).
std::optional<ElementMatch> find_element(std::string_view xml, std::string_view tag_name,
                                         std::size_t search_start)
{
  std::size_t position = search_start;
  while (position < xml.size())
  {
    const std::size_t open = xml.find('<', position);
    if (open == std::string_view::npos)
    {
      return std::nullopt;
    }
    const std::size_t name_start = open + 1;
    if (xml.compare(name_start, tag_name.size(), tag_name) != 0)
    {
      position = open + 1;
      continue;
    }
    const std::size_t after_name = name_start + tag_name.size();
    if (after_name >= xml.size() ||
        (xml[after_name] != '>' && xml[after_name] != '/' && !is_xml_whitespace(xml[after_name])))
    {
      position = open + 1;  // a longer tag name that merely starts the same
      continue;
    }
    const std::size_t open_end = xml.find('>', after_name);
    if (open_end == std::string_view::npos)
    {
      return std::nullopt;
    }
    if (xml[open_end - 1] == '/')
    {
      return ElementMatch{open, std::string_view{}, open_end + 1};
    }
    const std::string closing_tag = "</" + std::string(tag_name) + ">";
    const std::size_t close = xml.find(closing_tag, open_end + 1);
    if (close == std::string_view::npos)
    {
      return std::nullopt;
    }
    return ElementMatch{open, xml.substr(open_end + 1, close - open_end - 1),
                        close + closing_tag.size()};
  }
  return std::nullopt;
}

/// Trimmed inner text of the first `<tag>` within `xml`; nullopt when absent.
std::optional<std::string> first_element_text(std::string_view xml, std::string_view tag_name)
{
  const std::optional<ElementMatch> match = find_element(xml, tag_name, 0);
  if (!match.has_value())
  {
    return std::nullopt;
  }
  return std::string(core::trimmed_view(match->inner_text));
}

/// First `<license><name>` text within `xml` (a pom's own `<licenses>` block,
/// typically `coordinate_region`), trimmed; nullopt when absent. Only the
/// FIRST `<license>` entry is read: mirrors composer.cpp's `.front()` of a
/// composer.json `license` array: and only its `<name>`, never `<url>`/
/// `<comments>`/`<distribution>`. Verbatim, no SPDX normalization (parsers/
/// never includes output/): Component::license is a single string, so a
/// dual-licensed pom only ever surfaces its first declared license here.
std::optional<std::string> first_pom_license_name(std::string_view xml)
{
  const std::optional<ElementMatch> licenses_block = find_element(xml, "licenses", 0);
  if (!licenses_block.has_value())
  {
    return std::nullopt;
  }
  const std::optional<ElementMatch> license_entry =
      find_element(licenses_block->inner_text, "license", 0);
  if (!license_entry.has_value())
  {
    return std::nullopt;
  }
  return first_element_text(license_entry->inner_text, "name");
}

/// Erase every `<tag>…</tag>` span. Used for `<dependencyManagement>`
/// (version pins, not dependencies) and `<exclusions>` (their nested
/// groupId/artifactId would poison the flat extraction below).
std::string remove_elements(std::string_view xml, std::string_view tag_name)
{
  std::string remaining;
  remaining.reserve(xml.size());
  std::size_t position = 0;
  while (position < xml.size())
  {
    const std::optional<ElementMatch> match = find_element(xml, tag_name, position);
    if (!match.has_value())
    {
      remaining.append(xml.substr(position));
      break;
    }
    remaining.append(xml.substr(position, match->span_start - position));
    position = match->resume_position;
  }
  return remaining;
}

/// Child elements of the first `<properties>` block as name->value. One flat
/// level: exactly what `${property}` resolution needs, nothing more.
std::map<std::string, std::string> collect_pom_properties(std::string_view xml)
{
  std::map<std::string, std::string> properties;
  const std::optional<ElementMatch> block = find_element(xml, "properties", 0);
  if (!block.has_value())
  {
    return properties;
  }
  const std::string_view body = block->inner_text;
  std::size_t position = 0;
  while (position < body.size())
  {
    const std::size_t open = body.find('<', position);
    if (open == std::string_view::npos)
    {
      break;
    }
    if (open + 1 >= body.size() || body[open + 1] == '/')
    {
      position = open + 1;
      continue;
    }
    std::size_t name_end = open + 1;
    while (name_end < body.size() && body[name_end] != '>' && body[name_end] != '/' &&
           !is_xml_whitespace(body[name_end]))
    {
      ++name_end;
    }
    const std::string property_name(body.substr(open + 1, name_end - open - 1));
    if (property_name.empty())
    {
      position = open + 1;
      continue;
    }
    const std::optional<ElementMatch> child = find_element(body, property_name, open);
    if (!child.has_value())
    {
      position = open + 1;
      continue;
    }
    properties.emplace(property_name, std::string(core::trimmed_view(child->inner_text)));
    position = child->resume_position;
  }
  return properties;
}

/// Shortest possible whole-value property reference: "${}" (empty name).
constexpr std::size_t kMinPropertyReferenceLength = 3;

/// Outcome of a one-level `${property}` lookup, shared by `<version>`,
/// `<groupId>` and `<artifactId>`. `value` is always what a
/// caller should use for a literal or successfully-substituted field; for an
/// unresolved reference it is `raw_text`, UNCHANGED, so a caller that wants to
/// keep going with the original text already has it (groupId/artifactId do;
/// version does not: see parse_pom).
struct PropertyResolution
{
  std::string value;
  std::string property_name;  ///< the `${name}` looked up; empty when raw_text carried no reference
  bool resolved = false;
};

/// Resolve one whole-value `${name}` reference against `properties`, one
/// level deep, no recursion. A value that is not of the shape `${...}` at all
/// passes through as already-literal (`resolved = true`, `property_name`
/// empty). A whole-value `${name}` reference is looked up; `resolved = true`
/// only when the name is present, non-empty, and its value does not itself
/// contain `${`. Anything else: name absent, value empty, value itself
/// still `${`-laden, or `raw_text` only PARTIALLY containing `${` (e.g.
/// `"1.${x}"`): is `resolved = false`.
PropertyResolution resolve_property_reference(const std::string& raw_text,
                                              const std::map<std::string, std::string>& properties)
{
  PropertyResolution resolution;
  resolution.value = raw_text;
  if (raw_text.size() >= kMinPropertyReferenceLength && raw_text.substr(0, 2) == "${" &&
      raw_text.back() == '}')
  {
    resolution.property_name = raw_text.substr(2, raw_text.size() - 3);
    const auto property_iterator = properties.find(resolution.property_name);
    if (property_iterator != properties.end() && !property_iterator->second.empty() &&
        property_iterator->second.find("${") == std::string::npos)
    {
      resolution.value = property_iterator->second;
      resolution.resolved = true;
    }
  }
  else if (raw_text.find("${") == std::string::npos)
  {
    resolution.resolved = true;  // already literal, nothing to substitute
  }
  // else: partial interpolation: unresolvable at one level, by design.
  return resolution;
}

/// Canonicalize `component.purl` in place, warning when the produced purl is
/// somehow invalid (defensive: percent-encoding should make that impossible).
void canonicalize_purl(core::Component& component,
                       core::Result<std::vector<core::Component>>& result)
{
  const core::Result<core::Purl> parsed_purl = core::Purl::parse(component.purl);
  if (!parsed_purl.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "maven: produced purl failed validation: " + component.purl, "maven");
  }
  else
  {
    component.purl = parsed_purl.value.canonical();
  }
}

/// Append one `pkg:maven` component. The groupId is the purl namespace :
/// dotted, single-segment, so plain `percent_encode` (never the `/`-preserving
/// namespace variant) keeps any stray structural byte escaped.
void emit_maven_component(std::string_view group_id, std::string_view artifact_id,
                          std::string_view version, core::Scope scope, core::Confidence confidence,
                          std::string detail, std::vector<core::Component>& components,
                          core::Result<std::vector<core::Component>>& result)
{
  core::Component component;
  component.name = std::string(group_id) + ":" + std::string(artifact_id);
  component.version = std::string(version);
  component.purl = "pkg:maven/" + core::percent_encode(group_id) + "/" +
                   core::percent_encode(artifact_id) + "@" + core::percent_encode(version);
  // The groupId is maven's own namespace for who publishes the artifact
  // (Maven Central enforces one groupId per publisher/organization), so it
  // doubles as NTIA/CRA supplier evidence with no extra parsing.
  component.supplier = std::string(group_id);
  component.scope = scope;
  component.evidence.push_back({core::Source::Manifest, std::move(detail), confidence});
  canonicalize_purl(component, result);
  components.push_back(std::move(component));
}

/// Parse one pom.xml with the minimal scanner (see the header for its exact
/// scope). Declarations, not resolver output -> Confidence::Medium, except a
/// dependency whose groupId/artifactId could not be fully resolved from
/// `<properties>`, which is downgraded to Low.
void parse_pom(std::string_view bytes, const std::string& label, std::size_t package_limit,
               std::size_t& package_budget, std::vector<core::Component>& components,
               core::Result<std::vector<core::Component>>& result)
{
  const std::string cleaned = strip_comments_and_unwrap_cdata(bytes);

  // Parent coordinates first (they feed the project.* pseudo-properties),
  // then drop the span so the nearest-tag heuristic below cannot mistake the
  // parent's version for the pom's own.
  std::optional<std::string> parent_group_id;
  std::optional<std::string> parent_version;
  const std::optional<ElementMatch> parent = find_element(cleaned, "parent", 0);
  if (parent.has_value())
  {
    parent_group_id = first_element_text(parent->inner_text, "groupId");
    parent_version = first_element_text(parent->inner_text, "version");
  }
  std::string working = remove_elements(cleaned, "parent");
  working = remove_elements(working, "dependencyManagement");
  working = remove_elements(working, "exclusions");

  // The pom's own coordinates: nearest tag before the first <dependencies>
  // block (conventional pom order), falling back to the parent's.
  const std::size_t dependencies_position = working.find("<dependencies");
  const std::string_view coordinate_region = std::string_view(working).substr(
      0, (dependencies_position == std::string::npos) ? working.size() : dependencies_position);
  std::optional<std::string> project_group_id = first_element_text(coordinate_region, "groupId");
  if (!project_group_id.has_value() || project_group_id->empty())
  {
    project_group_id = parent_group_id;
  }
  std::optional<std::string> project_version = first_element_text(coordinate_region, "version");
  if (!project_version.has_value() || project_version->empty())
  {
    project_version = parent_version;
  }

  // artifactId is NEVER inherited from <parent> in Maven: sibling modules
  // under one parent must have distinct artifactIds: so unlike groupId/
  // version there is no parent-fallback variable: the existing <parent>
  // extraction above never even reads <parent><artifactId>.
  const std::optional<std::string> project_artifact_id =
      first_element_text(coordinate_region, "artifactId");

  // The pom's own <licenses><license><name>: first entry wins,
  // verbatim, no SPDX normalization.
  const std::optional<std::string> project_license = first_pom_license_name(coordinate_region);

  // The pom's own coordinates ARE this file's identity: unlike a
  // <dependency> entry, never one of the pom's own dependencies. Same gap
  // class as vcpkg's ports-registry own-identity fix. Emitted
  // unconditionally, for every pom.xml: unlike vcpkg's `ports/` registry,
  // Maven has no directory-shape signal to distinguish a vendored/reactor
  // module's own pom from the top-level pom of the project bomwerk itself is
  // scanning, so a self-scan will list its own product as a component of its
  // own SBOM: an accepted tradeoff, deliberately narrower for vcpkg because
  // that signal exists there. Declared, not resolved -> Confidence::High,
  // matching vcpkg's own-identity reasoning: a hardcoded fact in the file,
  // not an interpolated reference.
  if (project_group_id.has_value() && !project_group_id->empty() &&
      project_artifact_id.has_value() && !project_artifact_id->empty() &&
      project_version.has_value() && !project_version->empty())
  {
    emit_maven_component(*project_group_id, *project_artifact_id, *project_version,
                         core::Scope::Required, core::Confidence::High, label + " own-identity",
                         components, result);
    if (project_license.has_value())
    {
      components.back().license = *project_license;
    }
  }
  else
  {
    // Mirrors vcpkg's component_from_port_identity: warn rather than
    // silently drop a pom's own identity when it can't be resolved.
    result.warn(core::WarningCode::kSelfIdentityUnresolvable,
                "maven: " + label +
                    ": pom lacks a resolvable groupId/artifactId/version, self-identity skipped",
                "maven");
  }

  std::map<std::string, std::string> properties = collect_pom_properties(working);
  if (project_version.has_value() && !project_version->empty())
  {
    properties["project.version"] = *project_version;
  }
  if (project_group_id.has_value() && !project_group_id->empty())
  {
    properties["project.groupId"] = *project_group_id;
  }
  if (parent_version.has_value() && !parent_version->empty())
  {
    properties["project.parent.version"] = *parent_version;
  }

  std::size_t malformed_dependency_count = 0;
  std::size_t unresolved_version_count = 0;
  std::size_t unresolved_identity_count = 0;
  std::size_t position = 0;
  while (true)
  {
    const std::optional<ElementMatch> dependency = find_element(working, "dependency", position);
    if (!dependency.has_value())
    {
      break;
    }
    position = dependency->resume_position;
    const std::string_view body = dependency->inner_text;

    const std::optional<std::string> group_id = first_element_text(body, "groupId");
    const std::optional<std::string> artifact_id = first_element_text(body, "artifactId");
    if (!group_id.has_value() || group_id->empty() || !artifact_id.has_value() ||
        artifact_id->empty())
    {
      ++malformed_dependency_count;
      continue;
    }

    // Version resolution: literal, or ONE `${property}` lookup: a value that
    // itself still contains `${` stays unresolved (no recursion, by design).
    std::optional<std::string> version = first_element_text(body, "version");
    std::string version_property_name;
    if (version.has_value())
    {
      const PropertyResolution version_resolution =
          resolve_property_reference(*version, properties);
      if (version_resolution.resolved)
      {
        version = version_resolution.value;
        version_property_name = version_resolution.property_name;
      }
      else
      {
        version.reset();
      }
    }
    if (!version.has_value() || version->empty())
    {
      ++unresolved_version_count;
      continue;
    }

    // groupId/artifactId resolution: the SAME one-level lookup as
    // version above, but an unresolved reference is DOWNGRADED and KEPT, never
    // dropped: matching every other "can't fully resolve an identifier" case
    // in this codebase (cmake_deps::apply_unresolved_downgrade, vcpkg, python,
    // submodules, conan) rather than version's own drop-on-unresolved
    // behavior: losing a real dependency from a CRA-evidence SBOM because one
    // field didn't resolve is worse than keeping it, clearly flagged.
    const PropertyResolution group_id_resolution =
        resolve_property_reference(*group_id, properties);
    const PropertyResolution artifact_id_resolution =
        resolve_property_reference(*artifact_id, properties);
    const bool identity_unresolved =
        !group_id_resolution.resolved || !artifact_id_resolution.resolved;
    if (identity_unresolved)
    {
      ++unresolved_identity_count;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "maven: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "maven");
      result.complete = false;
      break;
    }
    --package_budget;

    core::Scope scope = core::Scope::Required;
    const std::optional<std::string> declared_scope = first_element_text(body, "scope");
    const std::optional<std::string> optional_flag = first_element_text(body, "optional");
    if (declared_scope.has_value() &&
        core::equals_ascii_ignore_case(*declared_scope, kMavenTestScope))
    {
      scope = core::Scope::Excluded;  // the pom itself says test-only
    }
    else if (optional_flag.has_value() && core::equals_ascii_ignore_case(*optional_flag, "true"))
    {
      scope = core::Scope::Optional;
    }

    std::string detail = label;
    if (declared_scope.has_value() && !declared_scope->empty() && scope != core::Scope::Excluded)
    {
      detail += " scope=" + *declared_scope;
    }
    if (group_id_resolution.resolved && !group_id_resolution.property_name.empty())
    {
      detail += " groupId-from-property " + group_id_resolution.property_name;
    }
    if (artifact_id_resolution.resolved && !artifact_id_resolution.property_name.empty())
    {
      detail += " artifactId-from-property " + artifact_id_resolution.property_name;
    }
    if (!version_property_name.empty())
    {
      detail += " version-from-property " + version_property_name;
    }
    // A pom declares, it does not resolve -> Medium, unless its groupId/
    // artifactId could not be fully resolved, in which case the identity
    // itself is untrustworthy -> Low.
    const core::Confidence confidence =
        identity_unresolved ? core::Confidence::Low : core::Confidence::Medium;
    emit_maven_component(group_id_resolution.value, artifact_id_resolution.value, *version, scope,
                         confidence, std::move(detail), components, result);
  }

  if (malformed_dependency_count > 0)
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "maven: " + std::to_string(malformed_dependency_count) +
                    " dependency element(s) without groupId/artifactId skipped: " + label,
                "maven");
  }
  if (unresolved_version_count > 0)
  {
    result.warn(core::WarningCode::kEntriesSkippedUnresolved,
                "maven: " + std::to_string(unresolved_version_count) +
                    " dependency(ies) without a resolvable version skipped: " + label,
                "maven");
  }
  if (unresolved_identity_count > 0)
  {
    result.warn(core::WarningCode::kUnresolvedVariableOrInterpolation,
                "maven: " + std::to_string(unresolved_identity_count) +
                    " dependency(ies) with an unresolved groupId/artifactId property reported at "
                    "low confidence: " +
                    label,
                "maven");
  }
}

/// Parse one gradle.lockfile's `group:artifact:version=configurations` lines.
/// Gradle's own resolver output -> Confidence::High.
void parse_gradle_lockfile(std::string_view bytes, const std::string& label,
                           std::size_t package_limit, std::size_t& package_budget,
                           std::vector<core::Component>& components,
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
    if (line.empty() || line.front() == '#')
    {
      continue;
    }
    const std::size_t equals_position = line.find('=');
    if (equals_position == std::string_view::npos)
    {
      ++malformed_line_count;
      continue;
    }
    const std::string_view coordinate = line.substr(0, equals_position);
    const std::string_view configurations = line.substr(equals_position + 1);
    if (coordinate == kGradleEmptyCoordinate)
    {
      continue;  // configurations that resolved to no dependencies at all
    }
    const std::size_t first_colon = coordinate.find(':');
    const std::size_t second_colon = (first_colon == std::string_view::npos)
                                         ? std::string_view::npos
                                         : coordinate.find(':', first_colon + 1);
    if (first_colon == std::string_view::npos || second_colon == std::string_view::npos ||
        coordinate.find(':', second_colon + 1) != std::string_view::npos)
    {
      ++malformed_line_count;
      continue;
    }
    const std::string_view group_id = coordinate.substr(0, first_colon);
    const std::string_view artifact_id =
        coordinate.substr(first_colon + 1, second_colon - first_colon - 1);
    const std::string_view version = coordinate.substr(second_colon + 1);
    if (group_id.empty() || artifact_id.empty() || version.empty())
    {
      ++malformed_line_count;
      continue;
    }

    if (package_budget == 0)
    {
      result.warn(core::WarningCode::kEntryLimitReached,
                  "maven: package limit " + std::to_string(package_limit) +
                      " reached; remaining entries skipped",
                  "maven");
      result.complete = false;
      break;
    }
    --package_budget;

    // Every configuration name starting with `test` means the lockfile itself
    // says test-only: recorded, never guessed. No configurations = no claim.
    core::Scope scope = core::Scope::Required;
    bool has_any_configuration = false;
    bool every_configuration_is_test = true;
    std::size_t token_start = 0;
    while (token_start <= configurations.size())
    {
      const std::size_t token_end = configurations.find(',', token_start);
      const std::string_view token = core::trimmed_view(configurations.substr(
          token_start, (token_end == std::string_view::npos) ? std::string_view::npos
                                                             : token_end - token_start));
      token_start =
          (token_end == std::string_view::npos) ? configurations.size() + 1 : token_end + 1;
      if (token.empty())
      {
        continue;
      }
      has_any_configuration = true;
      if (token.size() < kTestConfigurationPrefix.size() ||
          !core::equals_ascii_ignore_case(token.substr(0, kTestConfigurationPrefix.size()),
                                          kTestConfigurationPrefix))
      {
        every_configuration_is_test = false;
      }
    }
    if (has_any_configuration && every_configuration_is_test)
    {
      scope = core::Scope::Excluded;
    }

    std::string detail = label;
    if (has_any_configuration)
    {
      detail += " (configurations " + std::string(configurations) + ")";
    }
    emit_maven_component(group_id, artifact_id, version, scope, core::Confidence::High,
                         std::move(detail), components, result);
  }

  if (malformed_line_count > 0)
  {
    result.warn(
        core::WarningCode::kMalformedEntrySkipped,
        "maven: " + std::to_string(malformed_line_count) + " malformed line(s) skipped: " + label,
        "maven");
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
    const std::string filename = relative_path.filename().string();
    const bool is_pom = filename == kPomName;
    const bool is_gradle_lockfile = filename == kGradleLockfileName;
    if (!is_pom && !is_gradle_lockfile)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "maven: file limit reached; remaining maven files skipped", "maven");
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
      result.warn(core::WarningCode::kUnreadableFile, "maven: unreadable file: " + label, "maven");
      continue;
    }
    std::string_view bytes = file_read.bytes;
    if (file_read.truncated)
    {
      if (is_gradle_lockfile)
      {
        // Line-based: the readable prefix still parses; drop the cut-off tail
        // line so it cannot count as malformed.
        result.warn(core::WarningCode::kFileSizeLimitExceeded,
                    "maven: file exceeds size limit, parsing first part only: " + label, "maven");
        const std::size_t last_newline = bytes.rfind('\n');
        bytes = (last_newline == std::string_view::npos) ? std::string_view{}
                                                         : bytes.substr(0, last_newline + 1);
      }
      else
      {
        // A truncated XML document cannot be paired reliably; skipping beats
        // guessing.
        result.warn(core::WarningCode::kFileSizeLimitExceeded,
                    "maven: file exceeds size limit, skipped: " + label, "maven");
        continue;
      }
    }

    if (is_pom)
    {
      parse_pom(bytes, label, options.max_total_packages, package_budget, components, result);
    }
    else
    {
      parse_gradle_lockfile(bytes, label, options.max_total_packages, package_budget, components,
                            result);
    }
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

}  // namespace bomwerk::parsers::lockfiles::maven
