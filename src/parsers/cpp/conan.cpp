#include "parsers/cpp/conan.hpp"

#include <cstddef>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"
#include "parsers/cpp/conan_ref.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::cpp::conan
{
namespace
{

using core::json_utils::exceeds_json_nesting_depth;
using core::json_utils::kMaxJsonNestingDepth;
using core::json_utils::without_utf8_bom;

constexpr std::string_view kConanfileTxtName = "conanfile.txt";

/// conanfile.txt sections whose entries are dependency references. Other
/// sections ([generators], [options], [layout], …) are configuration, not
/// dependencies, and are skipped without a warning.
constexpr std::string_view kRequirementSections[] = {"requires", "tool_requires", "build_requires",
                                                     "test_requires"};

bool is_requirement_section(std::string_view section_name)
{
  for (const std::string_view candidate : kRequirementSections)
  {
    if (section_name == candidate)
    {
      return true;
    }
  }
  return false;
}

/// Drop an inline comment: text from a '#' that FOLLOWS whitespace. A '#'
/// glued to the reference is a recipe revision (`zlib/1.2.13#rrev`), which
/// conan's own conanfile.txt reader also distinguishes this way.
std::string_view without_inline_comment(std::string_view line)
{
  for (std::size_t character_index = 1; character_index < line.size(); ++character_index)
  {
    if (line[character_index] == '#' &&
        (line[character_index - 1] == ' ' || line[character_index - 1] == '\t'))
    {
      return line.substr(0, character_index);
    }
  }
  return line;
}

/// Confidence a reference earns from its own shape: a pinned recipe revision
/// (or a lockfile origin, `resolved_by_conan`) is High: conan's resolution
/// output; an exact declared version is Medium; a range or missing version is
/// Low (a constraint is not a pin).
core::Confidence confidence_for_reference(const ConanReference& reference, bool resolved_by_conan)
{
  if (resolved_by_conan || !reference.revision.empty())
  {
    return core::Confidence::High;
  }
  if (reference.version.empty() || is_conan_version_range(reference.version))
  {
    return core::Confidence::Low;
  }
  return core::Confidence::Medium;
}

/// Build one component from a parsed reference. Returns nullopt (with a
/// warning) when no name is recoverable: an identity-less entry would only
/// pollute the SBOM. Dogfoods `core::Purl::parse` like the other producers.
std::optional<core::Component> component_from_reference(
    const ConanReference& reference, const std::string& evidence_detail,
    core::Confidence confidence, const ParseOptions& options,
    core::Result<std::vector<core::Component>>& result)
{
  if (reference.name.empty())
  {
    result.warn(core::WarningCode::kSelfIdentityUnresolvable,
                "conan: " + evidence_detail + ": requirement has no package name", "conan");
    return std::nullopt;
  }
  core::Component component;
  component.name = reference.name;
  component.version = reference.version;
  component.purl = build_conan_purl(reference, options.emit_recipe_revision_qualifier);
  // The reference's `@user` segment is conan's own publisher field :
  // NTIA/CRA supplier evidence straight from the manifest. Most conancenter
  // recipes carry no user/channel at all, so this stays empty for them
  // rather than inventing a supplier the reference never stated.
  component.supplier = reference.user;

  std::string detail = evidence_detail;
  if (!options.emit_recipe_revision_qualifier && !reference.revision.empty())
  {
    // The revision still matters as evidence even when it is kept out of the
    // identity purl (the operator's configurable-identity decision).
    detail += " rev=" + reference.revision;
  }
  component.evidence.push_back({core::Source::Manifest, detail, confidence});

  core::canonicalize_purl(component.purl, "conan", result.warnings);
  return component;
}

/// Consume one unit of the shared cross-file requirement budget. Returns
/// true when the caller should proceed; false when the budget is already
/// exhausted (a warning has been emitted and the caller should stop parsing
/// this file: each exhausted call site still warns independently, so a
/// scan with many manifests left to skip may repeat this warning once per
/// file; that is pre-existing, unchanged behavior, not introduced here).
bool try_consume_requirement_budget(std::size_t& requirement_budget,
                                    core::Result<std::vector<core::Component>>& result)
{
  if (requirement_budget == 0)
  {
    result.warn(core::WarningCode::kEntryLimitReached,
                "conan: requirement limit reached; remaining entries skipped", "conan");
    return false;
  }
  --requirement_budget;
  return true;
}

/// Parse one conanfile.txt: section-oriented, line-based. `label` is the
/// root-relative path used in warnings and evidence details.
void parse_conanfile_txt(const std::string& bytes, const std::string& label,
                         const ParseOptions& options, std::size_t& requirement_budget,
                         std::vector<core::Component>& components,
                         core::Result<std::vector<core::Component>>& result)
{
  std::string_view remaining = without_utf8_bom(bytes);
  std::string current_section;
  while (!remaining.empty())
  {
    const std::size_t newline_position = remaining.find('\n');
    std::string_view line = remaining.substr(0, newline_position);
    remaining = (newline_position == std::string_view::npos)
                    ? std::string_view{}
                    : remaining.substr(newline_position + 1);

    line = core::trimmed_view(line);
    if (line.empty() || line.front() == '#' || line.front() == ';')
    {
      continue;
    }
    if (line.front() == '[')
    {
      const std::size_t closing_bracket = line.find(']');
      if (closing_bracket == std::string_view::npos)
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "conan: " + label + ": unterminated section header", "conan");
        current_section.clear();
        continue;
      }
      current_section =
          core::to_lower_ascii(core::trimmed_view(line.substr(1, closing_bracket - 1)));
      continue;
    }
    if (!is_requirement_section(current_section))
    {
      continue;
    }
    if (!try_consume_requirement_budget(requirement_budget, result))
    {
      return;
    }

    const std::string_view reference_text = core::trimmed_view(without_inline_comment(line));
    const ConanReference reference = parse_conan_reference(reference_text);
    const std::string evidence_detail = label + " [" + current_section + "]";
    std::optional<core::Component> component = component_from_reference(
        reference, evidence_detail, confidence_for_reference(reference, false), options, result);
    if (component.has_value())
    {
      components.push_back(std::move(*component));
    }
  }
}

constexpr std::string_view kConanfilePyName = "conanfile.py";
constexpr std::size_t kMaxPythonContinuationLines = 50;

/// Python attributes / self-methods whose string arguments are requirements.
constexpr std::string_view kPythonRequirementAttributes[] = {
    "requires", "build_requires", "tool_requires", "test_requires", "python_requires"};
constexpr std::string_view kPythonRequirementCalls[] = {
    "self.requires(", "self.build_requires(", "self.tool_requires(", "self.test_requires("};

/// One extracted python string literal plus whether it was an f-string /
/// contains interpolation braces -- the `${var}` analog of this ecosystem.
struct PythonStringLiteral
{
  std::string value;
  bool interpolated = false;
};

/// State carried across lines: are we inside a triple-quoted string, and with
/// which delimiter? Docstrings must not produce phantom requirements.
struct PythonScanState
{
  bool in_triple_quote = false;
  char triple_quote_character = '"';
};

/// True when 3 characters starting at `index` all equal `quote_character` :
/// an allocation-free triple-quote check. Requires the full 3 characters to
/// be present (never matches on fewer, even though `substr`'s own clamping
/// would have made a length-mismatched comparison fail anyway).
bool starts_with_triple_quote(std::string_view line, std::size_t index, char quote_character)
{
  return index + 3 <= line.size() && line[index] == quote_character &&
         line[index + 1] == quote_character && line[index + 2] == quote_character;
}

/// Remove comments and record string literals for one physical line. Returns
/// the line with comments stripped; literals (outside docstrings) land in
/// `literals`. Tracks single-line ' and " strings with backslash escapes and
/// toggles `state.in_triple_quote` on \"\"\"/''' so multi-line docstrings are
/// skipped wholesale. Bounded: one pass over the line, no backtracking
/// precedent: no std::regex, no catastrophic backtracking).
std::string scan_python_line(std::string_view line, PythonScanState& state,
                             std::vector<PythonStringLiteral>& literals)
{
  std::string code_text;
  code_text.reserve(line.size());
  std::size_t character_index = 0;
  while (character_index < line.size())
  {
    const char character = line[character_index];
    if (state.in_triple_quote)
    {
      if (starts_with_triple_quote(line, character_index, state.triple_quote_character))
      {
        state.in_triple_quote = false;
        character_index += 3;
        continue;
      }
      ++character_index;
      continue;
    }
    if (character == '#')
    {
      break;  // comment: rest of line is not code
    }
    if (character == '"' || character == '\'')
    {
      if (starts_with_triple_quote(line, character_index, character))
      {
        state.in_triple_quote = true;
        state.triple_quote_character = character;
        character_index += 3;
        continue;
      }
      // Single-line literal: honor backslash escapes; note a preceding 'f'.
      const bool is_format_string =
          !code_text.empty() && (code_text.back() == 'f' || code_text.back() == 'F');
      PythonStringLiteral literal;
      ++character_index;
      while (character_index < line.size() && line[character_index] != character)
      {
        if (line[character_index] == '\\' && character_index + 1 < line.size())
        {
          literal.value.push_back(line[character_index + 1]);
          character_index += 2;
          continue;
        }
        literal.value.push_back(line[character_index]);
        ++character_index;
      }
      ++character_index;  // past the closing quote (or end of line if unterminated)
      literal.interpolated = is_format_string || literal.value.find('{') != std::string::npos;
      literals.push_back(std::move(literal));
      code_text.push_back('\x01');  // placeholder so bracket counting skips string contents
      continue;
    }
    code_text.push_back(character);
    ++character_index;
  }
  return code_text;
}

/// Net bracket depth change of comment-and-string-stripped python code.
int bracket_depth_delta(std::string_view code_text)
{
  int depth_delta = 0;
  for (const char character : code_text)
  {
    if (character == '(' || character == '[' || character == '{')
    {
      ++depth_delta;
    }
    if (character == ')' || character == ']' || character == '}')
    {
      --depth_delta;
    }
  }
  return depth_delta;
}

/// True when `code_text` is an assignment to `attribute_name` at statement
/// start: optional indentation, the exact word, optional spaces, '=' but not
/// '=='. Example: matches "    requires = ..." but not "requires_extra =" and
/// not "if requires == x".
bool is_attribute_assignment(std::string_view code_text, std::string_view attribute_name)
{
  const std::string_view stripped = core::trimmed_view(code_text);
  if (stripped.rfind(attribute_name, 0) != 0)
  {
    return false;
  }
  std::string_view after_name = stripped.substr(attribute_name.size());
  const std::string_view after_spaces = core::trimmed_view(after_name);
  return !after_spaces.empty() && after_spaces.front() == '=' &&
         (after_spaces.size() == 1 || after_spaces[1] != '=');
}

/// Emit one requirement extracted from python text, honoring the
/// interpolation rules: interpolated NAME -> warn + skip (no identity);
/// interpolated VERSION -> name kept, version emptied, Low + warn.
void emit_python_requirement(const PythonStringLiteral& literal, const std::string& label,
                             const std::string& section, const ParseOptions& options,
                             std::vector<core::Component>& components,
                             core::Result<std::vector<core::Component>>& result)
{
  ConanReference reference = parse_conan_reference(literal.value);
  core::Confidence confidence = confidence_for_reference(reference, false);
  if (literal.interpolated)
  {
    if (reference.name.find('{') != std::string::npos || reference.name.empty())
    {
      result.warn(
          core::WarningCode::kUnresolvedVariableOrInterpolation,
          "conan: " + label + ": unresolved interpolation in requirement '" + literal.value + "'",
          "conan");
      return;
    }
    if (reference.version.find('{') != std::string::npos)
    {
      result.warn(
          core::WarningCode::kUnresolvedVariableOrInterpolation,
          "conan: " + label + ": unresolved version interpolation for '" + reference.name + "'",
          "conan");
      reference.version.clear();
      confidence = core::Confidence::Low;
    }
  }
  std::optional<core::Component> component = component_from_reference(
      reference, label + " [" + section + "]", confidence, options, result);
  if (component.has_value())
  {
    components.push_back(std::move(*component));
  }
}

/// Parse one conanfile.py by bounded text scan -- the file is NEVER executed
/// (Hard Rule 9: running a scanned repo's python is an RCE vector). Static
/// misses (computed requirements) are covered by conan.lock / --conan-graph.
void parse_conanfile_py(const std::string& bytes, const std::string& label,
                        const ParseOptions& options, std::size_t& requirement_budget,
                        std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  std::string_view remaining = without_utf8_bom(bytes);
  PythonScanState scan_state;
  int attribute_bracket_depth = 0;
  bool collecting_attribute = false;
  std::string collecting_section;
  std::size_t collecting_lines_remaining = 0;

  while (!remaining.empty())
  {
    const std::size_t newline_position = remaining.find('\n');
    std::string_view line = remaining.substr(0, newline_position);
    remaining = (newline_position == std::string_view::npos)
                    ? std::string_view{}
                    : remaining.substr(newline_position + 1);
    if (!line.empty() && line.back() == '\r')
    {
      line.remove_suffix(1);
    }

    std::vector<PythonStringLiteral> literals;
    const std::string code_text = scan_python_line(line, scan_state, literals);
    const bool line_continues = !code_text.empty() && code_text.back() == '\\';

    if (collecting_attribute)
    {
      // The kMaxPythonContinuationLines cap must actually count down: a
      // never-closing bracket (hostile or malformed input) must not collect
      // forever (Hard Rule 1 -- bounded, never a runaway loop).
      if (collecting_lines_remaining == 0)
      {
        result.warn(core::WarningCode::kEntryLimitReached,
                    "conan: " + label + ": requirement list too long, truncated", "conan");
        collecting_attribute = false;
      }
      else
      {
        --collecting_lines_remaining;
        for (const PythonStringLiteral& literal : literals)
        {
          if (!try_consume_requirement_budget(requirement_budget, result))
          {
            return;
          }
          emit_python_requirement(literal, label, collecting_section, options, components, result);
        }
        attribute_bracket_depth += bracket_depth_delta(code_text);
        if (attribute_bracket_depth <= 0 && !line_continues)
        {
          collecting_attribute = false;
        }
      }
      continue;
    }

    // Pattern A: attribute assignment at statement start.
    for (const std::string_view attribute_name : kPythonRequirementAttributes)
    {
      if (!is_attribute_assignment(code_text, attribute_name))
      {
        continue;
      }
      for (const PythonStringLiteral& literal : literals)
      {
        if (!try_consume_requirement_budget(requirement_budget, result))
        {
          return;
        }
        emit_python_requirement(literal, label, std::string(attribute_name), options, components,
                                result);
      }
      attribute_bracket_depth = bracket_depth_delta(code_text);
      if (attribute_bracket_depth > 0 || line_continues)
      {
        collecting_attribute = true;
        collecting_lines_remaining = kMaxPythonContinuationLines;
        collecting_section = std::string(attribute_name);
      }
      break;
    }
    if (collecting_attribute)
    {
      continue;
    }

    // Pattern B: self.requires(...)-family calls -- first string argument.
    for (const std::string_view call_prefix : kPythonRequirementCalls)
    {
      const std::size_t call_position = code_text.find(call_prefix);
      if (call_position == std::string_view::npos || literals.empty())
      {
        continue;
      }
      if (!try_consume_requirement_budget(requirement_budget, result))
      {
        return;
      }
      // "self.<method>(" -> section name is the method, without "self." and "(".
      const std::string section(call_prefix.substr(5, call_prefix.size() - 6));
      emit_python_requirement(literals.front(), label, section, options, components, result);
      break;
    }
  }
}

constexpr std::string_view kConanLockName = "conan.lock";

/// conan-2 lockfile top-level arrays holding requirement strings.
constexpr std::string_view kLockRequirementArrays[] = {"requires", "build_requires",
                                                       "python_requires", "config_requires"};

/// Emit one lockfile requirement string (conan-2 array entry or conan-1 node
/// ref). Lock entries are conan's own resolution output -> High confidence.
void emit_lock_requirement(const std::string& reference_text, const std::string& label,
                           const std::string& section, const ParseOptions& options,
                           std::size_t& requirement_budget,
                           std::vector<core::Component>& components,
                           core::Result<std::vector<core::Component>>& result)
{
  if (!try_consume_requirement_budget(requirement_budget, result))
  {
    return;
  }
  const ConanReference reference = parse_conan_reference(reference_text);
  std::optional<core::Component> component =
      component_from_reference(reference, label + " [" + section + "]",
                               confidence_for_reference(reference, true), options, result);
  if (component.has_value())
  {
    components.push_back(std::move(*component));
  }
}

/// Parse one conan.lock: conan-2 (`requires`/`build_requires`/… arrays) and
/// conan-1 (`graph_lock.nodes.*.ref`, consumer node "0" skipped). Parsed in
/// no-throw mode behind the depth pre-scan; malformed JSON degrades to one
/// warning (rule 1).
void parse_conan_lock(const std::string& bytes, const std::string& label,
                      const ParseOptions& options, std::size_t& requirement_budget,
                      std::vector<core::Component>& components,
                      core::Result<std::vector<core::Component>>& result)
{
  const std::string_view json_bytes = without_utf8_bom(bytes);
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "conan: " + label + ": JSON nesting exceeds depth limit, skipped", "conan");
    return;
  }
  const nlohmann::json parsed =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (parsed.is_discarded() || !parsed.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "conan: " + label + ": not valid JSON, skipped",
                "conan");
    return;
  }

  bool malformed_entry_reported = false;
  for (const std::string_view array_name : kLockRequirementArrays)
  {
    const auto array_iterator = parsed.find(array_name);
    if (array_iterator == parsed.end())
    {
      continue;  // key simply absent: a normal, well-formed lockfile shape
    }
    if (!array_iterator->is_array())
    {
      // Key present but the wrong shape: real dependencies were likely
      // dropped silently: warn once (not once per array) so the operator
      // knows the SBOM may be incomplete.
      if (!malformed_entry_reported)
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "conan: " + label + ": requirement entry could not be parsed, skipped",
                    "conan");
        malformed_entry_reported = true;
      }
      continue;
    }
    for (const nlohmann::json& entry : *array_iterator)
    {
      if (!entry.is_string())
      {
        if (!malformed_entry_reported)
        {
          result.warn(core::WarningCode::kMalformedEntrySkipped,
                      "conan: " + label + ": non-string requirement entry skipped", "conan");
          malformed_entry_reported = true;
        }
        continue;
      }
      emit_lock_requirement(entry.get<std::string>(), label, std::string(array_name), options,
                            requirement_budget, components, result);
    }
  }

  // conan-1: graph_lock.nodes: object of node objects, "0" is the consumer.
  // A present-but-malformed shape (not an object, missing/non-string ref, …)
  // means real dependencies were likely dropped silently: warn once so the
  // operator knows the SBOM may be incomplete, without failing the run
  // (rule 1: partial output beats none, but never a silent partial output).
  bool malformed_graph_lock_reported = false;
  const auto graph_lock_iterator = parsed.find("graph_lock");
  if (graph_lock_iterator != parsed.end())
  {
    if (!graph_lock_iterator->is_object())
    {
      result.warn(core::WarningCode::kMalformedEntrySkipped,
                  "conan: " + label + ": graph_lock entry could not be parsed, skipped", "conan");
      malformed_graph_lock_reported = true;
    }
    else
    {
      const auto nodes_iterator = graph_lock_iterator->find("nodes");
      const bool nodes_key_present = nodes_iterator != graph_lock_iterator->end();
      if (nodes_key_present && !nodes_iterator->is_object())
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "conan: " + label + ": graph_lock entry could not be parsed, skipped", "conan");
        malformed_graph_lock_reported = true;
      }
      else if (nodes_key_present)
      {
        for (const auto& [node_key, node_value] : nodes_iterator->items())
        {
          if (node_key == "0")
          {
            continue;
          }
          const auto reference_iterator =
              node_value.is_object() ? node_value.find("ref") : node_value.end();
          if (reference_iterator == node_value.end() || !reference_iterator->is_string())
          {
            if (!malformed_graph_lock_reported)
            {
              result.warn(core::WarningCode::kMalformedEntrySkipped,
                          "conan: " + label + ": graph_lock entry could not be parsed, skipped",
                          "conan");
              malformed_graph_lock_reported = true;
            }
            continue;
          }
          emit_lock_requirement(reference_iterator->get<std::string>(), label, "graph_lock",
                                options, requirement_budget, components, result);
        }
      }
    }
  }
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const core::FileIndex& file_index,
                                                 const fs::path& root, const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  std::vector<core::Component> components;
  std::size_t scanned_file_count = 0;
  std::size_t requirement_budget = options.max_total_requirements;

  for (const fs::path& relative_path : file_index.files)
  {
    const std::string filename = relative_path.filename().string();
    const bool is_txt_manifest = filename == kConanfileTxtName;
    const bool is_py_manifest = filename == kConanfilePyName;
    const bool is_lock_file = filename == kConanLockName;
    if (!is_txt_manifest && !is_py_manifest && !is_lock_file)
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "conan: file limit reached; remaining conan files skipped", "conan");
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "conan: unreadable file: " + label, "conan");
      continue;
    }
    if (file_read.truncated)
    {
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "conan: file exceeds size limit, parsing first part only: " + label, "conan");
    }
    if (is_txt_manifest)
    {
      parse_conanfile_txt(file_read.bytes, label, options, requirement_budget, components, result);
    }
    else if (is_py_manifest)
    {
      parse_conanfile_py(file_read.bytes, label, options, requirement_budget, components, result);
    }
    else
    {
      parse_conan_lock(file_read.bytes, label, options, requirement_budget, components, result);
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
  return result;
}

core::Result<std::vector<core::Component>> parse(const fs::path& root)
{
  return parse(root, ParseOptions{});
}

core::Result<std::vector<core::Component>> parse_graph_file(const fs::path& graph_json_path,
                                                            const ParseOptions& options)
{
  core::Result<std::vector<core::Component>> result;
  std::vector<core::Component> components;
  std::size_t requirement_budget = options.max_total_requirements;
  const std::string label = graph_json_path.filename().generic_string();

  const core::BoundedFileRead file_read =
      core::read_file_bounded(graph_json_path, options.max_graph_file_bytes);
  if (!file_read.readable)
  {
    result.warn(core::WarningCode::kUnreadableFile,
                "conan: unreadable graph file: " + graph_json_path.generic_string(), "conan");
    return result;
  }
  if (file_read.truncated)
  {
    result.warn(core::WarningCode::kFileSizeLimitExceeded,
                "conan: graph file exceeds size limit, skipped: " + label, "conan");
    return result;  // truncated JSON cannot parse; skipping beats guessing
  }

  const std::string_view json_bytes = without_utf8_bom(file_read.bytes);
  if (exceeds_json_nesting_depth(json_bytes, kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "conan: " + label + ": JSON nesting exceeds depth limit, skipped", "conan");
    return result;
  }
  const nlohmann::json parsed =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (parsed.is_discarded() || !parsed.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson, "conan: " + label + ": not valid JSON, skipped",
                "conan");
    return result;
  }

  const auto graph_iterator = parsed.find("graph");
  if (graph_iterator == parsed.end() || !graph_iterator->is_object())
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "conan: " + label + ": no graph.nodes object, is this `conan graph info` output?",
                "conan");
    return result;
  }
  const auto nodes_iterator = graph_iterator->find("nodes");
  if (nodes_iterator == graph_iterator->end() || !nodes_iterator->is_object())
  {
    result.warn(core::WarningCode::kMalformedEntrySkipped,
                "conan: " + label + ": no graph.nodes object, is this `conan graph info` output?",
                "conan");
    return result;
  }
  bool malformed_node_reported = false;
  for (const auto& [node_key, node_value] : nodes_iterator->items())
  {
    if (node_key == "0")
    {
      continue;  // "0" is the consumer project itself, not a dependency
    }
    const auto reference_iterator =
        node_value.is_object() ? node_value.find("ref") : node_value.end();
    if (reference_iterator == node_value.end() || !reference_iterator->is_string())
    {
      // Node present but the wrong shape (not an object, or missing/non-string
      // "ref"): a real dependency was likely dropped silently: warn once
      // (not once per node), symmetric with the same protection already
      // given to malformed graph_lock shapes in parse_conan_lock.
      if (!malformed_node_reported)
      {
        result.warn(core::WarningCode::kMalformedEntrySkipped,
                    "conan: " + label + ": graph node could not be parsed, skipped", "conan");
        malformed_node_reported = true;
      }
      continue;
    }
    emit_lock_requirement(reference_iterator->get<std::string>(), label, "graph", options,
                          requirement_budget, components, result);
  }

  result.value = core::merge_all(std::move(components));
  return result;
}

}  // namespace bomwerk::parsers::cpp::conan
