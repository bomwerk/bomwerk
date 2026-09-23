#include "parsers/ci/github_actions.hpp"

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/exclusions.hpp"
#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/percent.hpp"
#include "core/purl.hpp"
#include "core/submodule_paths.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::ci::github_actions
{
namespace
{

/// Characters that open a quoted region. Both spellings appear in the wild
/// (`uses: 'owner/repo@v1'` and `uses: "owner/repo@v1"` are both valid YAML).
constexpr std::string_view kQuoteCharacters = "\"'";

/// Value prefixes that open a multi-line block scalar (`|`, `>`, with
/// optional chomping/indentation indicators such as `|-`, `>2`): a `run:`
/// shell script or a folded `restore-keys:` list, both common in real
/// workflow files. Its body is everything indented deeper than the key that
/// opened it and must be skipped as a unit, or free text inside it (a shell
/// command that happens to mention "uses:") could masquerade as a reference.
constexpr std::string_view kBlockScalarIndicators = "|>";

/// A quoted scalar needs at least its two delimiters before there is an
/// interior to strip.
constexpr std::size_t kDelimiterPairLength = 2;

constexpr std::string_view kUsesKey = "uses";

/// Sentinel for "no block scalar body is currently being skipped".
constexpr std::size_t kNoBlockScalar = static_cast<std::size_t>(-1);

/// True when `relative_path` is a workflow file GitHub itself would run:
/// directly under `.github/workflows/`, `.yml` or `.yaml`. GitHub does not
/// recognize workflows nested any deeper, so neither does this scan.
bool is_workflow_file(const fs::path& relative_path)
{
  if (relative_path.parent_path() != fs::path(".github") / "workflows")
  {
    return false;
  }
  const std::string extension = relative_path.extension().string();
  return extension == ".yml" || extension == ".yaml";
}

/// Offset of the first unquoted ':' that ends `content` or is followed by a
/// space, or `npos` when there is none. A Berry-style quoted key such as
/// `"uses": owner/repo@v1` has no bearing here (workflow keys are never
/// quoted in practice), but the quote-awareness keeps this consistent with
/// `core::yaml_subset`'s identical rule and safe against a quoted value that
/// happens to contain a colon (a `run:` one-liner, say).
std::size_t key_separator_offset(std::string_view content)
{
  char open_quote = '\0';
  for (std::size_t index = 0; index < content.size(); ++index)
  {
    const char character = content[index];
    if (open_quote != '\0')
    {
      if (character == '\\' && open_quote == '"')
      {
        ++index;  // an escaped byte never closes the region
        continue;
      }
      if (character == open_quote)
      {
        open_quote = '\0';
      }
      continue;
    }
    if (kQuoteCharacters.find(character) != std::string_view::npos)
    {
      open_quote = character;
      continue;
    }
    if (character == ':' && (index + 1 == content.size() || content[index + 1] == ' '))
    {
      return index;
    }
  }
  return std::string_view::npos;
}

/// View of `content` up to a '#' comment, honoring quotes: a '#' starts a
/// comment only at the start of the content or after whitespace, matching
/// `core::yaml_subset`'s identical rule.
std::string_view without_inline_comment(std::string_view content)
{
  char open_quote = '\0';
  for (std::size_t index = 0; index < content.size(); ++index)
  {
    const char character = content[index];
    if (open_quote != '\0')
    {
      if (character == '\\' && open_quote == '"')
      {
        ++index;
        continue;
      }
      if (character == open_quote)
      {
        open_quote = '\0';
      }
      continue;
    }
    if (kQuoteCharacters.find(character) != std::string_view::npos)
    {
      open_quote = character;
      continue;
    }
    const bool follows_whitespace =
        index == 0 || content[index - 1] == ' ' || content[index - 1] == '\t';
    if (character == '#' && follows_whitespace)
    {
      return content.substr(0, index);
    }
  }
  return content;
}

/// Strip one matching pair of surrounding quotes. The interior is returned
/// verbatim: escapes are honored when locating boundaries, never rewritten.
std::string_view unquoted(std::string_view text)
{
  if (text.size() < kDelimiterPairLength)
  {
    return text;
  }
  const char first = text.front();
  if (kQuoteCharacters.find(first) == std::string_view::npos || text.back() != first)
  {
    return text;
  }
  return text.substr(1, text.size() - kDelimiterPairLength);
}

bool opens_block_scalar(std::string_view value)
{
  return !value.empty() && kBlockScalarIndicators.find(value.front()) != std::string_view::npos;
}

/// One `key: value` mapping line. `key` is already unquoted; `value` is
/// trimmed but not yet unquoted, so a caller can still check
/// `opens_block_scalar` on it before deciding whether to consume it.
struct KeyValueLine
{
  bool matched = false;
  std::string_view key;
  std::string_view value;
};

/// `content` has already had a comment stripped and been trimmed by the
/// caller: matches `core::yaml_subset::Reader::read_line`'s order exactly,
/// where comment-stripping happens once on the whole line before any
/// key/value split, not separately on the value.
KeyValueLine parse_key_value(std::string_view content)
{
  const std::size_t separator = key_separator_offset(content);
  if (separator == std::string_view::npos)
  {
    return {};
  }
  const std::string_view key = unquoted(core::trimmed_view(content.substr(0, separator)));
  const std::string_view value = core::trimmed_view(content.substr(separator + 1));
  return {true, key, value};
}

/// Which kind of dependency (if any) a `uses:` value names.
enum class UsesTargetKind
{
  GitHubAction,
  LocalAction,
  DockerAction,
  UnresolvableOwner  ///< Owner segment isn't shaped like a real GitHub login.
};

/// GitHub logins allow at most this many characters.
constexpr std::size_t kMaxGitHubLoginLength = 39;

/// True when `owner` is shaped like a real GitHub login: letters/digits with
/// single internal hyphens, never leading/trailing, per GitHub's own username
/// rules. This rejects not only a leftover `${{ ... }}` expression but also
/// curl's own workflows' bare `$` placeholder token -- a shape the
/// unresolved-expression guard alone does not catch.
bool is_valid_github_login(std::string_view owner)
{
  if (owner.empty() || owner.size() > kMaxGitHubLoginLength)
  {
    return false;
  }
  if (owner.front() == '-' || owner.back() == '-')
  {
    return false;
  }
  bool previous_was_hyphen = false;
  for (const char character : owner)
  {
    const bool is_alphanumeric = (character >= 'A' && character <= 'Z') ||
                                 (character >= 'a' && character <= 'z') ||
                                 (character >= '0' && character <= '9');
    if (character == '-')
    {
      if (previous_was_hyphen)
      {
        return false;  // no double hyphens
      }
      previous_was_hyphen = true;
      continue;
    }
    if (!is_alphanumeric)
    {
      return false;
    }
    previous_was_hyphen = false;
  }
  return true;
}

UsesTargetKind classify_uses_target(std::string_view value, std::string_view owner)
{
  if (value.starts_with("./") || value.starts_with("../"))
  {
    return UsesTargetKind::LocalAction;
  }
  if (value.starts_with("docker://"))
  {
    return UsesTargetKind::DockerAction;  // the URI scheme, never a bare "docker/" owner
  }
  if (!is_valid_github_login(owner))
  {
    return UsesTargetKind::UnresolvableOwner;
  }
  return UsesTargetKind::GitHubAction;
}

/// `owner/repo[/subpath][@ref]`, split apart. `subpath` (e.g. `codeql-action/
/// init`, or a reusable workflow's `.github/workflows/x.yml`) is deliberately
/// discarded: the issue's purl shape is exactly `pkg:github/<owner>/<repo>`.
struct ActionReference
{
  std::string owner;
  std::string repo;
  std::string ref;
  bool has_ref_separator = false;
};

ActionReference split_action_reference(std::string_view value)
{
  ActionReference parsed;
  std::string_view remainder = value;
  const std::size_t at_position = remainder.find('@');
  if (at_position != std::string_view::npos)
  {
    parsed.has_ref_separator = true;
    parsed.ref = std::string(remainder.substr(at_position + 1));
    remainder = remainder.substr(0, at_position);
  }
  const std::size_t first_slash = remainder.find('/');
  if (first_slash == std::string_view::npos)
  {
    return parsed;  // no owner/repo shape at all; caller treats as unusable
  }
  parsed.owner = std::string(remainder.substr(0, first_slash));
  const std::string_view after_owner = remainder.substr(first_slash + 1);
  const std::size_t second_slash = after_owner.find('/');
  parsed.repo = std::string(
      second_slash == std::string_view::npos ? after_owner : after_owner.substr(0, second_slash));
  return parsed;
}

bool contains_unresolved_expression(std::string_view text)
{
  return text.find("${{") != std::string_view::npos;
}

/// Mirrors `core::build_git_purl`'s exact style: lower-cased owner/repo
/// (GitHub resolves both case-insensitively), byte-exact ref (git refs are
/// case-sensitive), an empty `ref_for_purl` omits the `@` segment entirely :
/// the mechanism that keeps an unresolved `${{ ... }}` expression out of the
/// purl (never partially percent-encoded into it).
std::string build_github_action_purl(const std::string& owner, const std::string& repo,
                                     const std::string& ref_for_purl)
{
  std::string purl = "pkg:github/" +
                     core::percent_encode_purl_namespace(core::to_lower_ascii(owner)) + "/" +
                     core::percent_encode(core::to_lower_ascii(repo));
  if (!ref_for_purl.empty())
  {
    purl += "@" + core::percent_encode(ref_for_purl);
  }
  return purl;
}

/// Build a component from one already-extracted `uses:` value, or return
/// nothing when there is no dependency to report (local/Docker action, or an
/// owner/repo with nothing resolvable in it). `raw_value` is the value
/// exactly as written, used only for evidence/warning text.
std::optional<core::Component> component_from_uses_reference(
    const std::string& raw_value, const std::string& source_label,
    core::Result<std::vector<core::Component>>& result)
{
  const ActionReference parsed = split_action_reference(raw_value);
  const UsesTargetKind kind = classify_uses_target(raw_value, parsed.owner);
  if (kind == UsesTargetKind::LocalAction || kind == UsesTargetKind::DockerAction)
  {
    return std::nullopt;  // not a dependency bomwerk tracks; nothing wrong happened
  }
  if (kind == UsesTargetKind::UnresolvableOwner)
  {
    // Not owner/repo shaped at all -- a template expression, or a bare
    // placeholder token such as curl's own `$` -- never a formally-valid but
    // permanently-wrong purl namespace like "pkg:github/%24/...".
    result.warn(core::WarningCode::kDependencyMissingSource,
                "github-actions: '" + source_label + "' has 'uses: " + raw_value +
                    "' with an owner that is not a valid GitHub login; skipped",
                "github-actions");
    return std::nullopt;
  }
  if (parsed.repo.empty() || contains_unresolved_expression(parsed.repo))
  {
    // Nothing usable to identify the repo. No component, ever; never a
    // placeholder identity.
    result.warn(core::WarningCode::kDependencyMissingSource,
                "github-actions: '" + source_label + "' has 'uses: " + raw_value +
                    "' with no resolvable owner/repo; skipped",
                "github-actions");
    return std::nullopt;
  }

  core::Component component;
  component.name = parsed.repo;
  // The owner segment doubles as NTIA/CRA supplier evidence, the same
  // convention every other git-forge producer (submodules, cmake_deps) follows.
  component.supplier = parsed.owner;

  core::Confidence confidence = core::Confidence::Low;
  std::string purl_ref;  // stays empty unless the ref is a resolved SHA or tag/branch
  const bool ref_unresolved = contains_unresolved_expression(parsed.ref);
  if (!parsed.has_ref_separator || parsed.ref.empty() || ref_unresolved)
  {
    // Missing or unresolved: keep the raw text in `.version` for
    // debuggability (mirrors how the CMake producer keeps `${DEP_VERSION}`),
    // but never in the purl: `purl_ref` stays empty, so the purl carries no
    // `@` segment at all rather than leaking `${{` into it.
    component.version = parsed.ref;
    confidence = core::Confidence::Low;
    result.warn(core::WarningCode::kUnpinnedOrUnresolvedRef,
                "github-actions: '" + source_label + "' dependency 'uses: " + raw_value + "' has " +
                    (ref_unresolved ? "an unresolved ref" : "no pinned ref") +
                    "; reported at low confidence",
                "github-actions");
  }
  else if (core::is_hex_object_id(parsed.ref))
  {
    // A full commit SHA cannot be silently re-pointed: the immutable case.
    const std::string normalized_ref = core::normalized_object_id(parsed.ref);
    component.version = normalized_ref;
    purl_ref = normalized_ref;
    confidence = core::Confidence::High;
  }
  else
  {
    // A tag or branch name is operator text and stays byte-exact: and is
    // mutable: exactly the tj-actions-compromise risk class the issue cites.
    component.version = parsed.ref;
    purl_ref = parsed.ref;
    confidence = core::Confidence::Medium;
  }

  component.purl = build_github_action_purl(parsed.owner, parsed.repo, purl_ref);

  // Dogfood core::Purl: a purl we cannot parse back is a bug in the builder,
  // not merely degraded input: surface it so tests/fuzzers catch it, the
  // same idiom every other producer follows.
  const core::Result<core::Purl> validated = core::Purl::parse(component.purl);
  if (!validated.complete)
  {
    result.warn(core::WarningCode::kPurlValidationFailed,
                "github-actions: '" + source_label + "' produced an unparsable purl '" +
                    component.purl + "'",
                "github-actions");
  }

  component.evidence.push_back(
      {core::Source::Manifest, source_label + " -> uses: " + raw_value, confidence});
  return component;
}

/// Scan one workflow file's bytes line by line, consuming `uses_budget` for
/// every `uses:` mapping line found (regardless of whether it turns into a
/// component) and appending any resulting components to `components`.
void scan_workflow_file(std::string_view bytes, const std::string& source_label,
                        std::size_t& uses_budget, bool& budget_warned,
                        std::vector<core::Component>& components,
                        core::Result<std::vector<core::Component>>& result)
{
  bytes = core::json_utils::without_utf8_bom(bytes);
  std::size_t position = 0;
  std::size_t block_scalar_indentation = kNoBlockScalar;

  while (position <= bytes.size())
  {
    const std::size_t line_end = bytes.find('\n', position);
    const std::string_view raw_line =
        bytes.substr(position, line_end == std::string_view::npos ? std::string_view::npos
                                                                  : line_end - position);
    position = (line_end == std::string_view::npos) ? bytes.size() + 1 : line_end + 1;

    if (core::trimmed_view(raw_line).empty())
    {
      continue;  // blank lines carry no structure (mirrors core::yaml_subset::Reader)
    }
    const std::size_t indentation = core::leading_space_count(raw_line);

    // A block scalar's body is everything indented deeper than the key that
    // opened it. Skip it as a unit so a shell command inside a `run: |` step
    // (or a folded `restore-keys:` list) can never masquerade as a mapping :
    // mirrors `core::yaml_subset::Reader::read_line` exactly.
    if (block_scalar_indentation != kNoBlockScalar)
    {
      if (indentation > block_scalar_indentation)
      {
        continue;
      }
      block_scalar_indentation = kNoBlockScalar;
    }

    if (indentation >= raw_line.size() || raw_line[indentation] == '\t')
    {
      continue;  // tab indentation: not a construct this scanner reads
    }

    std::string_view content =
        core::trimmed_view(without_inline_comment(raw_line.substr(indentation)));
    if (content.empty())
    {
      continue;  // the line held only a comment
    }
    if (content == "-")
    {
      continue;  // a bare sequence-item dash, nothing else on this line
    }
    if (content.starts_with("- "))
    {
      // "- uses: owner/repo@ref" / "- name: ...\n  uses: ...": strip one
      // sequence-item marker and keep going: the shape core::yaml_subset
      // deliberately treats as outside its subset, but how most real
      // workflow steps are written.
      content = core::trimmed_view(content.substr(2));
      if (content.empty())
      {
        continue;
      }
    }

    const KeyValueLine parsed_line = parse_key_value(content);
    if (!parsed_line.matched)
    {
      continue;
    }
    if (opens_block_scalar(parsed_line.value))
    {
      block_scalar_indentation = indentation;
      continue;
    }
    if (parsed_line.key != kUsesKey)
    {
      continue;
    }

    const std::string uses_value = std::string(unquoted(parsed_line.value));
    if (uses_value.empty())
    {
      result.warn(
          core::WarningCode::kMalformedEntrySkipped,
          "github-actions: '" + source_label + "' has a 'uses:' line with no value; skipped",
          "github-actions");
      continue;
    }
    if (uses_budget == 0)
    {
      if (!budget_warned)
      {
        result.warn(core::WarningCode::kEntryLimitReached,
                    "github-actions: reference limit reached; remaining 'uses:' entries skipped",
                    "github-actions");
        budget_warned = true;
      }
      continue;
    }
    --uses_budget;
    std::optional<core::Component> component =
        component_from_uses_reference(uses_value, source_label, result);
    if (component.has_value())
    {
      components.push_back(std::move(*component));
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
  std::size_t uses_budget = options.max_total_uses_references;
  bool budget_warned = false;

  for (const fs::path& relative_path : file_index.files)
  {
    if (!is_workflow_file(relative_path))
    {
      continue;
    }
    if (scanned_file_count >= options.max_scanned_files)
    {
      result.warn(core::WarningCode::kFileLimitReached,
                  "github-actions: file limit reached; remaining workflow files skipped",
                  "github-actions");
      break;
    }
    ++scanned_file_count;

    const std::string label = relative_path.generic_string();
    const core::BoundedFileRead file_read =
        core::read_file_bounded(root / relative_path, options.max_file_bytes);
    if (!file_read.readable)
    {
      result.warn(core::WarningCode::kUnreadableFile, "github-actions: unreadable file: " + label,
                  "github-actions");
      continue;
    }
    if (file_read.truncated)
    {
      result.warn(core::WarningCode::kFileSizeLimitExceeded,
                  "github-actions: '" + label + "' exceeds the " +
                      std::to_string(options.max_file_bytes) +
                      "-byte cap; only the first part scanned",
                  "github-actions");
    }
    scan_workflow_file(file_read.bytes, label, uses_budget, budget_warned, components, result);
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

}  // namespace bomwerk::parsers::ci::github_actions
