#include "core/git_config.hpp"

#include <cstddef>
#include <limits>
#include <utility>

#include "core/file_io.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::core
{
namespace
{

// Bounds against hostile input (rule 1). Real `.gitmodules` files are a few KiB
// with tens of sections; these caps are orders of magnitude larger, so they
// only ever trip on crafted files: never on a legitimate one.
constexpr std::size_t kMaxConfigBytes = 1u << 20;  // 1 MiB
constexpr std::size_t kMaxLineBytes = 8u * 1024u;  // 8 KiB
constexpr std::size_t kMaxSections = 5000;
constexpr std::size_t kNoSection = std::numeric_limits<std::size_t>::max();

/// Strip one pair of surrounding double quotes, if present.
std::string unquoted(const std::string& value)
{
  if (value.size() >= 2 && value.front() == '"' && value.back() == '"')
  {
    return value.substr(1, value.size() - 2);
  }
  return value;
}

/// Parse a `[name "subsection"]` header (leading '[' already confirmed).
/// Returns false when the header is unterminated (no closing ']').
bool parse_section_header(const std::string& line, std::string& name, std::string& subsection)
{
  const std::size_t close = line.find(']');
  if (close == std::string::npos)
  {
    return false;
  }
  const std::string_view inside = std::string_view(line).substr(1, close - 1);
  const std::size_t quote = inside.find('"');
  if (quote == std::string_view::npos)
  {
    name = to_lower_ascii(trimmed_view(inside));
    subsection.clear();
    return true;
  }
  name = to_lower_ascii(trimmed_view(inside.substr(0, quote)));
  const std::size_t last_quote = inside.find_last_of('"');
  subsection = (last_quote > quote) ? std::string(inside.substr(quote + 1, last_quote - quote - 1))
                                    : std::string{};
  return true;
}

}  // namespace

const std::string* GitConfigSection::find(std::string_view key) const
{
  const std::string wanted = to_lower_ascii(key);
  for (const GitConfigEntry& entry : entries)
  {
    if (entry.key == wanted)
    {
      return &entry.value;
    }
  }
  return nullptr;
}

const std::string* GitConfig::find(std::string_view name, std::string_view subsection,
                                   std::string_view key) const
{
  const std::string wanted_name = to_lower_ascii(name);
  for (const GitConfigSection& section : sections)
  {
    if (section.name == wanted_name && section.subsection == subsection)
    {
      const std::string* value = section.find(key);
      if (value != nullptr)
      {
        return value;
      }
    }
  }
  return nullptr;
}

Result<GitConfig> parse_git_config(std::string_view text, const std::string& label)
{
  Result<GitConfig> result;

  // Strip a leading UTF-8 BOM so the first section header is still recognized.
  constexpr std::string_view kUtf8Bom = "\xEF\xBB\xBF";
  if (text.substr(0, kUtf8Bom.size()) == kUtf8Bom)
  {
    text.remove_prefix(kUtf8Bom.size());
  }

  if (text.size() > kMaxConfigBytes)
  {
    result.warn(WarningCode::kFileSizeLimitExceeded, label + ": exceeds " +
                                                         std::to_string(kMaxConfigBytes) +
                                                         " bytes; parsing the first part only");
    text = text.substr(0, kMaxConfigBytes);
  }

  std::size_t current_section = kNoSection;
  bool capped = false;
  std::size_t position = 0;
  const std::size_t length = text.size();
  while (position < length)
  {
    const std::size_t newline = text.find('\n', position);
    const std::size_t end = (newline == std::string_view::npos) ? length : newline;
    const std::string_view raw_line = text.substr(position, end - position);
    position = (newline == std::string_view::npos) ? length : newline + 1;

    if (raw_line.size() > kMaxLineBytes)
    {
      result.warn(
          WarningCode::kMalformedEntrySkipped,
          label + ": skipping an overlong line (" + std::to_string(raw_line.size()) + " bytes)");
      continue;
    }

    const std::string line = trimmed(raw_line);
    if (line.empty() || line.front() == '#' || line.front() == ';')
    {
      continue;
    }

    if (line.front() == '[')
    {
      if (result.value.sections.size() >= kMaxSections)
      {
        if (!capped)
        {
          result.warn(WarningCode::kGitConfigStructureInvalid, label + ": more than " +
                                                                   std::to_string(kMaxSections) +
                                                                   " sections; ignoring the rest");
          capped = true;
        }
        current_section = kNoSection;
        continue;
      }
      std::string name;
      std::string subsection;
      if (!parse_section_header(line, name, subsection))
      {
        result.warn(WarningCode::kGitConfigStructureInvalid,
                    label + ": skipping an unterminated section header");
        current_section = kNoSection;
        continue;
      }
      GitConfigSection section;
      section.name = std::move(name);
      section.subsection = std::move(subsection);
      result.value.sections.push_back(std::move(section));
      current_section = result.value.sections.size() - 1;
      continue;
    }

    // A `key = value` line (a bare key is git's boolean-true shorthand).
    if (current_section == kNoSection)
    {
      result.warn(WarningCode::kMalformedEntrySkipped,
                  label + ": skipping an entry outside any section");
      continue;
    }
    GitConfigEntry entry;
    const std::size_t equals = line.find('=');
    if (equals == std::string::npos)
    {
      entry.key = to_lower_ascii(line);
      entry.value = "true";
    }
    else
    {
      entry.key = to_lower_ascii(trimmed_view(std::string_view(line).substr(0, equals)));
      entry.value = unquoted(trimmed(std::string_view(line).substr(equals + 1)));
    }
    if (!entry.key.empty())
    {
      result.value.sections[current_section].entries.push_back(std::move(entry));
    }
  }

  return result;
}

Result<GitConfig> read_git_config(const std::filesystem::path& path)
{
  Result<GitConfig> result;

  std::error_code exists_error;
  if (!std::filesystem::exists(path, exists_error) || exists_error)
  {
    return result;  // absent => empty config, no warning: a repo may have none
  }

  // Read at most one byte past the cap so parse_git_config can report the
  // truncation instead of silently losing the tail.
  const BoundedFileRead file_read = read_file_bounded(path, kMaxConfigBytes + 1);
  if (!file_read.readable)
  {
    result.warn(WarningCode::kUnreadableFile, "cannot read " + path.string());
    return result;
  }

  return parse_git_config(file_read.bytes, path.filename().string());
}

}  // namespace bomwerk::core
