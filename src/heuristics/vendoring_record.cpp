#include "heuristics/vendoring_record.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/text.hpp"

namespace bomwerk::heuristics::vendoring_record
{
namespace
{

using namespace std::string_view_literals;

/// Version heads that name no release: a VCS word, a placeholder, or the `0`
/// Chromium writes for "no version". Compared lower-cased. A record whose head
/// is one of these states only its commit, when it has one.
constexpr std::array kNotAReleaseWords = {"git"sv,     "main"sv, "master"sv, "trunk"sv, "head"sv,
                                          "unknown"sv, "n/a"sv,  "none"sv,   "?"sv,     "0"sv};

/// Shortest run of hex digits (with at least one letter) read as an abbreviated
/// commit such as `826d672` rather than as a release. Git abbreviates to 7.
constexpr std::size_t kMinAbbreviatedCommitChars = 7u;

constexpr std::string_view kIndexVersionKey = "- Version:";
constexpr std::string_view kIndexUpstreamKey = "- Upstream:";

/// Deepest Markdown heading that opens or closes an index section. Deeper
/// headings are text inside the section.
constexpr std::size_t kMaxSectionHeadingLevel = 2u;

/// Call `visit` with each line of `text`, without its newline or a trailing
/// CR (CRLF files read the same as LF ones). `visit` returns false to stop.
template <typename Visitor>
void for_each_line(std::string_view text, Visitor&& visit)
{
  std::size_t position = 0;
  while (position < text.size())
  {
    const std::size_t newline = text.find('\n', position);
    const std::size_t line_end = (newline == std::string_view::npos) ? text.size() : newline;
    std::string_view line = text.substr(position, line_end - position);
    if (!line.empty() && line.back() == '\r')
    {
      line.remove_suffix(1);
    }
    if (!visit(line) || newline == std::string_view::npos)
    {
      return;
    }
    position = newline + 1;
  }
}

bool is_ascii_letter(char character)
{
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z');
}

bool is_ascii_digit(char character)
{
  return character >= '0' && character <= '9';
}

/// A space, a tab, an ASCII control byte or DEL: nothing a single URL or a
/// folder name may contain.
bool is_blank_or_control(char character)
{
  const auto byte = static_cast<unsigned char>(character);
  constexpr unsigned char kFirstPrintable = 0x21;
  constexpr unsigned char kDelete = 0x7F;
  return byte < kFirstPrintable || byte == kDelete;
}

bool is_release_character(char character)
{
  return is_ascii_letter(character) || is_ascii_digit(character) || character == '.' ||
         character == '_' || character == '+' || character == '~' || character == '-';
}

/// `826d672`: hex digits only, at least `kMinAbbreviatedCommitChars` of them,
/// and at least one letter, so a plain number such as `20240101` stays a
/// release.
bool is_abbreviated_commit(std::string_view text)
{
  if (text.size() < kMinAbbreviatedCommitChars || !core::is_hex_digits(text))
  {
    return false;
  }
  return std::any_of(text.begin(), text.end(), is_ascii_letter);
}

/// True when a Version head names a release: version-shaped, with a digit,
/// and none of the things that only look like one (a VCS word, a
/// placeholder, a commit, full or abbreviated).
bool names_release(std::string_view head)
{
  if (head.empty() || head.size() > kMaxVersionChars)
  {
    return false;
  }
  if (core::contains(kNotAReleaseWords, core::to_lower_ascii(head)))
  {
    return false;
  }
  if (core::is_hex_object_id(head) || is_abbreviated_commit(head))
  {
    return false;
  }
  if (!std::all_of(head.begin(), head.end(), is_release_character))
  {
    return false;
  }
  return std::any_of(head.begin(), head.end(), is_ascii_digit);
}

/// What a Version value states before a format adds its own fields.
struct StatedVersion
{
  std::string release;               ///< empty when the head names no release
  std::vector<std::string> commits;  ///< every object id the value mentions, lower-cased
};

void add_commit_if_object_id(std::string_view part, std::vector<std::string>& commits)
{
  const std::string_view candidate = core::trimmed_view(part);
  if (core::is_hex_object_id(candidate))
  {
    commits.push_back(core::to_lower_ascii(candidate));
  }
}

/// `0.22.3 (826d672…, 2026)` -> release `0.22.3`, commit `826d672…`;
/// `git (chromium/5907, 430a4f5…, 2023)` -> no release, commit `430a4f5…`;
/// `39b578a…, 2023` -> no release, commit `39b578a…`.
StatedVersion read_stated_version(std::string_view value)
{
  StatedVersion stated;
  value = core::trimmed_view(value);
  const std::size_t open = value.find(" (");
  const std::string_view head = (open == std::string_view::npos) ? value : value.substr(0, open);
  if (open != std::string_view::npos)
  {
    std::string_view inside = value.substr(open + 2);
    if (!inside.empty() && inside.back() == ')')
    {
      inside.remove_suffix(1);
    }
    std::size_t part_start = 0;
    while (part_start <= inside.size())
    {
      const std::size_t comma = inside.find(',', part_start);
      const std::size_t part_end = (comma == std::string_view::npos) ? inside.size() : comma;
      add_commit_if_object_id(inside.substr(part_start, part_end - part_start), stated.commits);
      if (comma == std::string_view::npos)
      {
        break;
      }
      part_start = comma + 1;
    }
  }
  const std::size_t head_comma = head.find(',');
  const std::string_view head_first = core::trimmed_view(
      (head_comma == std::string_view::npos) ? head : head.substr(0, head_comma));
  add_commit_if_object_id(head_first, stated.commits);
  if (names_release(head_first))
  {
    stated.release = std::string(head_first);
  }
  return stated;
}

/// The one commit in `commits`, or empty when there is none or two different
/// ones: a record that names two commits states neither.
std::string sole_commit(std::vector<std::string> commits)
{
  std::sort(commits.begin(), commits.end());
  commits.erase(std::unique(commits.begin(), commits.end()), commits.end());
  return commits.size() == 1 ? commits.front() : std::string{};
}

/// Fill `record.commit` and `record.version` (the release when stated, else
/// the commit). False when the record states neither.
bool settle_version(Record& record, const StatedVersion& stated,
                    const std::vector<std::string>& commits)
{
  record.commit = sole_commit(commits);
  record.version = stated.release.empty() ? record.commit : stated.release;
  return !record.version.empty();
}

/// `value` when it is exactly one `http://` or `https://` URL: no blanks, no
/// control bytes, something after the scheme. `Mozilla, via https://…` and a
/// line naming two URLs are not one URL.
std::string single_url(std::string_view value)
{
  value = core::trimmed_view(value);
  std::size_t scheme_length = 0;
  if (value.starts_with("https://"))
  {
    scheme_length = std::string_view("https://").size();
  }
  else if (value.starts_with("http://"))
  {
    scheme_length = std::string_view("http://").size();
  }
  if (scheme_length == 0 || value.size() == scheme_length)
  {
    return {};
  }
  if (std::any_of(value.begin(), value.end(), is_blank_or_control))
  {
    return {};
  }
  return std::string(value);
}

/// A section name that can only ever be one directory's name.
bool is_folder_token(std::string_view token)
{
  if (token.empty() || token == "." || token == "..")
  {
    return false;
  }
  return std::none_of(
      token.begin(), token.end(), [](char character)
      { return is_blank_or_control(character) || character == '/' || character == '\\'; });
}

/// The text of a `#` or `##` heading (`## zlib` -> `zlib`), or nullopt when
/// `line` is not one. A bare `##` is a heading with empty text.
std::optional<std::string_view> section_heading_text(std::string_view line)
{
  std::size_t level = 0;
  while (level < line.size() && line[level] == '#')
  {
    ++level;
  }
  if (level == 0 || level > kMaxSectionHeadingLevel)
  {
    return std::nullopt;
  }
  if (level == line.size())
  {
    return std::string_view{};
  }
  if (line[level] != ' ' && line[level] != '\t')
  {
    return std::nullopt;  // `#hashtag`, not a heading
  }
  return core::trimmed_view(line.substr(level));
}

/// The value after `key` when `line` is that column-0 bullet.
std::optional<std::string_view> bullet_value(std::string_view line, std::string_view key)
{
  if (!line.starts_with(key))
  {
    return std::nullopt;
  }
  return core::trimmed_view(line.substr(key.size()));
}

/// One index section while it is being read.
struct IndexSection
{
  std::string folder;
  std::size_t version_lines = 0;
  std::size_t upstream_lines = 0;
  std::string version_line;  ///< the whole `- Version:` line, as written
  std::string version_value;
  std::string upstream_value;
};

std::optional<Record> record_from_section(const IndexSection& section)
{
  if (section.version_lines != 1)
  {
    return std::nullopt;  // no version, or two libraries sharing one directory
  }
  Record record;
  record.folder = section.folder;
  const StatedVersion stated = read_stated_version(section.version_value);
  if (!settle_version(record, stated, stated.commits))
  {
    return std::nullopt;
  }
  if (section.upstream_lines == 1)
  {
    record.upstream = single_url(section.upstream_value);
  }
  record.version_line = section.version_line;
  return record;
}

/// A `Key: value` line of a README.chromium header: the key starts with a
/// letter at column 0 and holds only letters, digits, blanks and hyphens.
struct HeaderField
{
  std::string_view key;
  std::string_view value;
};

std::optional<HeaderField> header_field(std::string_view line)
{
  const std::size_t colon = line.find(':');
  if (colon == std::string_view::npos || colon == 0 || !is_ascii_letter(line.front()))
  {
    return std::nullopt;
  }
  const std::string_view key = line.substr(0, colon);
  const bool key_is_plain = std::all_of(key.begin(), key.end(),
                                        [](char character)
                                        {
                                          return is_ascii_letter(character) ||
                                                 is_ascii_digit(character) || character == ' ' ||
                                                 character == '-';
                                        });
  if (!key_is_plain)
  {
    return std::nullopt;
  }
  return HeaderField{core::trimmed_view(key), core::trimmed_view(line.substr(colon + 1))};
}

/// One README.chromium field of interest: how often it appeared, and its last
/// value and line. Only a field written exactly once is used.
struct ChromiumField
{
  std::size_t count = 0;
  std::string value;
  std::string line;

  void remember(std::string_view field_value, std::string_view field_line)
  {
    ++count;
    value = std::string(field_value);
    line = std::string(field_line);
  }
  [[nodiscard]] bool is_single() const { return count == 1; }
};

}  // namespace

std::vector<Record> parse_index(std::string_view text)
{
  std::map<std::string, std::size_t> sections_per_folder;
  std::map<std::string, Record> records_by_folder;
  std::optional<IndexSection> current;

  const auto close_section = [&]()
  {
    if (!current.has_value())
    {
      return;
    }
    ++sections_per_folder[current->folder];
    if (std::optional<Record> record = record_from_section(*current))
    {
      records_by_folder[current->folder] = std::move(*record);
    }
    current.reset();
  };

  for_each_line(
      text,
      [&](std::string_view line)
      {
        // A heading of any length closes the section, so an over-long
        // heading can never let the next section's bullets count for
        // the previous one.
        if (const std::optional<std::string_view> heading = section_heading_text(line))
        {
          close_section();
          if (line.size() <= kMaxLineChars && is_folder_token(*heading))
          {
            current = IndexSection{};
            current->folder = std::string(*heading);
          }
          return true;
        }
        if (!current.has_value() || line.size() > kMaxLineChars)
        {
          return true;
        }
        if (const std::optional<std::string_view> value = bullet_value(line, kIndexVersionKey))
        {
          ++current->version_lines;
          current->version_line = std::string(core::trimmed_view(line));
          current->version_value = std::string(*value);
        }
        else if (const std::optional<std::string_view> upstream =
                     bullet_value(line, kIndexUpstreamKey))
        {
          ++current->upstream_lines;
          current->upstream_value = std::string(*upstream);
        }
        return true;
      });
  close_section();

  std::vector<Record> records;
  records.reserve(records_by_folder.size());
  for (auto& [folder, record] : records_by_folder)
  {
    if (sections_per_folder[folder] == 1)
    {
      records.push_back(std::move(record));
    }
  }
  return records;
}

std::optional<Record> parse_readme_chromium(std::string_view text)
{
  bool saw_name = false;
  ChromiumField version;
  ChromiumField revision;
  ChromiumField url;

  for_each_line(text,
                [&](std::string_view line)
                {
                  if (core::trimmed_view(line).empty())
                  {
                    return true;
                  }
                  if (line.size() > kMaxLineChars)
                  {
                    return false;  // no header field is this long: the header has ended
                  }
                  const std::optional<HeaderField> field = header_field(line);
                  if (!field.has_value())
                  {
                    return false;  // the first line that is not a field ends the header
                  }
                  if (!saw_name)
                  {
                    saw_name = field->key == "Name";
                    return saw_name;
                  }
                  if (field->key == "Description")
                  {
                    return false;
                  }
                  const std::string_view written = core::trimmed_view(line);
                  if (field->key == "Version")
                  {
                    version.remember(field->value, written);
                  }
                  else if (field->key == "Revision")
                  {
                    revision.remember(field->value, written);
                  }
                  else if (field->key == "URL")
                  {
                    url.remember(field->value, written);
                  }
                  return true;
                });

  if (!saw_name)
  {
    return std::nullopt;
  }

  StatedVersion stated;
  if (version.is_single())
  {
    stated = read_stated_version(version.value);
  }
  std::vector<std::string> commits = stated.commits;
  if (revision.is_single())
  {
    add_commit_if_object_id(revision.value, commits);
  }

  Record record;
  if (!settle_version(record, stated, commits))
  {
    return std::nullopt;
  }
  if (url.is_single())
  {
    record.upstream = single_url(url.value);
  }
  if (version.is_single())
  {
    record.version_line = version.line;
  }
  if (revision.is_single())
  {
    record.version_line += (record.version_line.empty() ? "" : "; ") + revision.line;
  }
  return record;
}

}  // namespace bomwerk::heuristics::vendoring_record
