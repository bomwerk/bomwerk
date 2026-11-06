#include "core/yaml_subset.hpp"

#include <cstddef>
#include <string_view>

#include "core/text.hpp"

namespace bomwerk::core::yaml_subset
{
namespace
{

/// Characters that open a quoted region. Both spellings appear in the wild:
/// Yarn Berry writes `"`, pnpm writes `'`.
constexpr std::string_view kQuoteCharacters = "\"'";

/// Value prefixes that put a line outside the subset. Block scalars (`|`, `>`)
/// also swallow their indented body, so they are tracked rather than merely
/// skipped; the rest are single-line constructs.
constexpr std::string_view kBlockScalarIndicators = "|>";
constexpr std::string_view kAnchorAliasTagIndicators = "&*!";

/// A delimited scalar: `"quoted"`, `{flow: mapping}`: needs at least its two
/// delimiters before there is an interior to look at.
constexpr std::size_t kDelimiterPairLength = 2;

/// View of `content` up to a `#` comment, honoring quotes. A `#` starts a
/// comment only at the start of the content or after whitespace: a Yarn
/// `patch:` locator embeds a literal `#` inside its quoted value, and cutting
/// there truncates the resolution.
std::string_view without_comment(std::string_view content)
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
    const bool follows_whitespace =
        index == 0 || content[index - 1] == ' ' || content[index - 1] == '\t';
    if (character == '#' && follows_whitespace)
    {
      return content.substr(0, index);
    }
  }
  return content;
}

/// Offset of the `key: value` separator, or npos when the line has none. The
/// separator is the first `:` outside quotes that ends the line or is followed
/// by a space: a Berry entry key is `"name@npm:^1.2.3":`, whose inner `:` is
/// part of the key.
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
    if (character == ':' && (index + 1 == content.size() || content[index + 1] == ' '))
    {
      return index;
    }
  }
  return std::string_view::npos;
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

/// True when `content` starts with a block sequence marker: `-` alone or `- `.
bool is_sequence_marker(std::string_view content)
{
  return content == "-" || content.starts_with("- ");
}

/// True when `content` starts a construct the subset does not read: a sequence
/// item, a document marker, a flow sequence, or an anchor/alias/tag.
bool is_unsupported_start(std::string_view content)
{
  if (is_sequence_marker(content))
  {
    return true;
  }
  if (content.starts_with("---") || content.starts_with("..."))
  {
    return true;
  }
  if (content.front() == '[')
  {
    return true;
  }
  return kAnchorAliasTagIndicators.find(content.front()) != std::string_view::npos;
}

/// True when `value` opens a block scalar (`|`, `>`, with optional chomping and
/// indentation indicators such as `|-`, `>2`). Its body follows on the next
/// lines, so the caller has to skip more than this one line.
bool opens_block_scalar(std::string_view value)
{
  return !value.empty() && kBlockScalarIndicators.find(value.front()) != std::string_view::npos;
}

/// True when `value` is a one-line flow sequence `[ … ]`.
bool is_flow_sequence(std::string_view value)
{
  return value.size() >= kDelimiterPairLength && value.front() == '[' && value.back() == ']';
}

/// True when `value` is a single-line construct outside the subset: an anchor,
/// alias, tag or flow sequence (the last only when sequences are not read).
bool is_unsupported_value(std::string_view value, bool sequence_items)
{
  if (value.empty())
  {
    return false;
  }
  if (value.front() == '[')
  {
    return !(sequence_items && is_flow_sequence(value));
  }
  return kAnchorAliasTagIndicators.find(value.front()) != std::string_view::npos;
}

}  // namespace

bool Reader::next(Node& node)
{
  while (position_ <= bytes_.size())
  {
    const std::size_t line_end = bytes_.find('\n', position_);
    const std::string_view raw_line =
        bytes_.substr(position_, (line_end == std::string_view::npos) ? std::string_view::npos
                                                                      : line_end - position_);
    position_ = (line_end == std::string_view::npos) ? bytes_.size() + 1 : line_end + 1;

    if (read_line(raw_line, node))
    {
      return true;
    }
  }
  return false;
}

bool Reader::read_line(std::string_view raw_line, Node& node)
{
  if (core::trimmed_view(raw_line).empty())
  {
    return false;  // blank lines carry no structure and are not a gap
  }
  const std::size_t indentation = core::leading_space_count(raw_line);

  // A block scalar's body is everything indented deeper than the key that
  // opened it. Skip it as a unit so its free text cannot masquerade as
  // mappings; the first line back at or above that indentation resumes.
  if (block_scalar_indentation_ != kNoBlockScalar)
  {
    if (indentation > block_scalar_indentation_)
    {
      ++stats_.unsupported_line_count;
      return false;
    }
    block_scalar_indentation_ = kNoBlockScalar;
  }

  if (raw_line[indentation] == '\t')
  {
    // Tabs are not indentation in YAML, and no lockfile generator emits them.
    ++stats_.unsupported_line_count;
    return false;
  }

  std::string_view content = core::trimmed_view(without_comment(raw_line.substr(indentation)));
  if (content.empty())
  {
    return false;  // the line held only a comment
  }

  // Opt-in sequence item: strip the `- ` marker and measure the key at the
  // column after it, so the item's first key and its following keys line up.
  bool starts_sequence_item = false;
  std::size_t key_indentation = indentation;

  // Count a line outside the subset. A sequence item's line still marks where
  // a new item begins, as an empty item node, so the fields below it are never
  // attributed to the previous item.
  const auto skip_line = [&]() -> bool
  {
    ++stats_.unsupported_line_count;
    if (!starts_sequence_item)
    {
      return false;
    }
    node = Node{};
    node.indentation = key_indentation;
    node.starts_sequence_item = true;
    return true;
  };

  if (options_.sequence_items && is_sequence_marker(content))
  {
    starts_sequence_item = true;
    const std::string_view after_marker = content.substr(1);
    key_indentation = indentation + 1 + core::leading_space_count(after_marker);
    content = core::trimmed_view(after_marker);
    if (content.empty())
    {
      node = Node{};
      node.indentation = key_indentation;
      node.opens_block = true;  // a lone `-`: the item's mapping follows below
      node.starts_sequence_item = true;
      return true;
    }
    if (content.front() == '{')
    {
      return skip_line();  // a flow-mapping item `- {a: 1}` is outside the subset
    }
    if (key_separator_offset(content) == std::string_view::npos)
    {
      if (opens_block_scalar(content))
      {
        block_scalar_indentation_ = indentation;  // `- |`: skip the body as a unit
        return skip_line();
      }
      if (is_unsupported_start(content))
      {
        return skip_line();
      }
      node = Node{};
      node.indentation = key_indentation;
      node.value = unquoted(content);  // a bare `- scalar` item
      node.starts_sequence_item = true;
      return true;
    }
  }
  if (is_unsupported_start(content))
  {
    return skip_line();
  }

  const std::size_t separator = key_separator_offset(content);
  if (separator == std::string_view::npos)
  {
    return skip_line();
  }
  const std::string_view key = unquoted(core::trimmed_view(content.substr(0, separator)));
  if (key.empty())
  {
    return skip_line();
  }
  std::string_view value = core::trimmed_view(content.substr(separator + 1));

  if (opens_block_scalar(value))
  {
    block_scalar_indentation_ = key_indentation;
    return skip_line();
  }
  if (is_unsupported_value(value, options_.sequence_items))
  {
    return skip_line();
  }

  node = Node{};
  node.indentation = key_indentation;
  node.key = key;
  node.starts_sequence_item = starts_sequence_item;
  node.opens_block = value.empty();
  node.is_flow_mapping =
      value.size() >= kDelimiterPairLength && value.front() == '{' && value.back() == '}';
  node.is_flow_sequence = options_.sequence_items && is_flow_sequence(value);
  if (node.is_flow_mapping || node.is_flow_sequence)
  {
    node.value = core::trimmed_view(value.substr(1, value.size() - 2));
  }
  else
  {
    node.value = unquoted(value);
  }
  return true;
}

}  // namespace bomwerk::core::yaml_subset
