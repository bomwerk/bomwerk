#include "core/xml_scan.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/text.hpp"

namespace bomwerk::core::xml_scan
{
namespace
{

constexpr std::string_view kCommentOpen = "<!--";
constexpr std::string_view kCommentClose = "-->";
constexpr std::string_view kCdataOpen = "<![CDATA[";
constexpr std::string_view kCdataClose = "]]>";

/// `</` plus `>`: the bytes a closing tag adds around its name.
constexpr std::size_t kClosingTagOverhead = 3;

/// True for the characters that end a tag name: `>`, `/` and XML whitespace.
bool ends_tag_name(char character)
{
  return character == '>' || character == '/' || is_xml_whitespace(character);
}

/// Every literal `</name>` in a text, by name, in ascending offset order. A
/// child name never contains `>`, `/` or whitespace (`ends_tag_name`), so a
/// `</` whose name run hits `/` or whitespace before `>` can never close a
/// child and is not recorded. Building it is linear: each name run stops at
/// the next `/`, which is at the latest the next `</`.
class ClosingTagIndex
{
 public:
  void add(std::string_view name, std::size_t offset) { offsets_by_name_[name].push_back(offset); }

  /// Offset of the first `</name>` at or after `start`: exactly what
  /// `text.find("</" + name + ">", start)` returns, npos when there is none.
  [[nodiscard]] std::size_t first_at_or_after(std::string_view name, std::size_t start) const
  {
    const auto found = offsets_by_name_.find(name);
    if (found == offsets_by_name_.end())
    {
      return std::string_view::npos;
    }
    const auto offset = std::lower_bound(found->second.begin(), found->second.end(), start);
    return offset == found->second.end() ? std::string_view::npos : *offset;
  }

 private:
  std::map<std::string_view, std::vector<std::size_t>, std::less<>> offsets_by_name_;
};

ClosingTagIndex index_closing_tags(std::string_view text)
{
  ClosingTagIndex index;
  std::size_t position = 0;
  while (true)
  {
    const std::size_t open = text.find("</", position);
    if (open == std::string_view::npos)
    {
      return index;
    }
    std::size_t name_end = open + 2;
    while (name_end < text.size() && !ends_tag_name(text[name_end]))
    {
      ++name_end;
    }
    if (name_end < text.size() && text[name_end] == '>' && name_end > open + 2)
    {
      index.add(text.substr(open + 2, name_end - open - 2), open);
    }
    position = open + 1;
  }
}

void append_newlines_of(std::string& destination, std::string_view removed_text)
{
  destination.append(
      static_cast<std::size_t>(std::count(removed_text.begin(), removed_text.end(), '\n')), '\n');
}

}  // namespace

bool is_xml_whitespace(char character)
{
  return character == ' ' || character == '\t' || character == '\r' || character == '\n';
}

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
      const std::size_t comment_end = comment_close + kCommentClose.size();
      append_newlines_of(cleaned, xml.substr(position, comment_end - position));
      position = comment_end;
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

// `find_element` is the definition of how an element is matched: a name run
// ending at `>`, `/` or whitespace, a self-closing tag when the `>` is preceded
// by `/`, otherwise the first literal `</name>` after the open tag.
// `child_elements` below applies exactly the same rules in one linear pass
// (`ClosingTagIndex`, cached `>` and name runs); the unit test
// `reference_child_elements` pins the two together.
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
    if (after_name >= xml.size() || !ends_tag_name(xml[after_name]))
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

std::vector<ChildElement> child_elements(std::string_view body)
{
  // One linear pass. A naive scan restarts at every '<' and searches forward
  // for a '>' and for the matching closing tag, which is quadratic on hostile
  // input (`<a<a<a...`, `<a <a <a ...>`, many unclosed children): every
  // shortcut below returns exactly what that scan would, only without
  // rescanning text it has already seen.
  const ClosingTagIndex closing_tags = index_closing_tags(body);
  std::vector<ChildElement> children;
  std::size_t next_close_bracket = 0;  // cached body.find('>', ...) result
  bool close_bracket_cached = false;
  std::size_t name_run_end = 0;  // end of the last name run, see below
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
    // A name runs to the first '>', '/' or whitespace. A '<' inside the
    // previous run starts a run that ends at the same place, so it is reused
    // instead of rescanned.
    std::size_t name_end = open + 1;
    if (name_end < name_run_end)
    {
      name_end = name_run_end;
    }
    else
    {
      while (name_end < body.size() && !ends_tag_name(body[name_end]))
      {
        ++name_end;
      }
      name_run_end = name_end;
    }
    const std::string_view child_name = body.substr(open + 1, name_end - open - 1);
    if (child_name.empty())
    {
      position = open + 1;
      continue;
    }
    if (!close_bracket_cached || next_close_bracket < name_end)
    {
      next_close_bracket = body.find('>', name_end);
      close_bracket_cached = true;
    }
    if (next_close_bracket == std::string_view::npos)
    {
      break;  // no '>' after this '<', so none after any later '<' either
    }
    const std::size_t open_end = next_close_bracket;
    if (body[open_end - 1] == '/')
    {
      children.push_back({std::string(child_name), std::string()});
      position = open_end + 1;
      continue;
    }
    const std::size_t close = closing_tags.first_at_or_after(child_name, open_end + 1);
    if (close == std::string_view::npos)
    {
      position = open + 1;
      continue;
    }
    children.push_back({std::string(child_name), std::string(trimmed_view(body.substr(
                                                     open_end + 1, close - open_end - 1)))});
    position = close + child_name.size() + kClosingTagOverhead;
  }
  return children;
}

std::optional<TagMatch> find_next_tag(std::string_view xml, std::string_view tag_name,
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
    if (after_name >= xml.size() || !ends_tag_name(xml[after_name]))
    {
      position = open + 1;  // a longer tag name that merely starts the same
      continue;
    }
    const std::size_t open_end = xml.find('>', after_name);
    if (open_end == std::string_view::npos)
    {
      return std::nullopt;
    }
    const std::size_t attribute_end = (xml[open_end - 1] == '/') ? open_end - 1 : open_end;
    return TagMatch{xml.substr(after_name, attribute_end - after_name), open_end + 1};
  }
  return std::nullopt;
}

std::optional<std::string> find_attribute_value(std::string_view attribute_text,
                                                std::string_view attribute_name)
{
  std::size_t position = 0;
  while (position < attribute_text.size())
  {
    const std::size_t name_position = attribute_text.find(attribute_name, position);
    if (name_position == std::string_view::npos)
    {
      return std::nullopt;
    }
    position = name_position + 1;
    const bool has_left_boundary =
        name_position == 0 || is_xml_whitespace(attribute_text[name_position - 1]);
    const std::size_t after_name = name_position + attribute_name.size();
    if (!has_left_boundary || after_name >= attribute_text.size() ||
        attribute_text[after_name] != '=')
    {
      continue;
    }
    const std::size_t quote_position = after_name + 1;
    if (quote_position >= attribute_text.size() ||
        (attribute_text[quote_position] != '"' && attribute_text[quote_position] != '\''))
    {
      continue;
    }
    const char quote = attribute_text[quote_position];
    const std::size_t value_start = quote_position + 1;
    const std::size_t value_end = attribute_text.find(quote, value_start);
    if (value_end == std::string_view::npos)
    {
      return std::nullopt;
    }
    return std::string(attribute_text.substr(value_start, value_end - value_start));
  }
  return std::nullopt;
}

std::size_t line_number_at(std::string_view text, std::size_t position)
{
  const std::size_t bounded_position = std::min(position, text.size());
  return 1 + static_cast<std::size_t>(std::count(
                 text.begin(), text.begin() + static_cast<std::ptrdiff_t>(bounded_position), '\n'));
}

LineCounter::LineCounter(std::string_view text) : text_(text) {}

std::size_t LineCounter::line_number_at(std::size_t position)
{
  const std::size_t bounded_position = std::min(position, text_.size());
  if (bounded_position < counted_up_to_)
  {
    // Asked to go back: recount from the start, same answer as the free
    // function, only slower. Callers walk forward, so this is rare.
    counted_up_to_ = 0;
    newlines_before_ = 0;
  }
  newlines_before_ += static_cast<std::size_t>(
      std::count(text_.begin() + static_cast<std::ptrdiff_t>(counted_up_to_),
                 text_.begin() + static_cast<std::ptrdiff_t>(bounded_position), '\n'));
  counted_up_to_ = bounded_position;
  return 1 + newlines_before_;
}

}  // namespace bomwerk::core::xml_scan
