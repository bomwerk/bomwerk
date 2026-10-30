#include "core/xml_scan.hpp"

#include <algorithm>
#include <cstddef>
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

std::vector<ChildElement> child_elements(std::string_view body)
{
  std::vector<ChildElement> children;
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
    const std::string child_name(body.substr(open + 1, name_end - open - 1));
    if (child_name.empty())
    {
      position = open + 1;
      continue;
    }
    const std::optional<ElementMatch> child = find_element(body, child_name, open);
    if (!child.has_value())
    {
      position = open + 1;
      continue;
    }
    children.push_back({child_name, std::string(trimmed_view(child->inner_text))});
    position = child->resume_position;
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

}  // namespace bomwerk::core::xml_scan
