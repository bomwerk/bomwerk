#include "core/text.hpp"

#include <cstddef>

namespace bomwerk::core
{
namespace
{

constexpr std::string_view kAsciiWhitespace = " \t\r\n";
constexpr std::size_t kSha1HexLength = 40;
constexpr std::size_t kSha256HexLength = 64;

}  // namespace

char to_lower_ascii(char character)
{
  if (character >= 'A' && character <= 'Z')
  {
    return static_cast<char>(character - 'A' + 'a');
  }
  return character;
}

std::string to_lower_ascii(std::string_view text)
{
  std::string lowered;
  lowered.reserve(text.size());
  for (const char character : text)
  {
    lowered.push_back(to_lower_ascii(character));
  }
  return lowered;
}

char to_upper_ascii(char character)
{
  if (character >= 'a' && character <= 'z')
  {
    return static_cast<char>(character - 'a' + 'A');
  }
  return character;
}

std::string to_upper_ascii(std::string_view text)
{
  std::string uppered;
  uppered.reserve(text.size());
  for (const char character : text)
  {
    uppered.push_back(to_upper_ascii(character));
  }
  return uppered;
}

bool equals_ascii_ignore_case(std::string_view left, std::string_view right)
{
  if (left.size() != right.size())
  {
    return false;
  }
  for (std::size_t character_index = 0; character_index < left.size(); ++character_index)
  {
    if (to_lower_ascii(left[character_index]) != to_lower_ascii(right[character_index]))
    {
      return false;
    }
  }
  return true;
}

std::string_view trimmed_view(std::string_view text)
{
  const std::size_t first = text.find_first_not_of(kAsciiWhitespace);
  if (first == std::string_view::npos)
  {
    return {};
  }
  const std::size_t last = text.find_last_not_of(kAsciiWhitespace);
  return text.substr(first, last - first + 1);
}

std::string trimmed(std::string_view text)
{
  return std::string(trimmed_view(text));
}

std::string escaped_for_diagnostic(std::string_view text)
{
  std::string escaped;
  escaped.reserve(text.size());
  for (const unsigned char character : text)
  {
    switch (character)
    {
      case '\\':
        escaped += "\\\\";
        break;
      case '"':
        escaped += "\\\"";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (character < 0x20 || character == 0x7F)
        {
          constexpr char kHexDigits[] = "0123456789abcdef";
          escaped += "\\u00";
          escaped += kHexDigits[(character >> 4U) & 0x0FU];
          escaped += kHexDigits[character & 0x0FU];
        }
        else
        {
          escaped += static_cast<char>(character);
        }
        break;
    }
  }
  return escaped;
}

std::size_t leading_space_count(std::string_view line)
{
  std::size_t count = 0;
  while (count < line.size() && line[count] == ' ')
  {
    ++count;
  }
  return count;
}

bool is_hex_digits(std::string_view text)
{
  if (text.empty())
  {
    return false;
  }
  for (const char character : text)
  {
    const bool is_hex_digit = (character >= '0' && character <= '9') ||
                              (character >= 'a' && character <= 'f') ||
                              (character >= 'A' && character <= 'F');
    if (!is_hex_digit)
    {
      return false;
    }
  }
  return true;
}

bool is_hex_object_id(std::string_view text)
{
  if (text.size() != kSha1HexLength && text.size() != kSha256HexLength)
  {
    return false;
  }
  return is_hex_digits(text);
}

std::string normalized_object_id(std::string_view text)
{
  if (!is_hex_object_id(text))
  {
    return std::string(text);
  }
  return to_lower_ascii(text);
}

}  // namespace bomwerk::core
