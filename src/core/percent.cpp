#include "core/percent.hpp"

#include <cstddef>

namespace bomwerk::core
{
namespace
{

constexpr std::size_t kEscapeLength = 3;  ///< `%` plus two hex digits

/// Value of one hex digit, or -1 when `character` is not a hex digit.
int hex_digit_value(char character)
{
  if (character >= '0' && character <= '9')
  {
    return character - '0';
  }
  if (character >= 'a' && character <= 'f')
  {
    return character - 'a' + 10;
  }
  if (character >= 'A' && character <= 'F')
  {
    return character - 'A' + 10;
  }
  return -1;
}

}  // namespace

std::string percent_encode(std::string_view text)
{
  constexpr const char* kHexDigits = "0123456789ABCDEF";
  std::string encoded;
  encoded.reserve(text.size());
  for (const unsigned char character : text)
  {
    const bool is_unreserved = (character >= 'A' && character <= 'Z') ||
                               (character >= 'a' && character <= 'z') ||
                               (character >= '0' && character <= '9') || character == '-' ||
                               character == '.' || character == '_' || character == '~';
    if (is_unreserved)
    {
      encoded.push_back(static_cast<char>(character));
    }
    else
    {
      encoded.push_back('%');
      encoded.push_back(kHexDigits[character >> 4]);
      encoded.push_back(kHexDigits[character & 0x0F]);
    }
  }
  return encoded;
}

std::string percent_encode_purl_namespace(std::string_view namespace_path)
{
  std::string encoded;
  encoded.reserve(namespace_path.size());
  std::size_t segment_start = 0;
  while (true)
  {
    const std::size_t slash = namespace_path.find('/', segment_start);
    const std::size_t segment_end =
        (slash == std::string_view::npos) ? namespace_path.size() : slash;
    encoded += percent_encode(namespace_path.substr(segment_start, segment_end - segment_start));
    if (slash == std::string_view::npos)
    {
      break;
    }
    encoded.push_back('/');
    segment_start = slash + 1;
  }
  return encoded;
}

std::string percent_decode(std::string_view text)
{
  std::string decoded;
  decoded.reserve(text.size());
  std::size_t position = 0;
  while (position < text.size())
  {
    if (text[position] != '%' || position + kEscapeLength > text.size())
    {
      decoded.push_back(text[position]);
      ++position;
      continue;
    }
    const int high_digit = hex_digit_value(text[position + 1]);
    const int low_digit = hex_digit_value(text[position + 2]);
    if (high_digit < 0 || low_digit < 0)
    {
      // A malformed escape is operator text, not structure: keep the '%' and
      // carry on rather than swallowing the bytes behind it.
      decoded.push_back(text[position]);
      ++position;
      continue;
    }
    decoded.push_back(static_cast<char>((high_digit << 4) | low_digit));
    position += kEscapeLength;
  }
  return decoded;
}

}  // namespace bomwerk::core
