#include "core/json_utils.hpp"

namespace bomwerk::core::json_utils
{

std::string_view without_utf8_bom(std::string_view bytes)
{
  if (constexpr std::string_view kUtf8Bom = "\xEF\xBB\xBF"; bytes.starts_with(kUtf8Bom))
  {
    return bytes.substr(kUtf8Bom.size());
  }
  return bytes;
}

bool exceeds_json_nesting_depth(std::string_view bytes, int maximum_depth)
{
  int current_depth = 0;
  bool inside_string = false;
  bool previous_was_escape = false;
  for (const char character : bytes)
  {
    if (inside_string)
    {
      if (previous_was_escape)
      {
        previous_was_escape = false;
      }
      else if (character == '\\')
      {
        previous_was_escape = true;
      }
      else if (character == '"')
      {
        inside_string = false;
      }
      continue;
    }
    if (character == '"')
    {
      inside_string = true;
      continue;
    }
    if (character == '{' || character == '[')
    {
      ++current_depth;
      if (current_depth > maximum_depth)
      {
        return true;
      }
    }
    if (character == '}' || character == ']')
    {
      --current_depth;
    }
  }
  return false;
}

}  // namespace bomwerk::core::json_utils
