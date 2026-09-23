#include "observe/shim_names.hpp"

#include <algorithm>

namespace bomwerk::observe
{
namespace
{

/// ASCII-only upper-casing. `std::toupper` is locale-dependent and takes an
/// int; tool names are ASCII by construction, so the plain arithmetic is both
/// correct and free of the locale trap.
constexpr char to_upper_ascii(char character)
{
  if (character >= 'a' && character <= 'z')
  {
    return static_cast<char>(character - 'a' + 'A');
  }
  return character;
}

constexpr bool is_ascii_alphanumeric(char character)
{
  return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
         (character >= '0' && character <= '9');
}

}  // namespace

std::string shim_env_var_name(std::string_view tool_name)
{
  if (tool_name.empty())
  {
    return std::string();
  }
  std::string variable_name(kRealToolEnvVarPrefix);
  variable_name.reserve(kRealToolEnvVarPrefix.size() + tool_name.size());
  for (const char character : tool_name)
  {
    if (character == '+')
    {
      // `c++` => `BOMWERK_REAL_CPP`, `clang++` => `BOMWERK_REAL_CLANGPP`. Every
      // name in kShimmedToolNames stays distinct under this mapping.
      variable_name.push_back('P');
    }
    else if (is_ascii_alphanumeric(character))
    {
      variable_name.push_back(to_upper_ascii(character));
    }
    else
    {
      variable_name.push_back('_');
    }
  }
  return variable_name;
}

bool is_shimmed_tool_name(std::string_view tool_name)
{
  return std::find(kShimmedToolNames.begin(), kShimmedToolNames.end(), tool_name) !=
         kShimmedToolNames.end();
}

}  // namespace bomwerk::observe
