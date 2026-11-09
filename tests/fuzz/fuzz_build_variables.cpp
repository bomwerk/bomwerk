// libFuzzer harness for CMake `${...}` and MSBuild `$(...)` expansion (T40).
// The input's first line is a list of `name=value` definitions separated by
// `;`, the rest the text to expand in both dialects.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/build_variables.hpp"
#include "fuzz/fuzz_support.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
  const auto [definitions, text] =
      bomwerk::fuzz::split_at_first_newline(bomwerk::fuzz::as_text(data, size));
  for (const auto& dialect :
       {bomwerk::core::kCmakeVariableDialect, bomwerk::core::kMsbuildVariableDialect})
  {
    bomwerk::core::VariableTable table;
    std::string_view remaining = definitions;
    while (!remaining.empty())
    {
      const std::size_t end = remaining.find(';');
      const std::string_view definition = remaining.substr(0, end);
      const std::size_t equals = definition.find('=');
      if (equals != std::string_view::npos)
      {
        bomwerk::core::record_variable_definition(table, dialect, definition.substr(0, equals),
                                                  std::string(definition.substr(equals + 1)));
      }
      remaining = end == std::string_view::npos ? std::string_view{} : remaining.substr(end + 1);
    }
    static_cast<void>(bomwerk::core::expand_variables(text, table, dialect));
  }
  static_cast<void>(bomwerk::core::contains_unexpanded_variable(text));
  return 0;
}
