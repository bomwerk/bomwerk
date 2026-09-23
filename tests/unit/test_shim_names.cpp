// ctest unit test for the shim-name contract (observe/shim_names).
//
// The parent process sets BOMWERK_REAL_* and the shim reads it. Nothing checks
// at compile time that the two agree, so this test is what keeps them honest:
// a silent disagreement would leave every shim unable to find its real tool.
#include <set>
#include <string>

#include "observe/shim_names.hpp"
#include "support/check.hpp"

using bomwerk::observe::is_shimmed_tool_name;
using bomwerk::observe::kShimmedToolNames;
using bomwerk::observe::shim_env_var_name;

int main()
{
  // Given a plain tool name, when mapped, then it is upper-cased behind the
  // shared prefix.
  {
    BOMWERK_TEST_CHECK(shim_env_var_name("cc") == "BOMWERK_REAL_CC");
    BOMWERK_TEST_CHECK(shim_env_var_name("gcc") == "BOMWERK_REAL_GCC");
    BOMWERK_TEST_CHECK(shim_env_var_name("clang") == "BOMWERK_REAL_CLANG");
    BOMWERK_TEST_CHECK(shim_env_var_name("ld") == "BOMWERK_REAL_LD");
    BOMWERK_TEST_CHECK(shim_env_var_name("ar") == "BOMWERK_REAL_AR");
  }

  // Given a C++ driver name, when mapped, then each '+' becomes 'P': '+' is
  // not legal in an environment variable name.
  {
    BOMWERK_TEST_CHECK(shim_env_var_name("c++") == "BOMWERK_REAL_CPP");
    BOMWERK_TEST_CHECK(shim_env_var_name("g++") == "BOMWERK_REAL_GPP");
    BOMWERK_TEST_CHECK(shim_env_var_name("clang++") == "BOMWERK_REAL_CLANGPP");
  }

  // Given every shimmed tool, when all names are mapped, then no two collide.
  // A collision would silently point one tool's shim at another tool's binary
  //: a C file handed to the linker, or worse, quietly compiled by the wrong
  // driver.
  {
    std::set<std::string> variable_names;
    for (const std::string_view tool_name : kShimmedToolNames)
    {
      const std::string variable_name = shim_env_var_name(tool_name);
      BOMWERK_TEST_CHECK(!variable_name.empty());
      const bool inserted = variable_names.insert(variable_name).second;
      BOMWERK_TEST_CHECK(inserted);
    }
    BOMWERK_TEST_CHECK(variable_names.size() == kShimmedToolNames.size());
  }

  // Given a name carrying characters illegal in a variable name, when mapped,
  // then they become underscores and the result stays a legal name.
  {
    BOMWERK_TEST_CHECK(shim_env_var_name("x86_64-linux-gnu-gcc") ==
                       "BOMWERK_REAL_X86_64_LINUX_GNU_GCC");
    BOMWERK_TEST_CHECK(shim_env_var_name("a.b") == "BOMWERK_REAL_A_B");
  }

  // Given an empty name (argv[0] absent), when mapped, then the result is
  // empty: the shim must not look up a bare "BOMWERK_REAL_" and exec whatever
  // it finds.
  {
    BOMWERK_TEST_CHECK(shim_env_var_name("").empty());
  }

  // Given a tool name, when membership is tested, then only the shimmed set
  // matches.
  {
    BOMWERK_TEST_CHECK(is_shimmed_tool_name("cc"));
    BOMWERK_TEST_CHECK(is_shimmed_tool_name("clang++"));
    BOMWERK_TEST_CHECK(is_shimmed_tool_name("ar"));
    BOMWERK_TEST_CHECK(!is_shimmed_tool_name("python3"));
    BOMWERK_TEST_CHECK(!is_shimmed_tool_name("CC"));
    BOMWERK_TEST_CHECK(!is_shimmed_tool_name(""));
  }

  return 0;
}
