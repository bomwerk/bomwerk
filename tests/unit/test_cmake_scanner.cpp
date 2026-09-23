// ctest unit test for the CMake command lexer (the pure scanner half).
#include <cassert>
#include <cstddef>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "parsers/cpp/cmake_scanner.hpp"
#include "support/check.hpp"

using bomwerk::parsers::cpp::CmakeCommand;
using bomwerk::parsers::cpp::scan_cmake_commands;

namespace
{

const CmakeCommand* find_command(const std::vector<CmakeCommand>& commands, std::string_view name)
{
  for (const CmakeCommand& command : commands)
  {
    if (command.name == name)
    {
      return &command;
    }
  }
  return nullptr;
}

}  // namespace

int main()
{
  // Given a multi-line FetchContent_Declare, when scanned, then one command is
  // returned with its keyword/value arguments in order and its start line.
  {
    const std::string text =
        "FetchContent_Declare(\n"
        "  googletest\n"
        "  GIT_REPOSITORY https://github.com/google/googletest.git\n"
        "  GIT_TAG        v1.14.0\n"
        ")\n";
    const auto result = scan_cmake_commands(text);
    assert(result.complete);
    assert(result.warnings.empty());
    assert(result.value.size() == 1);
    const CmakeCommand& command = result.value[0];
    BOMWERK_TEST_CHECK(command.name == "FetchContent_Declare");
    BOMWERK_TEST_CHECK(command.line == 1);
    BOMWERK_TEST_CHECK(command.well_formed);
    BOMWERK_TEST_CHECK(command.arguments.size() == 5);
    BOMWERK_TEST_CHECK(command.arguments[0] == "googletest");
    BOMWERK_TEST_CHECK(command.arguments[1] == "GIT_REPOSITORY");
    BOMWERK_TEST_CHECK(command.arguments[2] == "https://github.com/google/googletest.git");
    BOMWERK_TEST_CHECK(command.arguments[3] == "GIT_TAG");
    BOMWERK_TEST_CHECK(command.arguments[4] == "v1.14.0");
  }

  // Given line and bracket comments interleaved with a call, when scanned, then
  // the comments are stripped and never leak into arguments.
  {
    const std::string text =
        "# a leading line comment\n"
        "#[[ a bracket\n comment spanning lines ]]\n"
        "CPMAddPackage(NAME fmt VERSION 10.2.1) # trailing comment\n";
    const auto result = scan_cmake_commands(text);
    assert(result.warnings.empty());
    assert(result.value.size() == 1);
    const CmakeCommand& command = result.value[0];
    BOMWERK_TEST_CHECK(command.name == "CPMAddPackage");
    BOMWERK_TEST_CHECK(command.arguments.size() == 4);
    BOMWERK_TEST_CHECK(command.arguments[0] == "NAME");
    BOMWERK_TEST_CHECK(command.arguments[3] == "10.2.1");
  }

  // Given a quoted argument containing ')' and '#', when scanned, then the whole
  // value is one argument and neither char ends the call or starts a comment.
  {
    const std::string text = "set(X \"a ) # b\")\n";
    const auto result = scan_cmake_commands(text);
    const CmakeCommand* command = find_command(result.value, "set");
    BOMWERK_TEST_CHECK(command != nullptr);
    BOMWERK_TEST_CHECK(command->arguments.size() == 2);
    BOMWERK_TEST_CHECK(command->arguments[1] == "a ) # b");
  }

  // Given an unquoted argument with a backslash-escaped quote: the real
  // vcpkg/ports/autodock-vina/CMakeLists.txt shape `-DVERSION=\"${GIT_VERSION}\"`
  //: when scanned, then the escaped quotes are literal characters inside ONE
  // bare argument, never mistaken for the start of a new quoted argument (which
  // would otherwise swallow the rest of the file as an unterminated string).
  {
    const std::string text =
        "target_compile_definitions(vina PUBLIC -DVERSION=\\\"${GIT_VERSION}\\\")\n";
    const auto result = scan_cmake_commands(text);
    assert(result.warnings.empty());
    assert(result.value.size() == 1);
    const CmakeCommand& command = result.value[0];
    BOMWERK_TEST_CHECK(command.name == "target_compile_definitions");
    BOMWERK_TEST_CHECK(command.arguments.size() == 3);
    BOMWERK_TEST_CHECK(command.arguments[2] == "-DVERSION=\"${GIT_VERSION}\"");
  }

  // Given the CPM single-arg shorthand, when scanned, then the '#ref' fragment
  // stays inside the one quoted argument (not treated as a comment).
  {
    const std::string text = "CPMAddPackage(\"gh:fmtlib/fmt#10.2.1\")\n";
    const auto result = scan_cmake_commands(text);
    assert(result.value.size() == 1);
    assert(result.value[0].arguments.size() == 1);
    assert(result.value[0].arguments[0] == "gh:fmtlib/fmt#10.2.1");
  }

  // Given a bracket argument, when scanned, then its literal (unescaped) content
  // is a single argument.
  {
    const std::string text = "message([=[ raw ]] text with ) ]=])\n";
    const auto result = scan_cmake_commands(text);
    assert(result.value.size() == 1);
    assert(result.value[0].arguments.size() == 1);
    assert(result.value[0].arguments[0] == " raw ]] text with ) ");
  }

  // Given a command name in lower case with a space before '(', when scanned,
  // then it is still captured (case preserved for the caller to fold).
  {
    const std::string text = "fetchcontent_declare (dep GIT_TAG main)\n";
    const auto result = scan_cmake_commands(text);
    assert(result.value.size() == 1);
    assert(result.value[0].name == "fetchcontent_declare");
    assert(result.value[0].arguments.size() == 3);
  }

  // Given an unterminated call, when scanned, then a warning is recorded, the
  // run stays complete, the partial command is still returned (no crash), and
  // it is flagged not-well-formed so consumers can distrust its arguments.
  {
    const std::string text = "FetchContent_Declare(dep GIT_TAG v1\n";
    const auto result = scan_cmake_commands(text);
    assert(result.complete);
    assert(!result.warnings.empty());
    assert(result.value.size() == 1);
    assert(result.value[0].name == "FetchContent_Declare");
    assert(!result.value[0].well_formed);
  }

  // Given hostile bytes (NUL, high bytes, stray parens), when scanned, then the
  // lexer never crashes and stays complete (ASan/UBSan guard).
  {
    std::string text = "CPMAddPackage(NAME x)";
    text.push_back('\0');
    text += "\x80\xff))) ((( \n";
    const auto result = scan_cmake_commands(std::string_view(text.data(), text.size()));
    assert(result.complete);
    assert(find_command(result.value, "CPMAddPackage") != nullptr);
  }

  std::puts("test_cmake_scanner: OK");
  return 0;
}
