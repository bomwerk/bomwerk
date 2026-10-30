// ctest unit test for the shared build-variable table and expander
// (framework-free).
#include <cstdio>
#include <string>

#include "core/build_variables.hpp"
#include "support/check.hpp"

using bomwerk::core::contains_unexpanded_variable;
using bomwerk::core::expand_variables;
using bomwerk::core::kCmakeVariableDialect;
using bomwerk::core::kMsbuildVariableDialect;
using bomwerk::core::mark_variable_ambiguous;
using bomwerk::core::merge_variable_tables;
using bomwerk::core::record_variable_definition;
using bomwerk::core::VariableTable;

int main()
{
  // Given text carrying each spelling of an unresolved reference, when
  // checked, then every one is detected; given plain text, none is.
  {
    BOMWERK_TEST_CHECK(contains_unexpanded_variable("${NAME}"));
    BOMWERK_TEST_CHECK(contains_unexpanded_variable("v$(Major).0"));
    BOMWERK_TEST_CHECK(contains_unexpanded_variable("$<TARGET_FILE:x>"));
    BOMWERK_TEST_CHECK(contains_unexpanded_variable("%(_Info.PackageVersion)"));
    BOMWERK_TEST_CHECK(contains_unexpanded_variable("$ENV{HOME}"));
    BOMWERK_TEST_CHECK(contains_unexpanded_variable("$CACHE{X}"));
    BOMWERK_TEST_CHECK(!contains_unexpanded_variable("1.2.3-beta"));
    BOMWERK_TEST_CHECK(!contains_unexpanded_variable("price is $5"));
    BOMWERK_TEST_CHECK(!contains_unexpanded_variable(""));
  }

  // Given a defined CMake variable, when text referencing it is expanded, then
  // the value is substituted, including inside a longer string and nested in a
  // name; an undefined reference stays verbatim.
  {
    VariableTable table;
    record_variable_definition(table, kCmakeVariableDialect, "VERSION", "1.2");
    record_variable_definition(table, kCmakeVariableDialect, "PART", "VERSION");
    BOMWERK_TEST_CHECK(expand_variables("v${VERSION}-rc", table, kCmakeVariableDialect) ==
                       "v1.2-rc");
    BOMWERK_TEST_CHECK(expand_variables("${${PART}}", table, kCmakeVariableDialect) == "1.2");
    BOMWERK_TEST_CHECK(expand_variables("${MISSING}/${VERSION}", table, kCmakeVariableDialect) ==
                       "${MISSING}/1.2");
    BOMWERK_TEST_CHECK(expand_variables("$(VERSION)", table, kCmakeVariableDialect) ==
                       "$(VERSION)");
  }

  // Given CMake names that differ only in case, when expanded, then they are
  // different variables; given MSBuild property names, then they are the same.
  {
    VariableTable cmake_table;
    record_variable_definition(cmake_table, kCmakeVariableDialect, "Version", "1");
    BOMWERK_TEST_CHECK(expand_variables("${version}", cmake_table, kCmakeVariableDialect) ==
                       "${version}");
    VariableTable msbuild_table;
    record_variable_definition(msbuild_table, kMsbuildVariableDialect, "AzureIdentityVersion",
                               "1.21.0");
    BOMWERK_TEST_CHECK(expand_variables("$(azureidentityversion)", msbuild_table,
                                        kMsbuildVariableDialect) == "1.21.0");
  }

  // Given a variable defined twice with different values, when expanded, then
  // it is ambiguous and stays unexpanded; defined twice with the SAME value, it
  // stays usable; defined empty, it is ambiguous.
  {
    VariableTable table;
    record_variable_definition(table, kCmakeVariableDialect, "TWICE", "a");
    record_variable_definition(table, kCmakeVariableDialect, "TWICE", "b");
    record_variable_definition(table, kCmakeVariableDialect, "SAME", "x");
    record_variable_definition(table, kCmakeVariableDialect, "SAME", "x");
    record_variable_definition(table, kCmakeVariableDialect, "EMPTY", "");
    BOMWERK_TEST_CHECK(expand_variables("${TWICE}", table, kCmakeVariableDialect) == "${TWICE}");
    BOMWERK_TEST_CHECK(expand_variables("${SAME}", table, kCmakeVariableDialect) == "x");
    BOMWERK_TEST_CHECK(expand_variables("a${EMPTY}b", table, kCmakeVariableDialect) ==
                       "a${EMPTY}b");
  }

  // Given a variable marked ambiguous, when another definition of it follows,
  // then it stays ambiguous.
  {
    VariableTable table;
    mark_variable_ambiguous(table, kCmakeVariableDialect, "NAME");
    record_variable_definition(table, kCmakeVariableDialect, "NAME", "late");
    BOMWERK_TEST_CHECK(expand_variables("${NAME}", table, kCmakeVariableDialect) == "${NAME}");
  }

  // Given two tables that disagree on one name, when merged, then that name
  // turns ambiguous and the agreed names survive.
  {
    VariableTable left;
    VariableTable right;
    record_variable_definition(left, kMsbuildVariableDialect, "Shared", "1");
    record_variable_definition(left, kMsbuildVariableDialect, "Same", "s");
    record_variable_definition(right, kMsbuildVariableDialect, "Shared", "2");
    record_variable_definition(right, kMsbuildVariableDialect, "Same", "s");
    merge_variable_tables(left, kMsbuildVariableDialect, right);
    BOMWERK_TEST_CHECK(expand_variables("$(Shared)", left, kMsbuildVariableDialect) == "$(Shared)");
    BOMWERK_TEST_CHECK(expand_variables("$(Same)", left, kMsbuildVariableDialect) == "s");
  }

  // Given two variables that reference each other, when expanded, then
  // expansion gives up and returns the original text instead of looping.
  {
    VariableTable table;
    record_variable_definition(table, kCmakeVariableDialect, "A", "${B}");
    record_variable_definition(table, kCmakeVariableDialect, "B", "${A}");
    BOMWERK_TEST_CHECK(expand_variables("${A}", table, kCmakeVariableDialect) == "${A}");
  }

  // Given a value that doubles at every level (a "billion laughs" shape),
  // when expanded, then the size limit stops it and the original text comes
  // back.
  {
    VariableTable table;
    record_variable_definition(table, kCmakeVariableDialect, "L0", "xxxxxxxxxx");
    for (int level = 1; level <= 7; ++level)
    {
      const std::string previous = "${L" + std::to_string(level - 1) + "}";
      record_variable_definition(table, kCmakeVariableDialect, "L" + std::to_string(level),
                                 previous + previous + previous + previous + previous + previous +
                                     previous + previous + previous + previous);
    }
    const std::string text = "${L7}";
    BOMWERK_TEST_CHECK(expand_variables(text, table, kCmakeVariableDialect) == text);
  }

  // Given a reference that is never closed, when expanded, then the text is
  // kept as written and nothing throws.
  {
    VariableTable table;
    record_variable_definition(table, kCmakeVariableDialect, "X", "1");
    BOMWERK_TEST_CHECK(expand_variables("a${X", table, kCmakeVariableDialect) == "a${X");
  }

  std::puts("test_build_variables: OK");
  return 0;
}
