// ctest unit test for the shared name-list loader
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>

#include "core/name_list.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::load_name_list;

int main()
{
  const std::set<std::string> fallback = {"fallback.txt"};

  // A list file: comments and blank lines skipped, whitespace trimmed, duplicates collapsed.
  const fs::path list_path = fs::temp_directory_path() / "bomwerk_test_name_list.txt";
  {
    std::ofstream list_stream(list_path);
    list_stream << "# a comment\n"
                << "\n"
                << "  first.txt  \n"
                << "second.txt\n"
                << "first.txt\n";
  }
  auto loaded = load_name_list(list_path, "test list", fallback);
  BOMWERK_TEST_CHECK(loaded.warnings.empty());
  BOMWERK_TEST_CHECK(loaded.value.size() == 2);
  BOMWERK_TEST_CHECK(loaded.value.contains("first.txt"));
  BOMWERK_TEST_CHECK(loaded.value.contains("second.txt"));
  fs::remove(list_path);

  // Unreadable file degrades to the fallback with a warning: never throws (rule 1).
  auto missing =
      load_name_list(fs::temp_directory_path() / "bomwerk_no_such_list.txt", "test list", fallback);
  BOMWERK_TEST_CHECK(missing.warnings.size() == 1);
  BOMWERK_TEST_CHECK(missing.value == fallback);

  // A file with only comments also degrades to the fallback.
  const fs::path empty_list_path = fs::temp_directory_path() / "bomwerk_test_empty_list.txt";
  {
    std::ofstream list_stream(empty_list_path);
    list_stream << "# nothing here\n\n";
  }
  auto empty_list = load_name_list(empty_list_path, "test list", fallback);
  BOMWERK_TEST_CHECK(empty_list.warnings.size() == 1);
  BOMWERK_TEST_CHECK(empty_list.value == fallback);
  fs::remove(empty_list_path);

  std::puts("test_name_list: OK");
  return 0;
}
