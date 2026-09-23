// ctest unit test for directory exclusions
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "core/exclusions.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::collision_prone_excluded_dir_names;
using bomwerk::core::default_excluded_dir_names;
using bomwerk::core::load_excluded_dir_names;

int main()
{
  const auto& excluded = default_excluded_dir_names();

  // Build/VCS/cache noise is skipped by default.
  BOMWERK_TEST_CHECK(excluded.contains(".git"));
  BOMWERK_TEST_CHECK(excluded.contains("build"));
  BOMWERK_TEST_CHECK(excluded.contains("cmake-build-debug"));
  BOMWERK_TEST_CHECK(excluded.contains("vcpkg_installed"));
  BOMWERK_TEST_CHECK(excluded.contains("buildtrees"));

  // The collision-prone subset is a strict subset of the excluded
  // names: build_file_index only trusts a name here if it is also actually
  // excluded: and never includes a VCS/cache name, which by convention never
  // holds first-party source.
  const auto& collision_prone = collision_prone_excluded_dir_names();
  BOMWERK_TEST_CHECK(collision_prone.contains("build"));
  BOMWERK_TEST_CHECK(collision_prone.contains("out"));
  for (const std::string& name : collision_prone)
  {
    BOMWERK_TEST_CHECK(excluded.contains(name));
  }
  BOMWERK_TEST_CHECK(!collision_prone.contains(".git"));
  BOMWERK_TEST_CHECK(!collision_prone.contains("vcpkg_installed"));
  BOMWERK_TEST_CHECK(!collision_prone.contains("_deps"));

  // Directories that legitimately hold source must NOT be excluded: an SBOM
  // has to see vendored third-party code and monorepo workspace packages.
  BOMWERK_TEST_CHECK(!excluded.contains("third_party"));
  BOMWERK_TEST_CHECK(!excluded.contains("vendor"));
  BOMWERK_TEST_CHECK(!excluded.contains("node_modules"));
  BOMWERK_TEST_CHECK(!excluded.contains("packages"));
  BOMWERK_TEST_CHECK(!excluded.contains("src"));

  // Excludes are runtime-configurable the same way manifest names are
  // (--exclude-list mirrors --manifest-list).
  const fs::path list_path = fs::temp_directory_path() / "bomwerk_test_exclude_list.txt";
  {
    std::ofstream list_stream(list_path);
    list_stream << "generated\n";
  }
  auto loaded = load_excluded_dir_names(list_path);
  assert(loaded.warnings.empty());
  assert(loaded.value.size() == 1);
  assert(loaded.value.contains("generated"));
  fs::remove(list_path);

  // Unreadable file degrades to the defaults with a warning: never throws (rule 1).
  auto missing = load_excluded_dir_names(fs::temp_directory_path() / "bomwerk_no_such_list.txt");
  assert(missing.warnings.size() == 1);
  assert(missing.value == default_excluded_dir_names());

  std::puts("test_exclusions: OK");
  return 0;
}
