// ctest unit test for the runtime-configurable manifest-name list
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "core/manifest_names.hpp"

namespace fs = std::filesystem;

using bomwerk::core::default_manifest_names;
using bomwerk::core::load_manifest_names;
using bomwerk::core::matches_manifest_name;

int main()
{
  // Built-in defaults cover the C/C++ parser targets (submodules, CMake, conan, vcpkg).
  assert(default_manifest_names().contains(".gitmodules"));
  assert(default_manifest_names().contains("vcpkg.json"));
  assert(default_manifest_names().contains("conan.lock"));

  // …and the lockfile targets (npm, Python, Go).
  assert(default_manifest_names().contains("package-lock.json"));
  assert(default_manifest_names().contains("uv.lock"));
  assert(default_manifest_names().contains("poetry.lock"));
  assert(default_manifest_names().contains("requirements.txt"));
  assert(default_manifest_names().contains("go.sum"));

  // Given the canonical requirements manifest name, when matching filenames,
  // then the exact, hyphenated and underscored forms are recognized.
  assert(matches_manifest_name("requirements.txt", "requirements.txt"));
  assert(matches_manifest_name("requirements-docs.txt", "requirements.txt"));
  assert(matches_manifest_name("requirements_proselint.txt", "requirements.txt"));
  assert(matches_manifest_name("requirements-dev-test.txt", "requirements.txt"));

  // Given the dot-separator prefix and suffix conventions, when
  // matching filenames, then both directions are recognized.
  assert(matches_manifest_name("requirements.ide.txt", "requirements.txt"));
  assert(matches_manifest_name("requirements.test-specific.txt", "requirements.txt"));
  assert(matches_manifest_name("driver.requirements.txt", "requirements.txt"));
  assert(matches_manifest_name("basic.requirements.txt", "requirements.txt"));

  // Given lookalikes or a custom manifest name, when matching filenames, then
  // only exact custom names match and the requirements family stays gated by
  // the canonical requirements.txt entry.
  assert(!matches_manifest_name("dev-requirements.txt", "requirements.txt"));
  assert(!matches_manifest_name("requirements-.txt", "requirements.txt"));
  assert(!matches_manifest_name("requirements_.txt", "requirements.txt"));
  assert(!matches_manifest_name("requirements-dev.in", "requirements.txt"));
  assert(!matches_manifest_name("requirements-dev.TXT", "requirements.txt"));
  assert(!matches_manifest_name("requirements.txt.bak", "requirements.txt"));
  assert(!matches_manifest_name("requirements-docs.txt", "custom.lock"));
  assert(matches_manifest_name("requirements-docs.txt", "requirements-docs.txt"));

  // Given degenerate dot-family qualifiers or the still-out-of-scope
  // hyphen/underscore suffix shapes, when matching filenames, then none of
  // them match -- the dot suffix/prefix families require a non-empty
  // qualifier, and this round deliberately covers dot only.
  assert(!matches_manifest_name("requirements..txt", "requirements.txt"));
  assert(!matches_manifest_name(".requirements.txt", "requirements.txt"));
  assert(!matches_manifest_name("dev_requirements.txt", "requirements.txt"));

  // …and the lockfile targets (Rust, JVM, .NET, PHP, Ruby).
  assert(default_manifest_names().contains("Cargo.lock"));
  assert(default_manifest_names().contains("pom.xml"));
  assert(default_manifest_names().contains("gradle.lockfile"));
  assert(default_manifest_names().contains("packages.lock.json"));
  assert(default_manifest_names().contains("composer.lock"));
  assert(default_manifest_names().contains("Gemfile.lock"));

  // …and the Yarn and pnpm lockfile targets (Yarn both generations, pnpm v6/v9).
  assert(default_manifest_names().contains("yarn.lock"));
  assert(default_manifest_names().contains("pnpm-lock.yaml"));
  assert(default_manifest_names().contains("pubspec.lock"));

  // A list file: comments and blank lines skipped, whitespace trimmed, duplicates collapsed.
  const fs::path list_path = fs::temp_directory_path() / "bomwerk_test_manifest_names.txt";
  {
    std::ofstream list_stream(list_path);
    list_stream << "# custom scan profile\n"
                << "\n"
                << "  custom.lock  \n"
                << "requirements.txt\n"
                << "custom.lock\n";
  }
  auto loaded = load_manifest_names(list_path);
  assert(loaded.warnings.empty());
  assert(loaded.complete);
  assert(loaded.value.size() == 2);
  assert(loaded.value.contains("custom.lock"));
  assert(loaded.value.contains("requirements.txt"));
  fs::remove(list_path);

  // Unreadable file degrades to the defaults with a warning: never throws (rule 1).
  auto missing = load_manifest_names(fs::temp_directory_path() / "bomwerk_no_such_list.txt");
  assert(missing.warnings.size() == 1);
  assert(missing.value == default_manifest_names());

  // A file with only comments also degrades to the defaults.
  const fs::path empty_list_path = fs::temp_directory_path() / "bomwerk_test_empty_list.txt";
  {
    std::ofstream list_stream(empty_list_path);
    list_stream << "# nothing here\n\n";
  }
  auto empty_list = load_manifest_names(empty_list_path);
  assert(empty_list.warnings.size() == 1);
  assert(empty_list.value == default_manifest_names());
  fs::remove(empty_list_path);

  std::puts("test_manifest_names: OK");
  return 0;
}
