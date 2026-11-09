// ctest unit test for the runtime-configurable manifest-name list
#include <cstdio>
#include <filesystem>
#include <fstream>

#include "core/manifest_names.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::default_manifest_names;
using bomwerk::core::is_inside_installed_dependencies;
using bomwerk::core::load_manifest_names;
using bomwerk::core::matches_manifest_name;

int main()
{
  // Built-in defaults cover the C/C++ parser targets (submodules, CMake, conan, vcpkg).
  BOMWERK_TEST_CHECK(default_manifest_names().contains(".gitmodules"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("vcpkg.json"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("conan.lock"));

  // …and the lockfile targets (npm, Python, Go).
  BOMWERK_TEST_CHECK(default_manifest_names().contains("package-lock.json"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("uv.lock"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("poetry.lock"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("requirements.txt"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("go.sum"));

  // Given the canonical requirements manifest name, when matching filenames,
  // then the exact, hyphenated and underscored forms are recognized.
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements-docs.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements_proselint.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements-dev-test.txt", "requirements.txt"));

  // Given the dot-separator prefix and suffix conventions, when
  // matching filenames, then both directions are recognized.
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements.ide.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements.test-specific.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(matches_manifest_name("driver.requirements.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(matches_manifest_name("basic.requirements.txt", "requirements.txt"));

  // Given lookalikes or a custom manifest name, when matching filenames, then
  // only exact custom names match and the requirements family stays gated by
  // the canonical requirements.txt entry.
  BOMWERK_TEST_CHECK(!matches_manifest_name("dev-requirements.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements-.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements_.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements-dev.in", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements-dev.TXT", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements.txt.bak", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements-docs.txt", "custom.lock"));
  BOMWERK_TEST_CHECK(matches_manifest_name("requirements-docs.txt", "requirements-docs.txt"));

  // Given degenerate dot-family qualifiers or the still-out-of-scope
  // hyphen/underscore suffix shapes, when matching filenames, then none of
  // them match -- the dot suffix/prefix families require a non-empty
  // qualifier, and this round deliberately covers dot only.
  BOMWERK_TEST_CHECK(!matches_manifest_name("requirements..txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name(".requirements.txt", "requirements.txt"));
  BOMWERK_TEST_CHECK(!matches_manifest_name("dev_requirements.txt", "requirements.txt"));

  // …and the lockfile targets (Rust, JVM, .NET, PHP, Ruby).
  BOMWERK_TEST_CHECK(default_manifest_names().contains("Cargo.lock"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("pom.xml"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("gradle.lockfile"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("packages.lock.json"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("composer.lock"));
  // The composer.json fallback only ever sees a file the walk collected, and
  // `core::build_file_index` collects by this set: without the name here the
  // parser is dead code.
  BOMWERK_TEST_CHECK(default_manifest_names().contains("composer.json"));

  // Installed-dependency trees match on a whole path component, never a
  // prefix or substring, so a project directory that merely resembles one is
  // still the project's own.
  BOMWERK_TEST_CHECK(is_inside_installed_dependencies("vendor/acme/lib/composer.json"));
  BOMWERK_TEST_CHECK(is_inside_installed_dependencies("app/node_modules/x/package.json"));
  BOMWERK_TEST_CHECK(is_inside_installed_dependencies(".venv/lib/requirements.txt"));
  BOMWERK_TEST_CHECK(is_inside_installed_dependencies("bower_components/y/bower.json"));
  BOMWERK_TEST_CHECK(!is_inside_installed_dependencies("composer.json"));
  BOMWERK_TEST_CHECK(!is_inside_installed_dependencies("src/Illuminate/Auth/composer.json"));
  BOMWERK_TEST_CHECK(!is_inside_installed_dependencies("vendors/acme/composer.json"));
  BOMWERK_TEST_CHECK(!is_inside_installed_dependencies("my-vendor/composer.json"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("Gemfile.lock"));

  // …and the Yarn and pnpm lockfile targets (Yarn both generations, pnpm v6/v9).
  BOMWERK_TEST_CHECK(default_manifest_names().contains("yarn.lock"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("pnpm-lock.yaml"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("pubspec.lock"));

  // …and Zephyr's west manifest, under both spellings west itself accepts.
  BOMWERK_TEST_CHECK(default_manifest_names().contains("west.yml"));
  BOMWERK_TEST_CHECK(default_manifest_names().contains("west.yaml"));

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
  BOMWERK_TEST_CHECK(loaded.warnings.empty());
  BOMWERK_TEST_CHECK(loaded.complete);
  BOMWERK_TEST_CHECK(loaded.value.size() == 2);
  BOMWERK_TEST_CHECK(loaded.value.contains("custom.lock"));
  BOMWERK_TEST_CHECK(loaded.value.contains("requirements.txt"));
  fs::remove(list_path);

  // Unreadable file degrades to the defaults with a warning: never throws (rule 1).
  auto missing = load_manifest_names(fs::temp_directory_path() / "bomwerk_no_such_list.txt");
  BOMWERK_TEST_CHECK(missing.warnings.size() == 1);
  BOMWERK_TEST_CHECK(missing.value == default_manifest_names());

  // A file with only comments also degrades to the defaults.
  const fs::path empty_list_path = fs::temp_directory_path() / "bomwerk_test_empty_list.txt";
  {
    std::ofstream list_stream(empty_list_path);
    list_stream << "# nothing here\n\n";
  }
  auto empty_list = load_manifest_names(empty_list_path);
  BOMWERK_TEST_CHECK(empty_list.warnings.size() == 1);
  BOMWERK_TEST_CHECK(empty_list.value == default_manifest_names());
  fs::remove(empty_list_path);

  std::puts("test_manifest_names: OK");
  return 0;
}
