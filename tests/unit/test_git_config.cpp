// ctest unit test for the git-config INI reader
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <string>

#include "core/git_config.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::GitConfig;
using bomwerk::core::parse_git_config;
using bomwerk::core::read_git_config;

namespace
{

std::size_t count_submodule_sections(const GitConfig& config)
{
  std::size_t count = 0;
  for (const auto& section : config.sections)
  {
    if (section.name == "submodule")
    {
      ++count;
    }
  }
  return count;
}

}  // namespace

int main()
{
  // Given a well-formed .gitmodules snippet, when parsed, then sections and
  // key lookups resolve, and the subsection is preserved verbatim.
  {
    const auto result = parse_git_config(
        "[submodule \"lib/mbedtls\"]\n\tpath = lib/mbedtls\n"
        "\turl = https://github.com/Mbed-TLS/mbedtls.git\n",
        ".gitmodules");
    assert(result.warnings.empty());
    assert(result.value.sections.size() == 1);
    assert(result.value.sections[0].name == "submodule");
    assert(result.value.sections[0].subsection == "lib/mbedtls");
    const std::string* path = result.value.sections[0].find("path");
    BOMWERK_TEST_CHECK(path != nullptr && *path == "lib/mbedtls");
  }

  // Given comments, blank lines and a leading UTF-8 BOM, when parsed, then they
  // are ignored/stripped and the section is still recognized.
  {
    const auto result = parse_git_config(
        "\xEF\xBB\xBF# a comment\n\n[submodule \"x\"]\n\tpath = libs/x\n", ".gitmodules");
    assert(result.value.sections.size() == 1);
    assert(result.value.sections[0].subsection == "x");
  }

  // Given a remote/origin block, when queried via GitConfig::find, then the
  // origin url comes back (used for relative submodule URL resolution).
  {
    const auto result = parse_git_config(
        "[remote \"origin\"]\n\turl = https://github.com/acme/super.git\n", "config");
    const std::string* origin = result.value.find("remote", "origin", "url");
    BOMWERK_TEST_CHECK(origin != nullptr && *origin == "https://github.com/acme/super.git");
  }

  // Given an unterminated section header, when parsed, then it is skipped with
  // a warning instead of throwing.
  {
    const auto result =
        parse_git_config("[submodule \"broken\"\n\tpath = libs/broken\n", ".gitmodules");
    assert(!result.warnings.empty());
    BOMWERK_TEST_CHECK(count_submodule_sections(result.value) == 0);
  }

  // Given an overlong line (past the per-line cap), when parsed, then that line
  // is skipped with a warning but the rest of the section still parses.
  {
    const std::string long_value(9000, 'a');
    const auto result = parse_git_config(
        "[submodule \"x\"]\n\turl = " + long_value + "\n\tpath = libs/x\n", ".gitmodules");
    assert(!result.warnings.empty());
    assert(result.value.sections.size() == 1);
    assert(result.value.sections[0].find("url") == nullptr);   // the overlong url line was dropped
    assert(result.value.sections[0].find("path") != nullptr);  // the normal line survived
  }

  // Given a real vendored fixture, when read from disk, then all 11 openssl
  // submodules are found: coverage the author did not hand-write.
  {
    const fs::path fixture = fs::path(BOMWERK_FIXTURES_DIR) / "gitmodules" / "openssl.gitmodules";
    const auto result = read_git_config(fixture);
    assert(result.warnings.empty());
    BOMWERK_TEST_CHECK(count_submodule_sections(result.value) == 11);
  }

  std::puts("test_git_config: OK");
  return 0;
}
