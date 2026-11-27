// ctest unit test for atomic artifact writes through the real `scan` command.
//
// core/atomic_file's own test injects a failure at every step; this one checks
// the end-to-end contract an operator relies on: when an artifact cannot be
// written, scan exits 2 (core/exit_codes.hpp) and the file from the previous
// run is still there, whole, with no temporary file left beside it. Command
// sources are linked directly (same precedent as test_fail_on_cli.cpp).
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

#include "cli/scan_command.hpp"
#include "core/exit_codes.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace core = bomwerk::core;

using bomwerk::cli::run_scan;
using bomwerk::cli::ScanOptions;
using bomwerk::test::TempTree;

namespace
{

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

/// Whether `directory` holds any staged `*.bomwerk-*.tmp` file.
bool has_leftover_temporary_file(const fs::path& directory)
{
  std::error_code error;
  for (const fs::directory_entry& entry : fs::directory_iterator(directory, error))
  {
    const std::string name = entry.path().filename().string();
    const bool has_suffix = name.size() >= 4 && name.compare(name.size() - 4, 4, ".tmp") == 0;
    if (name.find(".bomwerk-") != std::string::npos && has_suffix)
    {
      return true;
    }
  }
  return false;
}

/// A repository whose scan is deterministic and network-free: one package.json
/// and no lockfile (a warnings-only scan, exit 1).
ScanOptions scan_options_for(const TempTree& repository, const fs::path& output_path)
{
  ScanOptions options;
  options.root_directory = repository.root();
  options.output_path = output_path;
  options.vuln_enabled = false;
  return options;
}

}  // namespace

int main()
{
  TempTree repository;
  repository.write("package.json", "{\"name\": \"example\", \"version\": \"1.0.0\"}");

  // Given an output directory that is not writable and holds the previous
  // run's SBOM, when scan runs again, then it exits 2, the previous SBOM is
  // byte-identical, and no temporary file is left. Root ignores permission
  // bits, so this case only runs as an ordinary user.
#if !defined(_WIN32)
  if (::geteuid() != 0)
  {
    TempTree output;
    const fs::path sbom_path = output.root() / "sbom.cdx.json";
    BOMWERK_TEST_CHECK(run_scan(scan_options_for(repository, sbom_path)) ==
                       core::kExitCompletedWithWarnings);
    const std::string previous_sbom = read_file(sbom_path);
    BOMWERK_TEST_CHECK(!previous_sbom.empty());

    fs::permissions(output.root(), fs::perms::owner_read | fs::perms::owner_exec,
                    fs::perm_options::replace);
    const int exit_code = run_scan(scan_options_for(repository, sbom_path));
    fs::permissions(output.root(), fs::perms::owner_all, fs::perm_options::replace);

    BOMWERK_TEST_CHECK(exit_code == core::kExitIncomplete);
    BOMWERK_TEST_CHECK(read_file(sbom_path) == previous_sbom);
    BOMWERK_TEST_CHECK(!has_leftover_temporary_file(output.root()));
  }
#endif

  // Given an output path that is a directory, when scan runs, then it exits 2,
  // the directory and its contents are intact, and no temporary file is left.
  {
    TempTree output;
    output.write("sbom.cdx.json/keep.txt", "keep");
    const fs::path sbom_path = output.root() / "sbom.cdx.json";
    BOMWERK_TEST_CHECK(run_scan(scan_options_for(repository, sbom_path)) == core::kExitIncomplete);
    BOMWERK_TEST_CHECK(fs::is_directory(sbom_path));
    BOMWERK_TEST_CHECK(read_file(sbom_path / "keep.txt") == "keep");
    BOMWERK_TEST_CHECK(!has_leftover_temporary_file(output.root()));
  }

  // Given a writable SBOM path but a --coverage path that is a directory, when
  // scan runs, then the SBOM is written whole, the coverage write fails, and
  // scan exits 2 rather than reporting success.
  {
    TempTree output;
    output.write("coverage.json/keep.txt", "keep");
    const fs::path sbom_path = output.root() / "sbom.cdx.json";
    ScanOptions options = scan_options_for(repository, sbom_path);
    options.coverage_path = output.root() / "coverage.json";
    BOMWERK_TEST_CHECK(run_scan(options) == core::kExitIncomplete);
    BOMWERK_TEST_CHECK(!read_file(sbom_path).empty());
    BOMWERK_TEST_CHECK(fs::is_directory(options.coverage_path));
    BOMWERK_TEST_CHECK(!has_leftover_temporary_file(output.root()));
  }

  // Given a previous SBOM, when scan runs again successfully, then it is
  // replaced in place and no temporary file is left.
  {
    TempTree output;
    output.write("sbom.cdx.json", "previous run");
    const fs::path sbom_path = output.root() / "sbom.cdx.json";
    BOMWERK_TEST_CHECK(run_scan(scan_options_for(repository, sbom_path)) ==
                       core::kExitCompletedWithWarnings);
    const std::string replaced = read_file(sbom_path);
    BOMWERK_TEST_CHECK(replaced != "previous run");
    BOMWERK_TEST_CHECK(replaced.find("CycloneDX") != std::string::npos);
    BOMWERK_TEST_CHECK(!has_leftover_temporary_file(output.root()));
  }

  std::puts("test_atomic_artifacts_cli: OK");
  return 0;
}
