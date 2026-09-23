// ctest unit test for `--fail-on`: CLI wiring (default, each named value, rejection
// of an unknown value) and the exit-code remap itself against two deterministic, network-free
// scenarios: a warnings-only scan and a genuinely incomplete one. Command sources are linked
// directly (same precedent as test_all_cpes_cli.cpp) since CLI command implementations are
// intentionally not a production library.
#include <CLI/CLI.hpp>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "cli/scan_command.hpp"
#include "core/exit_codes.hpp"
#include "core/sbom_format.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;
namespace core = bomwerk::core;

using bomwerk::cli::register_scan_command;
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

}  // namespace

int main()
{
  // Given no --fail-on on the command line, when scan's command line is parsed, then the option
  // defaults to Warnings: today's behavior, unchanged.
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    app.parse("scan " + tree.root().string());
    BOMWERK_TEST_CHECK(options.fail_on == core::FailOnThreshold::Warnings);
  }

  // Given each of the three documented values (mixed case), when scan's command line is parsed,
  // then it maps to the matching enum value.
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    app.parse("scan " + tree.root().string() + " --fail-on None");
    BOMWERK_TEST_CHECK(options.fail_on == core::FailOnThreshold::None);
  }
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    app.parse("scan " + tree.root().string() + " --fail-on WARNINGS");
    BOMWERK_TEST_CHECK(options.fail_on == core::FailOnThreshold::Warnings);
  }
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    app.parse("scan " + tree.root().string() + " --fail-on incomplete");
    BOMWERK_TEST_CHECK(options.fail_on == core::FailOnThreshold::Incomplete);
  }

  // Given an unrecognized --fail-on value, when scan's command line is parsed, then CLI11 rejects
  // it before run_scan ever runs.
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    bool threw = false;
    try
    {
      app.parse("scan " + tree.root().string() + " --fail-on sometimes");
    }
    catch (const CLI::ParseError&)
    {
      threw = true;
    }
    BOMWERK_TEST_CHECK(threw);
  }

  // Given a repo whose only finding is a warning (a package.json with no lockfile alongside :
  // the same shape as a real-world "django" case), when scan runs under each --fail-on
  // value, then only the exit code changes: warnings/default still fails (exit 1), incomplete
  // and none both succeed (exit 0), and the written SBOM is byte-identical across all three.
  {
    TempTree warnings_only_tree;
    warnings_only_tree.write("package.json", "{\"name\": \"example\", \"version\": \"1.0.0\"}");

    ScanOptions base_options;
    base_options.root_directory = warnings_only_tree.root();
    base_options.vuln_enabled = false;

    ScanOptions default_options = base_options;
    default_options.output_path = warnings_only_tree.root() / "default.cdx.json";
    const int default_exit_code = run_scan(default_options);
    BOMWERK_TEST_CHECK(default_exit_code == core::kExitCompletedWithWarnings);

    ScanOptions warnings_options = base_options;
    warnings_options.output_path = warnings_only_tree.root() / "warnings.cdx.json";
    warnings_options.fail_on = core::FailOnThreshold::Warnings;
    const int warnings_exit_code = run_scan(warnings_options);
    BOMWERK_TEST_CHECK(warnings_exit_code == core::kExitCompletedWithWarnings);

    ScanOptions incomplete_options = base_options;
    incomplete_options.output_path = warnings_only_tree.root() / "incomplete.cdx.json";
    incomplete_options.fail_on = core::FailOnThreshold::Incomplete;
    const int incomplete_exit_code = run_scan(incomplete_options);
    BOMWERK_TEST_CHECK(incomplete_exit_code == core::kExitClean);

    ScanOptions none_options = base_options;
    none_options.output_path = warnings_only_tree.root() / "none.cdx.json";
    none_options.fail_on = core::FailOnThreshold::None;
    const int none_exit_code = run_scan(none_options);
    BOMWERK_TEST_CHECK(none_exit_code == core::kExitClean);

    const std::string default_sbom = read_file(default_options.output_path);
    BOMWERK_TEST_CHECK(!default_sbom.empty());
    BOMWERK_TEST_CHECK(read_file(warnings_options.output_path) == default_sbom);
    BOMWERK_TEST_CHECK(read_file(incomplete_options.output_path) == default_sbom);
    BOMWERK_TEST_CHECK(read_file(none_options.output_path) == default_sbom);
  }

  // Given a genuinely incomplete scan (--all-cpes with --format spdx, rejected before any
  // producer runs: same deterministic case test_all_cpes_cli.cpp uses), when scan runs under
  // each --fail-on value, then warnings/default and incomplete both still fail (exit 2): an
  // incomplete scan is never demoted to a mere warning: while none alone succeeds (exit 0).
  {
    TempTree incomplete_tree;

    ScanOptions base_options;
    base_options.root_directory = incomplete_tree.root();
    base_options.output_path = incomplete_tree.root() / "sbom.spdx.json";
    base_options.format = core::SbomFormat::Spdx;
    base_options.all_cpes = true;
    base_options.vuln_enabled = false;

    ScanOptions default_options = base_options;
    BOMWERK_TEST_CHECK(run_scan(default_options) == core::kExitIncomplete);

    ScanOptions incomplete_options = base_options;
    incomplete_options.fail_on = core::FailOnThreshold::Incomplete;
    BOMWERK_TEST_CHECK(run_scan(incomplete_options) == core::kExitIncomplete);

    ScanOptions none_options = base_options;
    none_options.fail_on = core::FailOnThreshold::None;
    BOMWERK_TEST_CHECK(run_scan(none_options) == core::kExitClean);
  }

  return 0;
}
