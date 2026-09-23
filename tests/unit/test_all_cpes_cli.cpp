// ctest unit test for `--all-cpes` CLI wiring across scan/trim/binscan:
// default-false flag parsing, coexistence with the network fallback flags, scan's
// CycloneDX-only rejection of --format spdx, and trim/binscan's --output
// requirement. Command sources are linked directly (same precedent as
// direct command-source CLI tests) since CLI command implementations are
// intentionally not a production library.
#include <CLI/CLI.hpp>
#include <filesystem>
#include <string>
#include <system_error>

#include "cli/binscan_command.hpp"
#include "cli/scan_command.hpp"
#include "cli/trim_command.hpp"
#include "core/exit_codes.hpp"
#include "core/sbom_format.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;
namespace core = bomwerk::core;

using bomwerk::cli::BinscanOptions;
using bomwerk::cli::register_binscan_command;
using bomwerk::cli::register_scan_command;
using bomwerk::cli::register_trim_command;
using bomwerk::cli::run_binscan;
using bomwerk::cli::run_scan;
using bomwerk::cli::run_trim;
using bomwerk::cli::ScanOptions;
using bomwerk::cli::TrimOptions;
using bomwerk::test::TempTree;

namespace
{

bool path_exists(const fs::path& path)
{
  std::error_code existence_error;
  return fs::exists(path, existence_error) && !existence_error;
}

}  // namespace

int main()
{
  // Given no --all-cpes on the command line, when each of the three commands
  // is parsed, then the option defaults false: verified through the actual
  // CLI11 wiring, not just the struct's default member initializer.
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    app.parse("scan " + tree.root().string());
    BOMWERK_TEST_CHECK(!options.all_cpes);
    BOMWERK_TEST_CHECK(!options.license_fallback);
  }
  {
    TempTree tree;
    tree.write("sbom.json", "{}");
    CLI::App app;
    TrimOptions options;
    register_trim_command(app, options);
    app.parse("trim " + (tree.root() / "sbom.json").string());
    BOMWERK_TEST_CHECK(!options.all_cpes);
  }
  {
    TempTree tree;
    tree.write("sbom.json", "{}");
    CLI::App app;
    BinscanOptions options;
    register_binscan_command(app, options);
    app.parse("binscan " + (tree.root() / "sbom.json").string());
    BOMWERK_TEST_CHECK(!options.all_cpes);
  }

  // Given all three enrichment flags together, when scan's command line is
  // parsed, then they are independently true: CPE publication, NVD matching,
  // and registry license lookup are separate operator decisions.
  {
    TempTree tree;
    CLI::App app;
    ScanOptions options;
    register_scan_command(app, options);
    app.parse("scan " + tree.root().string() + " --all-cpes --cpe-fallback --license-fallback");
    BOMWERK_TEST_CHECK(options.all_cpes);
    BOMWERK_TEST_CHECK(options.cpe_fallback);
    BOMWERK_TEST_CHECK(options.license_fallback);
  }

  // Given --format spdx and --all-cpes together, when scan runs, then it is
  // rejected (exit 2) before any producer runs or any file is written: SPDX
  // has no property taxonomy to carry the provenance marker.
  {
    TempTree tree;
    ScanOptions options;
    options.root_directory = tree.root();
    options.output_path = tree.root() / "sbom.spdx.json";
    options.format = core::SbomFormat::Spdx;
    options.all_cpes = true;
    options.vuln_enabled = false;
    const int exit_code = run_scan(options);
    BOMWERK_TEST_CHECK(exit_code == core::kExitIncomplete);
    BOMWERK_TEST_CHECK(!path_exists(options.output_path));
  }

  // Given --all-cpes with CycloneDX (the valid combination), when scan runs
  // over an empty tree, then it is accepted and the SBOM is written :
  // rejection above is specific to SPDX, not to --all-cpes itself.
  {
    TempTree tree;
    ScanOptions options;
    options.root_directory = tree.root();
    options.output_path = tree.root() / "sbom.cdx.json";
    options.format = core::SbomFormat::CycloneDx;
    options.all_cpes = true;
    options.vuln_enabled = false;
    const int exit_code = run_scan(options);
    BOMWERK_TEST_CHECK(exit_code != core::kExitIncomplete);
    BOMWERK_TEST_CHECK(path_exists(options.output_path));
  }

  // Given --all-cpes with no --output, when trim runs, then it is rejected
  // before the SBOM is even read: there is nowhere to publish the
  // synthesized CPEs, and a report-only run must not silently drop them.
  {
    TrimOptions options;
    options.sbom_path = "/nonexistent/sbom.cdx.json";  // never reached
    options.all_cpes = true;
    const int exit_code = run_trim(options);
    BOMWERK_TEST_CHECK(exit_code == core::kExitIncomplete);
  }

  // Given the same combination, when binscan runs, then it is rejected the
  // same way, before the SBOM or trace is read.
  {
    BinscanOptions options;
    options.sbom_path = "/nonexistent/sbom.cdx.json";  // never reached
    options.all_cpes = true;
    const int exit_code = run_binscan(options);
    BOMWERK_TEST_CHECK(exit_code == core::kExitIncomplete);
  }

  return 0;
}
