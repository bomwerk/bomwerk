// ctest unit test for the repo-level scan config loader (core/scan_config).
#include <cstdio>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

#include "core/sbom_format.hpp"
#include "core/scan_config.hpp"
#include "core/warning.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::load_scan_config;
using bomwerk::core::SbomFormat;
using bomwerk::core::ScanConfig;
using bomwerk::core::SpdxVersion;
using bomwerk::core::Warning;
using bomwerk::test::TempTree;

namespace
{

/// True when any warning's message mentions `needle`: warning wording may
/// evolve, the subject named in it must not.
bool warnings_mention(const std::vector<Warning>& warnings, const std::string& needle)
{
  for (const Warning& warning : warnings)
  {
    if (warning.message.find(needle) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

int main()
{
  // Given a complete, valid bomwerk.toml, when loaded, then every field lands
  // and there are no warnings.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[scan]\n"
               "include = [\"app\", \"libs/core\"]\n"
               "exclude = [\"app/playground/\"]\n"
               "exclude_dir_names = [\"build\", \".git\"]\n"
               "manifest_names = [\"package-lock.json\"]\n"
               "all = true\n"
               "include_submodule_contents = true\n"
               "max_packages = 25000\n"
               "\n"
               "[output]\n"
               "format = \"spdx\"\n"
               "spdx_version = \"2.3\"\n"
               "path = \"out/sbom.json\"\n"
               "html = \"out/report.html\"\n"
               "report_config = \"branding.json\"\n"
               "coverage = \"out/coverage.json\"\n"
               "\n"
               "[product]\n"
               "id = \"acme-firmware\"\n"
               "version = \"1.2.3\"\n"
               "\n"
               "[cra]\n"
               "manufacturer_name = \"Acme Corp\"\n"
               "manufacturer_email = \"legal@acme.example\"\n"
               "security_contact = \"security@acme.example\"\n"
               "vulnerability_disclosure_url = \"https://acme.example/security\"\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.complete);
    BOMWERK_TEST_CHECK(loaded.warnings.empty());
    const std::vector<fs::path> expected_includes{"app", "libs/core"};
    // The trailing slash on "app/playground/" is normalized away so the
    // walk's component-wise prefix matching sees a clean subtree path.
    const std::vector<fs::path> expected_excludes{"app/playground"};
    BOMWERK_TEST_CHECK(loaded.value.include_paths == expected_includes);
    BOMWERK_TEST_CHECK(loaded.value.exclude_paths == expected_excludes);
    BOMWERK_TEST_CHECK(loaded.value.excluded_dir_names == std::set<std::string>({"build", ".git"}));
    BOMWERK_TEST_CHECK(loaded.value.manifest_names == std::set<std::string>({"package-lock.json"}));
    BOMWERK_TEST_CHECK(loaded.value.scan_all_directories.has_value() &&
                       *loaded.value.scan_all_directories);
    BOMWERK_TEST_CHECK(loaded.value.include_submodule_contents.has_value() &&
                       *loaded.value.include_submodule_contents);
    BOMWERK_TEST_CHECK(loaded.value.max_packages.has_value() &&
                       *loaded.value.max_packages == 25000);
    BOMWERK_TEST_CHECK(loaded.value.format.has_value() && *loaded.value.format == SbomFormat::Spdx);
    BOMWERK_TEST_CHECK(loaded.value.spdx_version.has_value() &&
                       *loaded.value.spdx_version == SpdxVersion::V2_3);
    BOMWERK_TEST_CHECK(loaded.value.output_path == fs::path("out/sbom.json"));
    BOMWERK_TEST_CHECK(loaded.value.html_report_path == fs::path("out/report.html"));
    BOMWERK_TEST_CHECK(loaded.value.report_config_path == fs::path("branding.json"));
    BOMWERK_TEST_CHECK(loaded.value.coverage_path == fs::path("out/coverage.json"));
    BOMWERK_TEST_CHECK(loaded.value.product_id == "acme-firmware");
    BOMWERK_TEST_CHECK(loaded.value.product_version == "1.2.3");
    BOMWERK_TEST_CHECK(loaded.value.cra_metadata.manufacturer_name == "Acme Corp");
    BOMWERK_TEST_CHECK(loaded.value.cra_metadata.manufacturer_email == "legal@acme.example");
    BOMWERK_TEST_CHECK(loaded.value.cra_metadata.security_contact == "security@acme.example");
    BOMWERK_TEST_CHECK(loaded.value.cra_metadata.vulnerability_disclosure_url ==
                       "https://acme.example/security");
  }

  // Given an unknown key inside [cra] (a typo), when loaded, then it
  // warns by name and every other [cra] key still lands: same one-bad-key
  // shouldn't-cost-the-rest contract every other table already has.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[cra]\n"
               "manufacturer_nam = \"Acme Corp\"\n"  // typo
               "security_contact = \"security@acme.example\"\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[cra].manufacturer_nam"));
    BOMWERK_TEST_CHECK(loaded.value.cra_metadata.manufacturer_name.empty());
    BOMWERK_TEST_CHECK(loaded.value.cra_metadata.security_contact == "security@acme.example");
  }

  // Given a missing file, when loaded, then one warning and an empty config :
  // never a throw, never complete = false (rule 1).
  {
    TempTree tree;
    const auto loaded = load_scan_config(tree.root() / "no_such_bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.complete);
    BOMWERK_TEST_CHECK(loaded.warnings.size() == 1);
    BOMWERK_TEST_CHECK(loaded.value.include_paths.empty());
    BOMWERK_TEST_CHECK(!loaded.value.format.has_value());
    BOMWERK_TEST_CHECK(!loaded.value.max_packages.has_value());
  }

  // Given malformed TOML, when loaded, then one warning and an empty config :
  // the toml++ parse_error is confined inside the loader.
  {
    TempTree tree;
    tree.write("bomwerk.toml", "[scan\ninclude = not-even-toml");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.complete);
    BOMWERK_TEST_CHECK(loaded.warnings.size() == 1);
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "not valid TOML"));
  }

  // Given a wrong-typed value, when loaded, then that key warns and is
  // ignored while the rest of the file still applies.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[scan]\n"
               "include = \"app\"\n"  // must be an array, not a string
               "all = true\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].include"));
    BOMWERK_TEST_CHECK(loaded.value.include_paths.empty());
    BOMWERK_TEST_CHECK(loaded.value.scan_all_directories.has_value() &&
                       *loaded.value.scan_all_directories);
  }

  // Given a wrong type, zero, a negative value, or a value above the
  // repository-config ceiling for max_packages, when loaded, then each value
  // warns and is ignored so the caller retains its trusted default.
  {
    const std::vector<std::string> invalid_max_packages_values{"\"many\"", "0", "-1", "100001"};
    for (const std::string& configured_value : invalid_max_packages_values)
    {
      TempTree tree;
      tree.write("bomwerk.toml",
                 "[scan]\n"
                 "max_packages = " +
                     configured_value + "\n");
      const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
      BOMWERK_TEST_CHECK(loaded.complete);
      BOMWERK_TEST_CHECK(!loaded.value.max_packages.has_value());
      BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].max_packages"));
      BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "1 through 100000"));
    }
  }

  // Given [scan] include_submodule_contents absent, when loaded, then it
  // stays disengaged so the caller keeps its default: submodule contents are
  // skipped unless something explicitly asks for them.
  {
    TempTree tree;
    tree.write("bomwerk.toml", "[scan]\nall = true\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.warnings.empty());
    BOMWERK_TEST_CHECK(!loaded.value.include_submodule_contents.has_value());
  }

  // Given a wrong-typed include_submodule_contents, when loaded, then it warns
  // by name and stays disengaged rather than being read as truthy: a repo
  // must not widen its own scan by writing a non-boolean.
  {
    TempTree tree;
    tree.write("bomwerk.toml", "[scan]\ninclude_submodule_contents = \"yes\"\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].include_submodule_contents"));
    BOMWERK_TEST_CHECK(!loaded.value.include_submodule_contents.has_value());
  }

  // Given unknown tables and keys (a typo, or the deliberately unsupported
  // [vuln] table: the repo under audit must not switch off its own audit),
  // when loaded, then each warns by name and is ignored.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[scan]\n"
               "includ = [\"app\"]\n"  // typo
               "\n"
               "[vuln]\n"
               "enabled = false\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].includ"));
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[vuln]"));
    BOMWERK_TEST_CHECK(loaded.value.include_paths.empty());
  }

  // Given paths that could escape the scanned tree (absolute, or containing
  // ".." after normalization), when loaded, then each entry warns and is
  // dropped while safe entries survive: the config is untrusted input.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[scan]\n"
               "include = [\"/etc\", \"../sibling\", \"app/../../escape\", \"app/../ok\"]\n"
               "\n"
               "[output]\n"
               "path = \"/tmp/anywhere.json\"\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    // "app/../ok" normalizes to "ok", which stays inside the tree; the other
    // three cannot be made safe and are dropped.
    const std::vector<fs::path> expected_includes{"ok"};
    BOMWERK_TEST_CHECK(loaded.value.include_paths == expected_includes);
    BOMWERK_TEST_CHECK(loaded.value.output_path.empty());
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "/etc"));
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[output].path"));
  }

  // Given a "." entry (naming the whole scanned tree) in either include or
  // exclude, when loaded, then it warns and is dropped: the per-subtree
  // filter can never match "." during the walk, so letting it through would
  // silently do nothing (worst for exclude, which would look like it excludes
  // everything but actually excludes nothing).
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[scan]\n"
               "include = [\".\", \"app\"]\n"
               "exclude = [\".\"]\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    const std::vector<fs::path> expected_includes{"app"};
    BOMWERK_TEST_CHECK(loaded.value.include_paths == expected_includes);
    BOMWERK_TEST_CHECK(loaded.value.exclude_paths.empty());
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].include"));
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].exclude"));
  }

  // Given more entries than the per-array cap, when loaded, then the array is
  // truncated with a warning rather than growing the walk's per-file scan
  // cost unboundedly: a hostile bomwerk.toml packing thousands of subtree
  // strings into the 1 MiB byte cap must not turn every file/directory visit
  // during the walk into an O(entries) scan.
  {
    TempTree tree;
    std::string toml_text = "[scan]\ninclude = [";
    constexpr int kEntriesWritten = 300;
    for (int index = 0; index < kEntriesWritten; ++index)
    {
      if (index > 0)
      {
        toml_text += ", ";
      }
      toml_text += "\"dir" + std::to_string(index) + "\"";
    }
    toml_text += "]\n";
    tree.write("bomwerk.toml", toml_text);
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.value.include_paths.size() == 256);
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[scan].include"));
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "more than 256 entries"));
  }

  // Given an invalid enum value, when loaded, then it warns and the optional
  // stays disengaged so the caller keeps its default.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[output]\n"
               "format = \"sbomx\"\n"
               "spdx_version = \"9.9\"\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(!loaded.value.format.has_value());
    BOMWERK_TEST_CHECK(!loaded.value.spdx_version.has_value());
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[output].format"));
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[output].spdx_version"));
  }

  // Given a file above the size cap, when loaded, then it is refused whole
  // with one warning: a truncated TOML could half-parse into something the
  // author never wrote.
  {
    TempTree tree;
    std::string oversized = "[scan]\n# ";
    oversized.append(2 * 1024 * 1024, 'x');
    tree.write("bomwerk.toml", oversized);
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.warnings.size() == 1);
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "1 MiB"));
    BOMWERK_TEST_CHECK(loaded.value.include_paths.empty());
  }

  // Given a [warnings] suppress list, when loaded, then bare codes and
  // ecosystem-specific entries land verbatim and there are no warnings.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[warnings]\n"
               "suppress = [\"BW-CORE-004\", \"BW-CORE-005:npm\"]\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.warnings.empty());
    BOMWERK_TEST_CHECK(loaded.value.suppressed_warning_codes.size() == 2);
    BOMWERK_TEST_CHECK(loaded.value.suppressed_warning_codes.count("BW-CORE-004") == 1);
    BOMWERK_TEST_CHECK(loaded.value.suppressed_warning_codes.count("BW-CORE-005:npm") == 1);
  }

  // Given an unknown key under [warnings], when loaded, then it warns by name like any other
  // table, and a wrong-typed `suppress` degrades to an empty list with one warning.
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[warnings]\n"
               "supress = [\"BW-CORE-004\"]\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[warnings].supress"));
    BOMWERK_TEST_CHECK(loaded.value.suppressed_warning_codes.empty());
  }
  {
    TempTree tree;
    tree.write("bomwerk.toml",
               "[warnings]\n"
               "suppress = \"BW-CORE-004\"\n");
    const auto loaded = load_scan_config(tree.root() / "bomwerk.toml");
    BOMWERK_TEST_CHECK(loaded.warnings.size() == 1);
    BOMWERK_TEST_CHECK(warnings_mention(loaded.warnings, "[warnings].suppress"));
    BOMWERK_TEST_CHECK(loaded.value.suppressed_warning_codes.empty());
  }

  std::puts("test_scan_config: OK");
  return 0;
}
