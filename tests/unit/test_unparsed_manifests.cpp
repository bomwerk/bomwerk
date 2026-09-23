// ctest unit test for the unparsed-manifest reporter (framework-free).
// Every scenario below is a shape taken from the 16-repo scan evaluation, so a
// regression here is a regression against a real repository.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "core/manifest_names.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::default_manifest_names;
using bomwerk::core::ecosystem_manifests;
using bomwerk::core::EcosystemManifests;
using bomwerk::core::find_unparsed_manifests;
using bomwerk::core::UnparsedManifestReport;

namespace
{

/// A `core::FileIndex::files` for the test: root-relative and sorted, exactly
/// what `build_file_index` hands the real caller.
std::vector<fs::path> file_index(std::vector<std::string> relative_paths)
{
  std::vector<fs::path> files;
  files.reserve(relative_paths.size());
  for (const std::string& relative_path : relative_paths)
  {
    files.emplace_back(relative_path);
  }
  std::sort(files.begin(), files.end());
  return files;
}

}  // namespace

int main()
{
  // Given a repo whose only npm lockfile is one with no parser yet, when
  // scanned, then one npm finding names it as a lockfile. This was
  // backstage/cal.com/electron with a yarn.lock, each reporting "manifest files
  // found: 0" and exiting clean; with the yarn and pnpm producers landed, bun.lock is what
  // still stands in for that shape.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"bun.lock", "README.md"}));
    BOMWERK_TEST_CHECK(reports.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].ecosystem == "npm");
    BOMWERK_TEST_CHECK(reports[0].filename == "bun.lock");
    BOMWERK_TEST_CHECK(reports[0].is_lockfile);
    BOMWERK_TEST_CHECK(reports[0].paths.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].paths[0] == fs::path("bun.lock"));
  }

  // Given a yarn.lock alone, when scanned, then NOTHING is reported: the producer reads
  // both Yarn generations, so the ecosystem is covered. This is the assertion
  // that would have fired before that producer existed and must never fire again.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"yarn.lock", "package.json", "README.md"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given a requirements-family file beside a loose Python manifest, when
  // scanned, then the variant counts as supported coverage and pyproject.toml
  // does not produce a false unparsed-manifest warning.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"pyproject.toml", "requirements-docs.txt"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // …and the same for a pnpm-lock.yaml alone, which the pnpm producer reads. This is
  // freeCodeCamp, which reported only its 2 submodules while 2636 dependencies
  // sat unread in the lockfile beside them.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"pnpm-lock.yaml", "package.json", "README.md"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given a supported lockfile beside the unsupported one, when scanned, then
  // nothing is reported: the ecosystem was read.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"package-lock.json", "bun.lock"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given a supported lockfile in an ANCESTOR directory, when scanned, then the
  // nested unsupported lockfile is covered by it.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"a/package-lock.json", "a/b/bun.lock"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given the two lockfiles in SIBLING subtrees, when scanned, then the unread
  // one is still reported: a package-lock.json in an unrelated subtree
  // resolves nothing for it. This is the rust repo's shape, which carries a
  // lockfile of each kind in unrelated trees.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"a/bun.lock", "b/package-lock.json"}));
    BOMWERK_TEST_CHECK(reports.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].ecosystem == "npm");
    BOMWERK_TEST_CHECK(reports[0].paths[0] == fs::path("a/bun.lock"));
  }

  // Given a cargo workspace: one root Cargo.lock over many member Cargo.toml
  // files: when scanned, then nothing is reported. rust has 60 locks against
  // 369 manifests; per-file reporting would bury the run in ~300 false
  // warnings, which is why suppression walks ancestors rather than siblings.
  {
    std::vector<std::string> workspace_paths = {"Cargo.lock", "Cargo.toml"};
    for (int member_index = 0; member_index < 300; ++member_index)
    {
      workspace_paths.push_back("crates/member" + std::to_string(member_index) + "/Cargo.toml");
    }
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index(workspace_paths));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given correctly paired go.mod/go.sum across many modules, when scanned,
  // then nothing is reported: kubernetes carries 39 of each and exits clean
  // today, and must keep doing so.
  {
    std::vector<std::string> module_paths;
    for (int module_index = 0; module_index < 39; ++module_index)
    {
      const std::string directory = "staging/mod" + std::to_string(module_index) + "/";
      module_paths.push_back(directory + "go.mod");
      module_paths.push_back(directory + "go.sum");
    }
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index(module_paths));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given a composer.json alone, when scanned, then ONE finding names it: a
  // declared `require` range is not a resolved version, so composer.json is a
  // loose manifest, not a supported lock: the same tier go.mod sits in. This
  // is laravel/laravel-framework's shape: composer.json with no
  // composer.lock, since a library package does not ship one.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"composer.json", "artisan"}));
    BOMWERK_TEST_CHECK(reports.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].ecosystem == "composer");
    BOMWERK_TEST_CHECK(reports[0].filename == "composer.json");
    BOMWERK_TEST_CHECK(!reports[0].is_lockfile);
    BOMWERK_TEST_CHECK(reports[0].paths.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].paths[0] == fs::path("composer.json"));
  }

  // Given composer.json WITH its lock, when scanned, then nothing is reported.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"composer.json", "composer.lock"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given a monorepo: one unread lockfile over 200 package.json files: when
  // scanned, then exactly ONE finding names the lockfile. The lockfile tier
  // outranks the loose tier, so the operator reads one problem, not two.
  {
    std::vector<std::string> monorepo_paths = {"bun.lock", "package.json"};
    for (int package_index = 0; package_index < 200; ++package_index)
    {
      monorepo_paths.push_back("packages/p" + std::to_string(package_index) + "/package.json");
    }
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index(monorepo_paths));
    BOMWERK_TEST_CHECK(reports.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].filename == "bun.lock");
    BOMWERK_TEST_CHECK(reports[0].is_lockfile);
  }

  // …and the same monorepo under yarn or pnpm is now silent end to end: both
  // producers read those lockfiles, so the 200 member package.json files are covered
  // too. These are backstage's and freeCodeCamp's shapes, the repos that
  // motivated the whole ticket.
  for (const std::string& lockfile_name : {std::string("yarn.lock"), std::string("pnpm-lock.yaml")})
  {
    std::vector<std::string> monorepo_paths = {lockfile_name, "package.json"};
    for (int package_index = 0; package_index < 200; ++package_index)
    {
      monorepo_paths.push_back("packages/p" + std::to_string(package_index) + "/package.json");
    }
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index(monorepo_paths));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // Given an INSTALLED dependency tree, when scanned, then its manifests are
  // not reported: they belong to the dependency, not to the scanned project,
  // and node_modules/vendor are not pruned from the walk itself.
  {
    const std::vector<UnparsedManifestReport> reports = find_unparsed_manifests(
        file_index({"node_modules/left-pad/package.json", "node_modules/x/bun.lock",
                    "vendor/acme/lib/composer.json", "src/main.cpp"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }

  // …but a manifest OUTSIDE the installed tree is still reported, so the filter
  // above cannot silence the repo's own lockfile.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"bun.lock", "node_modules/left-pad/package.json"}));
    BOMWERK_TEST_CHECK(reports.size() == 1);
    BOMWERK_TEST_CHECK(reports[0].filename == "bun.lock");
    BOMWERK_TEST_CHECK(reports[0].paths.size() == 1);
  }

  // Given a tree with no dependency manifests at all, when scanned, then there
  // is nothing to report: absence is not a finding.
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"README.md", "src/main.cpp"}));
    BOMWERK_TEST_CHECK(reports.empty());
  }
  BOMWERK_TEST_CHECK(find_unparsed_manifests({}).empty());

  // Given several unread ecosystems at once, when scanned, then findings come
  // back ordered by ecosystem so two runs emit identical bytes (rule 3).
  {
    const std::vector<UnparsedManifestReport> reports =
        find_unparsed_manifests(file_index({"web/bun.lock", "api/Cargo.toml", "Gemfile"}));
    BOMWERK_TEST_CHECK(reports.size() == 3);
    BOMWERK_TEST_CHECK(reports[0].ecosystem == "cargo");
    BOMWERK_TEST_CHECK(reports[1].ecosystem == "npm");
    BOMWERK_TEST_CHECK(reports[2].ecosystem == "rubygems");
    BOMWERK_TEST_CHECK(reports[1].filename == "bun.lock");
  }

  // Given the table itself, then every supported lockfile is a name the scan
  // actually looks for, and no filename is claimed as both readable and not.
  // These invariants are what force the composer fallback to move its entry left rather than
  // leaving a parser shipped and still reported as missing.
  {
    for (const EcosystemManifests& ecosystem : ecosystem_manifests())
    {
      BOMWERK_TEST_CHECK(!ecosystem.ecosystem.empty());
      for (const std::string_view supported_name : ecosystem.supported_locks)
      {
        BOMWERK_TEST_CHECK(default_manifest_names().contains(std::string(supported_name)));
      }
      for (const std::string_view unsupported_name : ecosystem.unsupported_locks)
      {
        BOMWERK_TEST_CHECK(!default_manifest_names().contains(std::string(unsupported_name)));
      }
      for (const std::string_view loose_name : ecosystem.loose_manifests)
      {
        BOMWERK_TEST_CHECK(!default_manifest_names().contains(std::string(loose_name)));
      }
    }
  }

  std::puts("test_unparsed_manifests: OK");
  return 0;
}
