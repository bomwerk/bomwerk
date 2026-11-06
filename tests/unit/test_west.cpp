// ctest unit test for the Zephyr west manifest producer.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "parsers/embedded/west.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;

namespace fs = std::filesystem;
namespace west = bomwerk::parsers::embedded::west;

namespace
{

const fs::path kWestFixtures = fs::path(BOMWERK_FIXTURES_DIR) / "west";

bool any_warning_contains(const Result<std::vector<Component>>& result, const std::string& fragment)
{
  return std::any_of(result.warnings.begin(), result.warnings.end(),
                     [&fragment](const bomwerk::core::Warning& warning)
                     { return warning.message.find(fragment) != std::string::npos; });
}

std::size_t warnings_with_code(const Result<std::vector<Component>>& result, WarningCode code)
{
  return static_cast<std::size_t>(std::count_if(result.warnings.begin(), result.warnings.end(),
                                                [code](const bomwerk::core::Warning& warning)
                                                { return warning.code == code; }));
}

/// The component named `name`, or nullptr: output order is the merge order, so
/// tests look components up rather than index them.
const Component* find_component(const Result<std::vector<Component>>& result,
                                const std::string& name)
{
  for (const Component& component : result.value)
  {
    if (component.name == name)
    {
      return &component;
    }
  }
  return nullptr;
}

}  // namespace

int main()
{
  // Given every project resolving through defaults.remote, when parsed, then
  // each url is url-base + name, a project without a revision takes
  // defaults.revision, groups are read past, and nothing is warned.
  {
    const auto result = west::parse(kWestFixtures / "default-remote");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    const Component* cmsis = find_component(result, "cmsis");
    BOMWERK_TEST_CHECK(cmsis != nullptr);
    BOMWERK_TEST_CHECK(
        cmsis->purl ==
        "pkg:github/zephyrproject-rtos/cmsis@1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d");
    BOMWERK_TEST_CHECK(cmsis->version == "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d");
    BOMWERK_TEST_CHECK(cmsis->supplier == "zephyrproject-rtos");
    BOMWERK_TEST_CHECK(highest_confidence(*cmsis) == Confidence::High);
    // The manifest sits at the scan root, so the workspace top directory is
    // above it and no checkout root can be claimed.
    BOMWERK_TEST_CHECK(cmsis->root.empty());
    const Component* nordic = find_component(result, "hal_nordic");
    BOMWERK_TEST_CHECK(nordic != nullptr);
    BOMWERK_TEST_CHECK(nordic->version == "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c");
  }

  // Given explicit urls, when parsed, then the url wins over the remote, a
  // non-forge host becomes pkg:generic, a trailing slash on url-base is not
  // doubled, and tags and branches are kept verbatim at Medium confidence.
  {
    const auto result = west::parse(kWestFixtures / "explicit-url");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    const Component* mcuboot = find_component(result, "mcuboot");
    BOMWERK_TEST_CHECK(mcuboot != nullptr);
    BOMWERK_TEST_CHECK(mcuboot->purl == "pkg:github/mcu-tools/mcuboot@v2.1.0");
    BOMWERK_TEST_CHECK(mcuboot->version == "v2.1.0");
    BOMWERK_TEST_CHECK(highest_confidence(*mcuboot) == Confidence::Medium);
    const Component* vendor = find_component(result, "vendor-hal");
    BOMWERK_TEST_CHECK(vendor != nullptr);
    BOMWERK_TEST_CHECK(vendor->purl.rfind("pkg:generic/vendor-hal@", 0) == 0);
    BOMWERK_TEST_CHECK(vendor->purl.find("vcs_url=") != std::string::npos);
    const Component* zephyr = find_component(result, "zephyr");
    BOMWERK_TEST_CHECK(zephyr != nullptr);
    BOMWERK_TEST_CHECK(zephyr->purl == "pkg:github/zephyrproject-rtos/zephyr@main");
  }

  // Given repo-path and no defaults.remote, when parsed, then the only remote
  // is used, repo-path names the repository and the west name the component.
  {
    const auto result = west::parse(kWestFixtures / "repo-path");
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "babblesim_base");
    BOMWERK_TEST_CHECK(result.value[0].purl ==
                       "pkg:github/babblesim/base@68baf150660213d67c29acb14bf9fccecf4612eb");
  }

  // Given import: on a project and on self, when parsed, then the importing
  // project is still a component, `import: false` is no import, and ONE
  // warning names both importers instead of guessing their projects.
  {
    const auto result = west::parse(kWestFixtures / "import");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(find_component(result, "zephyr") != nullptr);
    BOMWERK_TEST_CHECK(find_component(result, "not-imported") != nullptr);
    BOMWERK_TEST_CHECK(find_component(result, "cmsis") == nullptr);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "import: not followed"));
    BOMWERK_TEST_CHECK(any_warning_contains(result, "'self', 'zephyr'"));
    BOMWERK_TEST_CHECK(!any_warning_contains(result, "not-imported"));
  }

  // Given upstream Zephyr's real manifest checked out as a workspace, when
  // parsed, then all 81 projects become High-confidence components, project
  // paths become checkout roots inside the workspace, and the only warning is
  // self's import of submanifests.
  {
    const auto result = west::parse(kWestFixtures / "zephyr-v4.5.0");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 81);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kEntriesSkippedUnresolved) == 1);
    BOMWERK_TEST_CHECK(std::all_of(result.value.begin(), result.value.end(),
                                   [](const Component& component)
                                   { return highest_confidence(component) == Confidence::High; }));
    const Component* cmsis = find_component(result, "cmsis");
    BOMWERK_TEST_CHECK(cmsis != nullptr);
    BOMWERK_TEST_CHECK(cmsis->root == fs::path("modules/hal/cmsis"));
    const Component* cmsis_6 = find_component(result, "cmsis_6");
    BOMWERK_TEST_CHECK(cmsis_6 != nullptr);
    BOMWERK_TEST_CHECK(
        cmsis_6->purl ==
        "pkg:github/zephyrproject-rtos/cmsis_6@1c1840af7a7e757d6e2fec3ddb0e5ce0dfcc93c8");
    const Component* bsim = find_component(result, "babblesim_base");
    BOMWERK_TEST_CHECK(bsim != nullptr);
    BOMWERK_TEST_CHECK(bsim->purl ==
                       "pkg:github/babblesim/base@68baf150660213d67c29acb14bf9fccecf4612eb");
  }

  // Given a project with no revision and no defaults.revision, when parsed,
  // then it is a versionless Low-confidence component with a warning: west's
  // implicit `master` is never guessed.
  {
    TempTree tree;
    tree.write("west.yml", R"(manifest:
  remotes:
    - name: upstream
      url-base: https://github.com/zephyrproject-rtos
  projects:
    - name: floating
)");
    const auto result = west::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/zephyrproject-rtos/floating");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kUnpinnedOrUnresolvedRef) == 1);
  }

  // Given the `west.yaml` spelling, a compact list (dash at the parent key's
  // column), 4-space indentation and remotes declared AFTER projects, when
  // parsed, then all of it resolves: west reads the sections in any order.
  {
    TempTree tree;
    tree.write("west.yaml", R"(manifest:
    projects:
    - name: late
      revision: 0123456789abcdef0123456789abcdef01234567
    defaults:
        remote: upstream
    remotes:
    - name: upstream
      url-base: https://github.com/zephyrproject-rtos
)");
    const auto result = west::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(
        result.value[0].purl ==
        "pkg:github/zephyrproject-rtos/late@0123456789abcdef0123456789abcdef01234567");
  }

  // Given CRLF line endings, when parsed, then no `\r` reaches a url or a purl.
  {
    TempTree tree;
    tree.write("west.yml",
               "manifest:\r\n  remotes:\r\n    - name: upstream\r\n"
               "      url-base: https://github.com/zephyrproject-rtos\r\n"
               "  projects:\r\n    - name: crlf\r\n      revision: v1.0.0\r\n");
    const auto result = west::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/zephyrproject-rtos/crlf@v1.0.0");
  }

  // Given an embedded NUL byte, when parsed, then the file degrades to
  // warnings or a partial read and never crashes.
  {
    TempTree tree;
    const std::string with_nul("manifest:\n  projects:\n    - name: a\0b\n      url: x\n", 51);
    tree.write("west.yml", with_nul);
    const auto result = west::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
  }

  // Given a manifest above max_file_bytes, when parsed, then it is skipped
  // with a warning rather than half-read: a truncated prefix could lose the
  // remotes later projects resolve against.
  {
    TempTree tree;
    tree.write("west.yml", R"(manifest:
  projects:
    - name: big
      url: https://github.com/acme/big
      revision: v1
)");
    west::ParseOptions options;
    options.max_file_bytes = 16;
    const auto result = west::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kFileSizeLimitExceeded) == 1);
  }

  // Given more projects than the budget, when parsed, then output is partial,
  // the result is incomplete, and the limit is named in a warning.
  {
    TempTree tree;
    tree.write("west.yml", R"(manifest:
  projects:
    - name: one
      url: https://github.com/acme/one
      revision: v1
    - name: two
      url: https://github.com/acme/two
      revision: v1
)");
    west::ParseOptions options;
    options.max_total_projects = 1;
    const auto result = west::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kEntryLimitReached) == 1);
  }

  // Hostile fixtures (see fixtures/west/hostile/README.md): each warns or stays
  // silent, never crashes, never guesses, and never flips `complete`.
  const fs::path hostile = kWestFixtures / "hostile";
  {
    const auto result = west::parse(hostile / "missing-remote");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(find_component(result, "hal_ok") != nullptr);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kDependencyMissingSource) == 1);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "'cmsis'"));
  }
  {
    const auto result = west::parse(hostile / "ambiguous-remotes");
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(find_component(result, "base") != nullptr);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "'which-one'"));
  }
  {
    const auto result = west::parse(hostile / "block-scalar-fake-url");
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(find_component(result, "injected") == nullptr);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.purl.find("evil") == std::string::npos);
      BOMWERK_TEST_CHECK(component.purl.rfind("pkg:github/zephyrproject-rtos/", 0) == 0);
    }
  }
  {
    const auto result = west::parse(hostile / "tabs");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(any_warning_contains(result, "outside the readable YAML subset"));
  }
  {
    const auto result = west::parse(hostile / "self-url");
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }
  {
    const auto result = west::parse(hostile / "flow-mapping-item");
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(find_component(result, "first") != nullptr);
    BOMWERK_TEST_CHECK(find_component(result, "last") != nullptr);
    BOMWERK_TEST_CHECK(find_component(result, "flowed") == nullptr);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "malformed"));
  }
  {
    const auto result = west::parse(hostile / "not-a-manifest");
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }
  {
    const auto result = west::parse(hostile / "nameless-project");
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(find_component(result, "named") != nullptr);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "malformed"));
  }

  // Given project paths that are absolute, climb out with `..`, or name the
  // workspace top directory itself, when parsed, then the project is still
  // reported but owns no checkout root, so it cannot claim files outside its
  // own directory.
  {
    TempTree tree;
    tree.write("app/west.yml", R"(manifest:
  projects:
    - name: absolute
      url: https://github.com/acme/absolute
      revision: v1
      path: /etc
    - name: climbing
      url: https://github.com/acme/climbing
      revision: v1
      path: ../../outside
    - name: whole-tree
      url: https://github.com/acme/whole-tree
      revision: v1
      path: .
    - name: fine
      url: https://github.com/acme/fine
      revision: v1
      path: modules/fine
)");
    const auto result = west::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 4);
    for (const char* name : {"absolute", "climbing", "whole-tree"})
    {
      const Component* component = find_component(result, name);
      BOMWERK_TEST_CHECK(component != nullptr);
      BOMWERK_TEST_CHECK(component != nullptr && component->root.empty());
    }
    const Component* fine = find_component(result, "fine");
    BOMWERK_TEST_CHECK(fine != nullptr && fine->root == fs::path("modules/fine"));
  }

  // Given a project that imports but has no resolvable url, when parsed, then
  // it is skipped AND the import it would have pulled in is still named.
  {
    TempTree tree;
    tree.write("west.yml", R"(manifest:
  projects:
    - name: orphan
      import: true
)");
    const auto result = west::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kDependencyMissingSource) == 1);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kEntriesSkippedUnresolved) == 1);
  }

  std::puts("test_west: OK");
  return 0;
}
