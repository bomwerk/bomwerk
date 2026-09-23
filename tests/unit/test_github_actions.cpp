// ctest unit test for the GitHub Actions workflow dependency producer.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "parsers/ci/github_actions.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::test::TempTree;
namespace github_actions = bomwerk::parsers::ci::github_actions;

namespace
{

// A valid 40-hex (SHA-1) object id: the same synthetic pattern test_submodules.cpp uses.
const std::string kSha = "0123456789abcdef0123456789abcdef01234567";

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

const Component* find_by_purl_prefix(const std::vector<Component>& components,
                                     const std::string& prefix)
{
  for (const Component& component : components)
  {
    if (component.purl.rfind(prefix, 0) == 0)
    {
      return &component;
    }
  }
  return nullptr;
}

bool any_purl_contains(const std::vector<Component>& components, const std::string& needle)
{
  for (const Component& component : components)
  {
    if (component.purl.find(needle) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

int main()
{
  // Given a SHA-pinned reference written as a sequence-item "- uses:" line,
  // when parsed, then it is High confidence with the full SHA in the purl.
  {
    TempTree tree;
    tree.write(
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@" + kSha + "\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/actions/checkout@" + kSha);
    BOMWERK_TEST_CHECK(result.value[0].name == "checkout");
    BOMWERK_TEST_CHECK(result.value[0].supplier == "actions");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given a tag-pinned reference written as a nested "uses:" line after a
  // "- name:" step, when parsed, then it is Medium confidence, tag verbatim.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - name: Cache\n        uses: "
               "actions/cache@v4\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/actions/cache@v4");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given a reference whose ref is an unresolved ${{ }} expression, when
  // parsed, then it degrades to Low confidence with a warning, the purl
  // carries no "@" segment, and "${{" never appears in the purl.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: "
               "actions/setup-node@${{ matrix.node-action-ref }}\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/actions/setup-node");
    BOMWERK_TEST_CHECK(result.value[0].purl.find("${{") == std::string::npos);
    BOMWERK_TEST_CHECK(result.value[0].version == "${{ matrix.node-action-ref }}");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given a reference whose owner/repo is itself an unresolved expression,
  // when parsed, then no component is emitted at all -- never the syft-style
  // "pkg:github/%24/..." shape -- but a warning is still raised.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: ${{ inputs.action }}\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given a reference whose owner is a bare "$" placeholder token (curl's own
  // workflows use this, not a "${{ ... }}" expression at all), when parsed,
  // then no component is emitted -- never the syft-style "pkg:github/%24/..."
  // shape -- but a warning is still raised.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n"
               "      - uses: $/.github/actions/pkg-install\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(!any_purl_contains(result.value, "%24"));
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given a reference with no "@ref" at all, when parsed, then it degrades to
  // Low confidence with a warning and no "@" in the purl.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/checkout\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/actions/checkout");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given local action references, when parsed, then they are skipped
  // silently -- no component, no warning.
  {
    TempTree tree;
    tree.write(
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  build:\n    steps:\n      - uses: ./.github/actions/local-thing\n"
        "      - uses: ../sibling-action\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a docker:// action reference, when parsed, then it is skipped
  // silently.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: docker://alpine:3.19\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given an action whose owner is literally named "docker" (a real bug class
  // found against bomwerk's own ci.yml), when parsed, then it is NOT mistaken
  // for a docker:// action -- a normal component is emitted.
  {
    TempTree tree;
    tree.write(
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  build:\n    steps:\n      - uses: docker/build-push-action@v6\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/docker/build-push-action@v6");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given a job-level reusable-workflow "uses:" with a subpath, when parsed,
  // then the subpath is dropped from the purl.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  call-shared:\n    uses: "
               "octo-org/example-repo/.github/workflows/shared.yml@main\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/octo-org/example-repo@main");
  }

  // Given a step-level action reference with a subpath, when parsed, then the
  // subpath is dropped from the purl the same way.
  {
    TempTree tree;
    tree.write(
        ".github/workflows/ci.yml",
        "on: [push]\njobs:\n  build:\n    steps:\n      - uses: github/codeql-action/init@v3\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/github/codeql-action@v3");
  }

  // Given a commented-out "uses:" line, at top level and indented under a
  // real step, when parsed, then neither is picked up.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n"
               "      # uses: acme/should-not-appear@v1\n"
               "      - name: Real step\n"
               "        run: echo hi\n"
               "        # - uses: also/should-not-appear@v1\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a "run: |" block whose body contains a line that looks like a
  // "uses:" reference, when parsed, then it is skipped as part of the block
  // scalar body -- only a real step outside it is read.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n"
               "      - name: Print\n"
               "        run: |\n"
               "          echo \"uses: fake/fake@v1\"\n"
               "      - uses: acme/real@v1\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/real@v1");
  }

  // Given two different unresolved refs for the same owner/repo in the same
  // file, when parsed, then they collapse to one component via merge_all
  // (identical no-"@ref" purl) -- a deliberate consequence, not a bug -- and
  // both raw "uses:" lines remain individually recoverable in evidence.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n"
               "      - uses: acme/widget@${{ matrix.a }}\n"
               "      - uses: acme/widget@${{ matrix.b }}\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/widget");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 2);
  }

  // Given multiple workflow files each with multiple "uses:" lines, when
  // parsed, then every reference across every file is captured.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n"
               "      - uses: acme/one@v1\n      - uses: acme/two@v1\n");
    tree.write(".github/workflows/release.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: acme/three@v1\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 3);
  }

  // Given CRLF line endings, when parsed, then the reference is read
  // identically to an LF-only file.
  {
    TempTree tree;
    tree.write(".github/workflows/ci.yml",
               "on: [push]\r\njobs:\r\n  build:\r\n    steps:\r\n      - uses: acme/widget@v1\r\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/widget@v1");
  }

  // Given a UTF-8 BOM at the start of the file, when parsed, then the first
  // line is still read correctly.
  {
    TempTree tree;
    tree.write(
        ".github/workflows/ci.yml",
        "\xEF\xBB\xBFon: [push]\njobs:\n  build:\n    steps:\n      - uses: acme/widget@v1\n");
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/widget@v1");
  }

  // Given more "uses:" references than the configured budget, when parsed,
  // then result.complete stays true and exactly one budget warning is raised
  // even though the limit is crossed mid-file.
  {
    TempTree tree;
    std::string workflow = "on: [push]\njobs:\n  build:\n    steps:\n";
    for (int index = 0; index < 10; ++index)
    {
      workflow += "      - uses: acme/widget-" + std::to_string(index) + "@v1\n";
    }
    tree.write(".github/workflows/ci.yml", workflow);

    github_actions::ParseOptions options;
    options.max_total_uses_references = 4;
    const auto result = github_actions::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 4);
    const auto budget_warning_count = std::count_if(
        result.warnings.begin(), result.warnings.end(), [](const bomwerk::core::Warning& warning)
        { return warning.message.find("reference limit reached") != std::string::npos; });
    BOMWERK_TEST_CHECK(budget_warning_count == 1);
  }

  // Given a real vendored workflow file with a step in every form this
  // producer must handle (sequence-item "uses:", local actions, a real
  // docker:// reference, tag-pinned refs), when parsed, then only the real
  // GitHub Action references are reported.
  {
    TempTree tree;
    tree.write(".github/workflows/test.yml",
               read_file(fs::path(BOMWERK_FIXTURES_DIR) / "github-actions" / "checkout-test.yml"));
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(find_by_purl_prefix(result.value, "pkg:github/actions/checkout") != nullptr);
    BOMWERK_TEST_CHECK(find_by_purl_prefix(result.value, "pkg:github/actions/setup-node") !=
                       nullptr);
    BOMWERK_TEST_CHECK(!any_purl_contains(result.value, "bitnami"));
  }

  // Given a real vendored workflow file where every reference is SHA-pinned
  // with a trailing inline comment, when parsed, then the comment is
  // stripped and every reference rates High confidence.
  {
    TempTree tree;
    tree.write(".github/workflows/lint.yml",
               read_file(fs::path(BOMWERK_FIXTURES_DIR) / "github-actions" / "scorecard-lint.yml"));
    const auto result = github_actions::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 4);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(highest_confidence(component) == Confidence::High);
      BOMWERK_TEST_CHECK(component.purl.find('#') == std::string::npos);
    }
  }

  // Given every hostile fixture, when parsed, then the producer never
  // crashes and never returns the exit-2 (incomplete) state for a
  // merely-malformed file -- it warns and continues (rule 1).
  {
    const fs::path hostile_dir = fs::path(BOMWERK_FIXTURES_DIR) / "github-actions" / "hostile";
    for (const auto& entry : fs::directory_iterator(hostile_dir))
    {
      if (!entry.is_regular_file() || entry.path().extension() != ".yml")
      {
        continue;
      }
      TempTree tree;
      tree.write(".github/workflows/ci.yml", read_file(entry.path()));
      const auto result = github_actions::parse(tree.root());
      BOMWERK_TEST_CHECK(result.complete);  // malformed => warnings, never exit-2
    }
  }

  // Given more workflow files than a caller-tightened max_scanned_files
  // allows, when parsed, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  // Unlike every other producer's cap test, both files share one directory
  // (.github/workflows/ is not walked recursively) and differ by filename.
  {
    TempTree tree;
    tree.write(".github/workflows/a.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/aaa@v1\n");
    tree.write(".github/workflows/z.yml",
               "on: [push]\njobs:\n  build:\n    steps:\n      - uses: actions/zzz@v1\n");
    github_actions::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = github_actions::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/actions/aaa@v1");
  }

  std::puts("test_github_actions: OK");
  return 0;
}
