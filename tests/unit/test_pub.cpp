// ctest unit test for the Dart/Flutter pubspec.lock producer.
#include <cstdio>
#include <string>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/warning.hpp"
#include "parsers/lockfiles/pub.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::test::TempTree;

namespace pub_parser = bomwerk::parsers::lockfiles::pub;

namespace
{

bool any_warning_contains(const Result<std::vector<Component>>& result, const std::string& fragment)
{
  for (const bomwerk::core::Warning& warning : result.warnings)
  {
    if (warning.message.find(fragment) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

int main()
{
  // Given hosted, git, sdk and path entries, when parsed, then registry-backed
  // and pinned SDK entries emit while the local path entry stays silent.
  {
    TempTree tree;
    tree.write("pubspec.lock", R"(packages:
  analyzer:
    dependency: "direct main"
    description:
      name: analyzer
      sha256: "abc"
      url: "https://pub.dev"
    source: hosted
    version: 4.2.0
  local_pkg:
    dependency: transitive
    description:
      path: "../local_pkg"
      relative: true
    source: path
    version: 1.0.0
  git_pkg:
    dependency: transitive
    description:
      path: "."
      ref: main
      resolved-ref: abcdef1234567890
      url: "https://github.com/example/pkg.git"
    source: git
    version: 1.0.0
  flutter:
    dependency: "direct main"
    description: flutter
    source: sdk
    version: 3.24.0
)");
    const Result<std::vector<Component>> result = pub_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pub/analyzer@4.2.0");
    BOMWERK_TEST_CHECK(result.value[0].supplier.empty());
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:pub/flutter@3.24.0");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:pub/git_pkg@1.0.0");
    BOMWERK_TEST_CHECK(result.value[2].evidence[0].detail.find("resolved-ref") !=
                       std::string::npos);
  }

  // Given an unknown source, when parsed, then it is counted once and never guessed.
  {
    TempTree tree;
    tree.write("pubspec.lock", R"(packages:
  future_pkg:
    description: {}
    source: bzr
    version: 1.0.0
)");
    const auto result = pub_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(any_warning_contains(result, "1 entrie(s) with an unrecognized source"));
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
  }

  // Given more entries than the package budget, when parsed, then output is
  // partial and the budget warning is explicit.
  {
    TempTree tree;
    tree.write("pubspec.lock", R"(packages:
  aaa:
    source: hosted
    version: 1.0.0
  bbb:
    source: hosted
    version: 1.0.0
  ccc:
    source: hosted
    version: 1.0.0
)");
    pub_parser::ParseOptions options;
    options.max_total_packages = 2;
    const auto result = pub_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "package limit 2 reached"));
  }

  // Given two lockfiles with the same package and a tightened file budget,
  // when parsed, then one deterministic file is read and the limit is warned.
  {
    TempTree tree;
    tree.write("a/pubspec.lock", "packages:\n  aaa:\n    source: hosted\n    version: 1.0.0\n");
    tree.write("z/pubspec.lock", "packages:\n  zzz:\n    source: hosted\n    version: 1.0.0\n");
    pub_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = pub_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pub/aaa@1.0.0");
    BOMWERK_TEST_CHECK(any_warning_contains(result, "file limit reached"));
  }

  // Given an oversized lockfile whose cap ends in a partial entry, when
  // parsed, then complete prefix entries survive and the partial entry does not.
  {
    TempTree tree;
    const std::string lockfile =
        "packages:\n  complete:\n    source: hosted\n    version: 1.0.0\n"
        "  partial:\n    source: hosted\n    version: 2.0.0\n";
    tree.write("pubspec.lock", lockfile);
    pub_parser::ParseOptions options;
    options.max_file_bytes = 75;
    const auto result = pub_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pub/complete@1.0.0");
    BOMWERK_TEST_CHECK(any_warning_contains(result, "exceeds size limit"));
  }

  // Given a pubspec.lock path the file index names but that does not exist on
  // disk, when parsed, then it degrades to an unreadable-file warning without
  // making the scan incomplete. build_file_index only ever indexes regular
  // files, so a directory named "pubspec.lock" would never reach this code
  // path at all; the file-index overload is used directly to force the read
  // failure, mirroring test_manifest_walk.cpp's own unreadable-path scenario.
  {
    TempTree tree;
    const bomwerk::core::FileIndex file_index{{"pubspec.lock"}};
    const auto result = pub_parser::parse(file_index, tree.root(), pub_parser::ParseOptions{});
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "unreadable file"));
  }

  // Given duplicate entries across modules, when parsed, then merge_all keeps
  // one purl-ordered component.
  {
    TempTree tree;
    const std::string lockfile = "packages:\n  shared:\n    source: hosted\n    version: 1.0.0\n";
    tree.write("a/pubspec.lock", lockfile);
    tree.write("z/pubspec.lock", lockfile);
    const auto result = pub_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:pub/shared@1.0.0");
  }

  std::puts("test_pub: OK");
  return 0;
}
