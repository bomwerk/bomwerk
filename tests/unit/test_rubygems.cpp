// ctest unit test for the Gemfile.lock producer (framework-free).
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/lockfiles/rubygems.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace rubygems_parser = bomwerk::parsers::lockfiles::rubygems;

int main()
{
  // Given a Gemfile.lock with GEM, GIT and PATH sections, when parsed, then
  // registry and git gems are emitted High confidence (git with its
  // remote@revision in the evidence), 6-space dependency edges are never
  // gems, and the PATH spec is skipped as first-party.
  {
    TempTree tree;
    tree.write("Gemfile.lock", R"(GIT
  remote: https://github.com/example/custom-gem.git
  revision: 0f1e2d3c4b5a69788796a5b4c3d2e1f0aabbccdd
  specs:
    custom-gem (0.5.0)
      activesupport (>= 6.0)

GEM
  remote: https://rubygems.org/
  specs:
    concurrent-ruby (1.2.3)
    rack (3.0.11)
      concurrent-ruby (~> 1.0)

PATH
  remote: engines/local_engine
  specs:
    local_engine (0.9.9)

PLATFORMS
  arm64-darwin-23
  x86_64-linux

DEPENDENCIES
  custom-gem!
  rack (~> 3.0)

BUNDLED WITH
   2.5.9
)");

    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    // Purl-sorted.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:gem/concurrent-ruby@1.2.3");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:gem/custom-gem@0.5.0");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:gem/rack@3.0.11");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("remote https://rubygems.org/") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.value[1].evidence[0].detail.find(
                           "git https://github.com/example/custom-gem.git@0f1e") !=
                       std::string::npos);
  }

  // Given a platform-suffixed version, when parsed, then it is kept verbatim
  // in both the version and the purl.
  {
    TempTree tree;
    tree.write("Gemfile.lock", R"(GEM
  remote: https://rubygems.org/
  specs:
    nokogiri (1.16.5-arm64-darwin)
)");

    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == "1.16.5-arm64-darwin");
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:gem/nokogiri@1.16.5-arm64-darwin");
  }

  // Given malformed 4-space spec lines under specs:, when parsed, then they
  // are counted into one per-file warning and the good line survives.
  {
    TempTree tree;
    tree.write("Gemfile.lock", R"(GEM
  remote: https://rubygems.org/
  specs:
    no-version-parens
    (1.0.0)
    kept-gem (2.0.0)
)");

    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:gem/kept-gem@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("2 malformed spec line(s)") !=
                       std::string::npos);
  }

  // Given spec-shaped lines outside any GEM/GIT/PATH section: under
  // DEPENDENCIES, or before any header at all: when parsed, then they are
  // ignored silently: DEPENDENCIES lists requests, not resolutions.
  {
    TempTree tree;
    tree.write("Gemfile.lock", R"(    orphan-gem (1.0.0)
DEPENDENCIES
  specs:
    requested-gem (9.9.9)
)");

    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given hostile input: binary-ish garbage with no recognizable structure :
  // when parsed, then the producer stays complete and never crashes (rule 1).
  {
    TempTree tree;
    // Explicit length: the embedded NUL must reach the file, not truncate the
    // C-string literal.
    const std::string binary_garbage("\x00\x01\x02 garbage \xff\xfe\nGEM\n  specs \n  x\n", 32);
    tree.write("Gemfile.lock", binary_garbage);

    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given the same gem resolved in two Gemfile.lock files, when parsed, then
  // merge_all folds them into ONE component with both files as evidence.
  {
    TempTree tree;
    const std::string lock_contents = R"(GEM
  remote: https://rubygems.org/
  specs:
    rack (3.0.11)
)";
    tree.write("Gemfile.lock", lock_contents);
    tree.write("service/Gemfile.lock", lock_contents);

    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:gem/rack@3.0.11");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 2);
  }

  // Given three RubyGems packages and a budget of two, when parsed, then the
  // deterministic two-entry prefix is retained and the result is incomplete.
  // Given a budget equal to the entry count, then the result remains complete.
  {
    TempTree tree;
    tree.write("Gemfile.lock", R"(GEM
  remote: https://rubygems.org/
  specs:
    alpha (1.0.0)
    beta (2.0.0)
    gamma (3.0.0)
)");

    rubygems_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = rubygems_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:gem/alpha@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:gem/beta@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("rubygems: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        rubygems_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given more Gemfile.lock files than a caller-tightened max_scanned_files
  // allows, when parsed, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  {
    TempTree tree;
    tree.write("a/Gemfile.lock", R"(GEM
  remote: https://rubygems.org/
  specs:
    aaa (1.0.0)
)");
    tree.write("z/Gemfile.lock", R"(GEM
  remote: https://rubygems.org/
  specs:
    zzz (1.0.0)
)");
    rubygems_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = rubygems_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:gem/aaa@1.0.0");
  }

  std::puts("test_rubygems: OK");
  return 0;
}
