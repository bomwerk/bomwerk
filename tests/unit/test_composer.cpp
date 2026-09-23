// ctest unit test for the composer.lock producer (framework-free).
// composer.json is deliberately never read as a fallback: see composer.hpp.
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/lockfiles/composer.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace composer_parser = bomwerk::parsers::lockfiles::composer;

int main()
{
  // Given a composer.lock with runtime and dev packages, when parsed, then
  // dev packages get Scope::Excluded, the v-prefixed version is kept exactly
  // as written, the first license entry is captured and the dist shasum stays
  // in the evidence detail: never in Component::sha256.
  {
    TempTree tree;
    tree.write("composer.lock", R"({
      "packages": [
        {
          "name": "monolog/monolog",
          "version": "3.6.0",
          "license": ["MIT"],
          "dist": {
            "type": "zip",
            "shasum": "0f1e2d3c4b5a69788796a5b4c3d2e1f0aabbccdd"
          }
        },
        {
          "name": "guzzlehttp/guzzle",
          "version": "v7.8.1"
        }
      ],
      "packages-dev": [
        {
          "name": "phpunit/phpunit",
          "version": "v11.1.3"
        }
      ]
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    // Purl-sorted.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/guzzlehttp/guzzle@v7.8.1");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/monolog/monolog@3.6.0");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:composer/phpunit/phpunit@v11.1.3");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[1].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[2].scope == Scope::Excluded);
    BOMWERK_TEST_CHECK(result.value[1].license == "MIT");
    BOMWERK_TEST_CHECK(result.value[1].sha256.empty());
    BOMWERK_TEST_CHECK(result.value[1].evidence[0].detail.find("dist shasum 0f1e") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    BOMWERK_TEST_CHECK(result.value[0].name == "guzzlehttp/guzzle");
    // Composer's vendor segment is the publisher namespace: NTIA/CRA
    // supplier evidence with no extra parsing.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "guzzlehttp");
  }

  // Given entries whose name lacks the vendor/ half or whose version is
  // missing, when parsed, then they are counted into one per-file warning and
  // the well-formed entry survives.
  {
    TempTree tree;
    tree.write("composer.lock", R"({
      "packages": [
        { "name": "no-vendor-half", "version": "1.0.0" },
        { "name": "vendor/versionless" },
        { "name": "vendor/kept", "version": "2.0.0" }
      ]
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/vendor/kept@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("2 package entrie(s)") != std::string::npos);
  }

  // Given hostile input: not JSON at all, and JSON nested past the depth
  // limit: when parsed, then each degrades to exactly one warning and never
  // crashes (rule 1).
  {
    TempTree tree;
    tree.write("composer.lock", "<?php echo 'this is not json';");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("not valid JSON") != std::string::npos);
  }
  {
    TempTree tree;
    std::string deeply_nested;
    for (int depth = 0; depth < 200; ++depth)
    {
      deeply_nested += "{\"a\":";
    }
    tree.write("composer.lock", deeply_nested);

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("nesting exceeds depth limit") !=
                       std::string::npos);
  }

  // Given a lockfile with neither packages array, when parsed, then one
  // warning reports the missing arrays: real dependencies were likely
  // dropped, and silence would hide that.
  {
    TempTree tree;
    tree.write("composer.lock", R"({ "content-hash": "abc" })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("packages arrays missing") !=
                       std::string::npos);
  }

  // Given a composer.json with require and require-dev, and no composer.lock,
  // when parsed, then NOTHING is reported here: composer.json is
  // deliberately never read for dependency declarations, matching
  // `parsers::lockfiles::go`'s policy for a lockfile-less go.mod: a
  // `require` range is a constraint, not a resolved version, so it must not
  // become a synthetic component identity. `core::find_unparsed_manifests`
  // (tested separately, test_unparsed_manifests.cpp) is what tells the
  // operator a composer.json sat there unread.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": {
        "guzzlehttp/guzzle": "^7.8"
      },
      "require-dev": {
        "phpunit/phpunit": "^10.0"
      }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given both composer.json and composer.lock in the same directory, when
  // parsed, then only the lock is read: composer.json is never opened at
  // all, regardless of what sits beside it.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": { "monolog/monolog": "^3.0" }
    })");
    tree.write("composer.lock", R"({
      "packages": [
        { "name": "guzzlehttp/guzzle", "version": "7.8.1" }
      ]
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/guzzlehttp/guzzle@7.8.1");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given a composer.json belonging to an installed package under vendor/,
  // with no lock anywhere in the tree, when parsed, then it stays empty for
  // the same reason as the top-level case above: composer.json is never
  // read, wherever it sits.
  {
    TempTree tree;
    tree.write("vendor/acme/lib/composer.json", R"({
      "require": { "monolog/monolog": "^3.0" }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given three Composer packages and a budget of two, when parsed, then the
  // deterministic two-entry prefix is retained and the result is incomplete.
  // Given a budget equal to the entry count, then the result remains complete.
  {
    TempTree tree;
    tree.write("composer.lock", R"({
      "packages": [
        { "name": "acme/alpha", "version": "1.0.0" },
        { "name": "acme/beta", "version": "2.0.0" },
        { "name": "acme/gamma", "version": "3.0.0" }
      ]
    })");

    composer_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = composer_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/acme/alpha@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/acme/beta@2.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("composer: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        composer_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given more composer.lock files than a caller-tightened max_scanned_files
  // allows, when parsed, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  {
    TempTree tree;
    tree.write("a/composer.lock", R"({"packages": [{"name": "vendor/aaa", "version": "1.0.0"}]})");
    tree.write("z/composer.lock", R"({"packages": [{"name": "vendor/zzz", "version": "1.0.0"}]})");
    composer_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = composer_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/vendor/aaa@1.0.0");
  }

  std::puts("test_composer: OK");
  return 0;
}
