// ctest unit test for the composer producer (framework-free): composer.lock,
// and the composer.json fallback read where no lock sits beside it. A
// manifest requirement is a declared range, so it lands version-less at
// Medium confidence: see composer.hpp.
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
  // when parsed, then its declared requirements become components, so a
  // project that never committed a lock still gets a dependency list. Each
  // is Medium confidence with a VERSION-LESS purl: a `require` range is a
  // constraint, not a resolved version, and a purl carrying "^7.8" could
  // never match a real OSV/CPE record, so the version is dropped rather than
  // guessed and the range is kept as evidence. require-dev gets
  // Scope::Excluded. The platform pseudo-requirements are not Packagist
  // packages, so they are skipped under one counted warning.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": {
        "guzzlehttp/guzzle": "^7.8",
        "php": "^8.1",
        "php-64bit": "*",
        "ext-json": "*",
        "lib-curl": "*",
        "composer-runtime-api": "^2.0",
        "hhvm": "*"
      },
      "require-dev": {
        "phpunit/phpunit": "^10.0"
      }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);

    // merge_all orders by purl, so guzzlehttp sorts before phpunit.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/guzzlehttp/guzzle");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].name == "guzzlehttp/guzzle");
    BOMWERK_TEST_CHECK(result.value[0].supplier == "guzzlehttp");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("composer.json") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("(requires ^7.8)") !=
                       std::string::npos);

    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/phpunit/phpunit");
    BOMWERK_TEST_CHECK(result.value[1].version.empty());
    BOMWERK_TEST_CHECK(result.value[1].scope == Scope::Excluded);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::Medium);

    // php, php-64bit, ext-json, lib-curl, composer-runtime-api, hhvm: six
    // skips, one warning.
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("6 platform requirement(s)") !=
                       std::string::npos);
  }

  // Given a composer.json whose requirement is an exact version rather than a
  // range, when parsed, then the purl is STILL version-less: composer resolves
  // even an exact requirement against its own rules (replace, provide,
  // conflict, stability flags), so the manifest alone does not prove what is
  // installed. Only a lock does, and that is what the High tier is for.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": { "monolog/monolog": "3.6.0" }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/monolog/monolog");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("(requires 3.6.0)") !=
                       std::string::npos);
  }

  // Given a composer.json with no require maps at all, when parsed, then it is
  // silent: a library that declares no dependencies is normal, not degraded.
  // This is where the manifest fallback differs from composer.lock, whose
  // missing `packages` arrays do warn.
  {
    TempTree tree;
    tree.write("composer.json", R"({ "name": "acme/widget", "type": "library" })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a composer.json whose require names something that is not
  // vendor/package, when parsed, then that entry is skipped and counted
  // separately from the platform skips: composer names always have exactly
  // one slash, so a bare name has no namespace to put in the purl.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": {
        "monolog": "^3.0",
        "/leading": "^1.0",
        "trailing/": "^1.0",
        "acme/widget": "^2.0"
      }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/acme/widget");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("3 requirement(s) not named") !=
                       std::string::npos);
  }

  // Given real vendors whose names merely START with a platform prefix
  // (php-http, php-di) beside genuine platform requirements, when parsed,
  // then the vendors become components and only the slash-less platform names
  // are skipped: a prefix match alone would silently drop php-http/httplug.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": {
        "php-http/httplug": "^2.0",
        "php-di/php-di": "^7.0",
        "php-64bit": "*",
        "ext-json": "*",
        "lib-curl": "*",
        "composer-plugin-api": "^2.0"
      }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/php-di/php-di");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/php-http/httplug");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("4 platform requirement(s)") !=
                       std::string::npos);
  }

  // Given a composer.json whose require is not an object, when parsed, then it
  // degrades to a warning and no components, never a throw (rule 1).
  {
    TempTree tree;
    tree.write("composer.json", R"({ "require": ["monolog/monolog"] })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("require is not an object") !=
                       std::string::npos);
  }

  // Given a composer.json that is not valid JSON, when parsed, then it is
  // skipped with a warning rather than throwing past this boundary (rule 1).
  {
    TempTree tree;
    tree.write("composer.json", R"({ "require": { "acme/widget": )");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("not valid JSON") != std::string::npos);
  }

  // Given a lock in one directory and a lockless composer.json in a sibling
  // directory, when parsed, then suppression is PER DIRECTORY: the covered
  // manifest is skipped and the uncovered one is still read. A tree-wide
  // check would silently drop the second package set.
  {
    TempTree tree;
    tree.write("covered/composer.json", R"({
      "require": { "acme/ignored": "^1.0" }
    })");
    tree.write("covered/composer.lock", R"({
      "packages": [ { "name": "acme/resolved", "version": "1.2.3" } ]
    })");
    tree.write("uncovered/composer.json", R"({
      "require": { "acme/declared": "^2.0" }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/acme/declared");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/acme/resolved@1.2.3");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::High);
  }

  // Given a package that one directory's lock resolved and another
  // directory's lockless composer.json also requires, when parsed, then only
  // the versioned entry survives: the version-less one is a weaker duplicate
  // of the same package, so listing both would count one dependency twice.
  // A package only the manifest knows about is untouched.
  {
    TempTree tree;
    tree.write("app/composer.lock", R"({
      "packages": [ { "name": "symfony/console", "version": "v5.4.47" } ]
    })");
    tree.write("tests/fixture/composer.json", R"({
      "require": {
        "symfony/console": "^5.4",
        "acme/only-declared": "^1.0"
      }
    })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/acme/only-declared");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Medium);
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/symfony/console@v5.4.47");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::High);
  }

  // Given the same package resolved at two versions by two locks, and also
  // declared by a lockless composer.json, when parsed, then both versions
  // stay and the version-less duplicate is the only thing dropped.
  {
    TempTree tree;
    tree.write("a/composer.lock", R"({
      "packages": [ { "name": "symfony/process", "version": "v5.4.51" } ]
    })");
    tree.write("b/composer.lock", R"({
      "packages": [ { "name": "symfony/process", "version": "v6.4.0" } ]
    })");
    tree.write("c/composer.json", R"({ "require": { "symfony/process": "^5.4" } })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/symfony/process@v5.4.51");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/symfony/process@v6.4.0");
  }

  // Given a lock that lists a package only under packages-dev, and a lockless
  // composer.json that requires it at runtime, when parsed, then BOTH stay:
  // dropping the runtime requirement would make the package look dev-only,
  // which is the one fact the lock's entry cannot stand in for.
  {
    TempTree tree;
    tree.write("app/composer.lock", R"({
      "packages": [],
      "packages-dev": [ { "name": "phpunit/phpunit", "version": "11.1.3" } ]
    })");
    tree.write("lib/composer.json", R"({ "require": { "phpunit/phpunit": "^11.0" } })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/phpunit/phpunit");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/phpunit/phpunit@11.1.3");
    BOMWERK_TEST_CHECK(result.value[1].scope == Scope::Excluded);
  }

  // …whereas a dev-only requirement in the manifest IS shadowed by that same
  // dev-only lock entry: nothing is lost, they agree on scope.
  {
    TempTree tree;
    tree.write("app/composer.lock", R"({
      "packages": [],
      "packages-dev": [ { "name": "phpunit/phpunit", "version": "11.1.3" } ]
    })");
    tree.write("lib/composer.json", R"({ "require-dev": { "phpunit/phpunit": "^11.0" } })");

    const Result<std::vector<Component>> result = composer_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/phpunit/phpunit@11.1.3");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Excluded);
  }

  // Given more manifest requirements than the package budget allows, when
  // parsed, then the deterministic prefix is kept and the result is
  // incomplete: the fallback path honours the budget exactly as the lock path
  // does.
  {
    TempTree tree;
    tree.write("composer.json", R"({
      "require": {
        "acme/alpha": "^1.0",
        "acme/beta": "^2.0",
        "acme/gamma": "^3.0"
      }
    })");

    composer_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = composer_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:composer/acme/alpha");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:composer/acme/beta");
  }

  // Given both composer.json and composer.lock in the same directory, when
  // parsed, then only the lock is read: it is composer's own resolver
  // output, so it is authoritative, and the manifest's declared ranges would
  // only add a weaker duplicate. The skip is silent: not opening a file this
  // producer has no reason to read is not a degraded scan.
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
  // with no lock anywhere in the tree, when parsed, then it is ignored even
  // though nothing covers it: vendor/acme/lib/composer.json is acme's own
  // declaration, not this project's, and reporting it would blame the
  // operator for someone else's file
  // (`core::is_inside_installed_dependencies`). Silent, like the lock-wins
  // skip above.
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
