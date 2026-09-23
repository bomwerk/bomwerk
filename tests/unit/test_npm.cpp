// ctest unit test for the package-lock.json producer (framework-free).
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/lockfiles/npm.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace npm_parser = bomwerk::parsers::lockfiles::npm;

int main()
{
  // Given a v3 lockfile with a runtime dep, a scoped dep and a dev-only dep,
  // when parsed, then the root "" entry is skipped, every package is High
  // confidence, the scope keeps its %40 namespace, and ONLY the dev package
  // carries Scope::Excluded: recorded from the lockfile, never guessed.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "name": "demo-app",
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "demo-app", "version": "1.0.0" },
        "node_modules/left-pad": {
          "version": "1.3.0",
          "integrity": "sha512-mqiF8Vp/1Grx1v0Y3f2c0M8u30YvrO1uHkni6nAaCFBSTZaFyG8crRXfHtGWqYIm/pgW6TkVCa+PZIRAlSN1WA==",
          "license": "WTFPL"
        },
        "node_modules/@scope/pkg": { "version": "2.0.0" },
        "node_modules/typescript": { "version": "5.4.5", "dev": true }
      }
    })");

    const Result<std::vector<Component>> result = npm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    // Purl-sorted: %40scope < left-pad < typescript.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/%40scope/pkg@2.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:npm/left-pad@1.3.0");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:npm/typescript@5.4.5");
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[1].scope == Scope::Required);
    BOMWERK_TEST_CHECK(result.value[2].scope == Scope::Excluded);
    BOMWERK_TEST_CHECK(result.value[1].license == "WTFPL");
    BOMWERK_TEST_CHECK(result.value[1].sha256.empty());  // integrity is sha512 -> evidence only
    // An npm scope names a real registry-enforced organization, so it
    // doubles as NTIA/CRA supplier evidence; an unscoped package states none.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "scope");
    BOMWERK_TEST_CHECK(result.value[1].supplier.empty());
    BOMWERK_TEST_CHECK(result.value[1].evidence.size() == 1);
    BOMWERK_TEST_CHECK(result.value[1].evidence[0].detail.find("integrity sha512-") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[1]) == Confidence::High);
  }

  // Given a nested install (`node_modules/a/node_modules/b`), when parsed,
  // then the name is the LAST node_modules segment: package `b`.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "lockfileVersion": 2,
      "packages": {
        "node_modules/a": { "version": "1.0.0" },
        "node_modules/a/node_modules/b": { "version": "2.0.0" }
      }
    })");

    const Result<std::vector<Component>> result = npm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/a@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:npm/b@2.0.0");
  }

  // Given workspace entries (a path key outside node_modules, a link entry and
  // a version-less entry), when parsed, then all three are skipped with ONE
  // counted warning: first-party code is not a dependency.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "monorepo" },
        "packages/app": { "version": "0.0.1" },
        "node_modules/app": { "link": true, "resolved": "packages/app" },
        "node_modules/no-version": {},
        "node_modules/real-dep": { "version": "4.2.0" }
      }
    })");

    const Result<std::vector<Component>> result = npm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/real-dep@4.2.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("3 workspace/link entrie(s)") !=
                       std::string::npos);
  }

  // Given an npm <7 lockfile (lockfileVersion 1, nested dependencies tree),
  // when parsed, then no components are guessed and ONE clear warning asks for
  // a regenerate: the exit-1 path, never silence.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "lockfileVersion": 1,
      "dependencies": { "left-pad": { "version": "1.3.0" } }
    })");

    const Result<std::vector<Component>> result = npm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("lockfileVersion 1 unsupported") !=
                       std::string::npos);
  }

  // Given hostile input (not JSON, absurd nesting, a v3 file with a malformed
  // packages map), when parsed, then each degrades to one warning and the run
  // never crashes or throws (rule 1).
  {
    TempTree not_json_tree;
    not_json_tree.write("package-lock.json", "this is not json {{{");
    const Result<std::vector<Component>> not_json_result = npm_parser::parse(not_json_tree.root());
    BOMWERK_TEST_CHECK(not_json_result.complete);
    BOMWERK_TEST_CHECK(not_json_result.value.empty());
    BOMWERK_TEST_CHECK(not_json_result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(not_json_result.warnings[0].message.find("not valid JSON") !=
                       std::string::npos);

    TempTree deep_tree;
    deep_tree.write("package-lock.json", std::string(200, '[') + std::string(200, ']'));
    const Result<std::vector<Component>> deep_result = npm_parser::parse(deep_tree.root());
    BOMWERK_TEST_CHECK(deep_result.complete);
    BOMWERK_TEST_CHECK(deep_result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(deep_result.warnings[0].message.find("nesting exceeds depth limit") !=
                       std::string::npos);

    TempTree bad_packages_tree;
    bad_packages_tree.write("package-lock.json",
                            R"({ "lockfileVersion": 3, "packages": "not-a-map" })");
    const Result<std::vector<Component>> bad_packages_result =
        npm_parser::parse(bad_packages_tree.root());
    BOMWERK_TEST_CHECK(bad_packages_result.complete);
    BOMWERK_TEST_CHECK(bad_packages_result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(bad_packages_result.warnings[0].message.find(
                           "packages map missing or malformed") != std::string::npos);
  }

  // Given a lockfile larger than the byte cap, when parsed, then it is skipped
  // with a warning: a truncated JSON document cannot parse, so skipping beats
  // guessing.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "lockfileVersion": 3,
      "packages": { "node_modules/left-pad": { "version": "1.3.0" } }
    })");

    npm_parser::ParseOptions options;
    options.max_file_bytes = 10;
    const Result<std::vector<Component>> result = npm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("exceeds size limit, skipped") !=
                       std::string::npos);
  }

  // Given more packages than max_total_packages, when parsed, then the budget
  // stops the parse early with a warning instead of unbounded output.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "lockfileVersion": 3,
      "packages": {
        "node_modules/one": { "version": "1.0.0" },
        "node_modules/two": { "version": "1.0.0" },
        "node_modules/three": { "version": "1.0.0" }
      }
    })");

    npm_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = npm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/one@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:npm/three@1.0.0");
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("npm: package limit 2 reached") !=
                       std::string::npos);

    options.max_total_packages = 3;
    const Result<std::vector<Component>> exact_limit_result =
        npm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 3);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given one package-lock.json that exactly fills the budget plus a second
  // file with another valid entry, when parsed, then that later entry proves
  // exhaustion: the deterministic prefix survives, the result is incomplete,
  // exactly one warning is emitted, and the over-budget package does not leak
  // into the result.
  {
    TempTree tree;
    tree.write("package-lock.json", R"({
      "lockfileVersion": 3,
      "packages": {
        "node_modules/one": { "version": "1.0.0" },
        "node_modules/two": { "version": "1.0.0" }
      }
    })");
    tree.write("vendor/other/package-lock.json", R"({
      "lockfileVersion": 3,
      "packages": { "node_modules/four": { "version": "1.0.0" } }
    })");

    npm_parser::ParseOptions options;
    options.max_total_packages = 2;
    const Result<std::vector<Component>> result = npm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.name != "four");
    }
  }

  // Given a tree with no package-lock.json, when parsed, then the result is
  // cleanly empty: absence is not an error.
  {
    TempTree tree;
    tree.write("README.md", "no npm here\n");
    const Result<std::vector<Component>> result = npm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given more package-lock.json files than a caller-tightened
  // max_scanned_files allows, when parsed, then a warning reports the cap,
  // the run stays complete, and the scanned subset is the path-sorted
  // (deterministic) one.
  {
    TempTree tree;
    tree.write("a/package-lock.json", R"({
      "name": "demo-app",
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "demo-app", "version": "1.0.0" },
        "node_modules/aaa": { "version": "1.0.0" }
      }
    })");
    tree.write("z/package-lock.json", R"({
      "name": "demo-app",
      "lockfileVersion": 3,
      "packages": {
        "": { "name": "demo-app", "version": "1.0.0" },
        "node_modules/zzz": { "version": "1.0.0" }
      }
    })");
    npm_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = npm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/aaa@1.0.0");
  }

  std::puts("test_npm: OK");
  return 0;
}
