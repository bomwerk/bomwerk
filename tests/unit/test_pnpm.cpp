// ctest unit test for the pnpm-lock.yaml producer (framework-free).
// The lockfile shapes below are taken from the 16-repo scan evaluation :
// freeCodeCamp's v9 lockfile, whose `packages:` section holds 2636 entries and
// whose `snapshots:` section repeats 2744 keys of the same shape, 521 of them
// carrying a resolved peer set. That second section is the reason this file
// leads with a section-confusion test.
#include <cstdio>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "parsers/lockfiles/pnpm.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::test::TempTree;

namespace pnpm_parser = bomwerk::parsers::lockfiles::pnpm;

namespace
{

/// True when any warning mentions `fragment`: warnings are aggregated per
/// file, so tests assert on content rather than on position.
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

/// True when any component's version contains `character`. A peer suffix
/// leaking out of `snapshots:` shows up exactly here, as a `(` inside a version.
bool any_version_contains(const Result<std::vector<Component>>& result, char character)
{
  for (const Component& component : result.value)
  {
    if (component.version.find(character) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

int main()
{
  // Given a v9 lockfile whose `snapshots:` section repeats every `packages:`
  // key with the peer set it was resolved against appended, when parsed, then
  // ONLY the packages section contributes: the snapshots keys must not become
  // components whose version is `1.2.3(react@18.2.0)`. This is the whole
  // correctness argument for tracking sections rather than matching key shape,
  // and it is a silent-wrong-answer bug, not a crash: hence first.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

importers:

  .:
    dependencies:
      left-pad:
        specifier: ^1.3.0
        version: 1.3.0

packages:

  '@scope/name@1.2.3':
    resolution: {integrity: sha512-AAAA}

  left-pad@1.3.0:
    resolution: {integrity: sha512-BBBB}

snapshots:

  '@scope/name@1.2.3(react@18.2.0)':
    dependencies:
      left-pad: 1.3.0

  left-pad@1.3.0: {}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    // Purl-sorted: %40scope < left-pad.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/%40scope/name@1.2.3");
    BOMWERK_TEST_CHECK(result.value[0].name == "@scope/name");
    BOMWERK_TEST_CHECK(result.value[0].version == "1.2.3");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:npm/left-pad@1.3.0");
    // An npm scope names a real registry-enforced organization, so it
    // doubles as NTIA/CRA supplier evidence; an unscoped package states none.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "scope");
    BOMWERK_TEST_CHECK(result.value[1].supplier.empty());
    // The regression this test exists for.
    BOMWERK_TEST_CHECK(!any_version_contains(result, '('));
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    // pnpm records dev-vs-prod only in importers:, so nothing is narrowed.
    BOMWERK_TEST_CHECK(result.value[0].scope == Scope::Required);
    // The sha512 integrity is evidence, never Component::sha256.
    BOMWERK_TEST_CHECK(result.value[0].sha256.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given `importers:` naming first-party workspace members whose keys sit
  // deeper than a package entry, when parsed, then nothing is emitted from them
  // and nothing is warned: a monorepo declaring its own members is normal
  // shape, exactly like a rubygems PATH spec.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      dotenv:
        specifier: 16.6.1
        version: 16.6.1
    devDependencies:
      '@freecodecamp/shared':
        specifier: workspace:*
        version: link:packages/shared

  packages/shared: {}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given the pnpm v6 spelling: a leading `/` on the key and a trailing
  // `(peer@version)` suffix that v9 moved out to snapshots: when parsed, then
  // both are stripped and the version stays clean. The suffix embeds its own
  // `@`, so cutting it before the name/version split is what makes this work.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: '6.0'

packages:

  /@scope/name@1.2.3(react@18.2.0):
    resolution: {integrity: sha512-CCCC}

  /left-pad@1.3.0:
    resolution: {integrity: sha512-DDDD}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/%40scope/name@1.2.3");
    BOMWERK_TEST_CHECK(result.value[0].version == "1.2.3");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:npm/left-pad@1.3.0");
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given git and tarball dependencies, whose resolution carries no `integrity`
  // and whose key puts a URL where the version belongs, when parsed, then each
  // is skipped and counted into ONE warning rather than forced into a purl no
  // vulnerability feed could match.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: '9.0'

packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-EEEE}

  'tarball-dep@https://example.invalid/pkg.tgz':
    resolution: {tarball: https://example.invalid/pkg.tgz}

  git-dep@1.0.0:
    resolution: {repo: https://example.invalid/g.git, commit: 0f1e2d3c4b5a}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/left-pad@1.3.0");
    BOMWERK_TEST_CHECK(any_warning_contains(result, "2 git/URL entrie(s)"));
    // Counted once, not once per entry.
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
  }

  // Given an `integrity` value that is itself quoted and carries a literal
  // comma, when parsed, then the full value survives intact. A naive unquoted
  // comma-split would treat that internal comma as a field boundary and
  // truncate the value right there: the segment "integrity: 'sha512-AB"
  // still matches the field name, so the truncation would pass silently
  // rather than showing up as a missing integrity or an extra warning; only
  // the evidence text reveals it.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: '9.0'
packages:
  quoted-comma@1.0.0:
    resolution: {integrity: 'sha512-AB,CD'}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/quoted-comma@1.0.0");
    BOMWERK_TEST_CHECK(result.value[0].evidence.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("sha512-AB,CD") !=
                       std::string::npos);
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given an entry whose `resolution:` line never arrives, when parsed, then it
  // is counted separately from a git/URL skip: one is a known limitation, the
  // other is a lockfile that did not say what it resolved to.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: '9.0'

packages:

  orphan@9.9.9:
    engines: {node: '>=6.0.0'}

  left-pad@1.3.0:
    resolution: {integrity: sha512-FFFF}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/left-pad@1.3.0");
    BOMWERK_TEST_CHECK(any_warning_contains(result, "1 entrie(s) without a resolution"));
  }

  // Given a lockfileVersion this grammar does not read: v5 spells its keys
  // `/name/version`, which would split into a version-less name rather than
  // fail: when parsed, then the whole file is skipped with ONE warning and no
  // component is guessed at.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(lockfileVersion: 5.4

packages:

  /left-pad/1.3.0:
    resolution: {integrity: sha512-GGGG}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);  // degraded, never incomplete (rule 1)
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(any_warning_contains(result, "lockfileVersion '5.4' unsupported"));
  }

  // Given a YAML file with no lockfileVersion at all, when parsed, then nothing
  // is emitted: identity of the format is never assumed from key shape alone.
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml", R"(packages:

  left-pad@1.3.0:
    resolution: {integrity: sha512-HHHH}
)");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(any_warning_contains(result, "no lockfileVersion"));
  }

  // Given hostile input: tab indentation, a block scalar whose body looks like
  // mappings, a sequence, an anchor: when parsed, then the readable entries
  // still come out and the rest degrades to a counted warning. Never a throw,
  // never a crash (Hard Rule 1).
  {
    TempTree tree;
    tree.write("pnpm-lock.yaml",
               "lockfileVersion: '9.0'\n"
               "\n"
               "packages:\n"
               "\n"
               "  left-pad@1.3.0:\n"
               "    resolution: {integrity: sha512-IIII}\n"
               "    deprecated: |\n"
               "      fake@0.0.1:\n"
               "        resolution: {integrity: sha512-EVIL}\n"
               "\n"
               "\tnot-a-package@1.0.0:\n"
               "  - sequence-item\n"
               "  anchored@1.0.0: &anchor\n");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    // The block scalar's body must not smuggle in a component.
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/left-pad@1.3.0");
    BOMWERK_TEST_CHECK(any_warning_contains(result, "outside the readable YAML subset"));
  }

  // Given a lockfile larger than the read cap, when parsed, then the readable
  // prefix still yields its components and the truncation is reported: a
  // partial answer, never nothing.
  {
    TempTree tree;
    std::string lockfile = "lockfileVersion: '9.0'\n\npackages:\n\n";
    for (int index = 0; index < 200; ++index)
    {
      lockfile += "  pkg" + std::to_string(index) + "@1.0.0:\n";
      lockfile += "    resolution: {integrity: sha512-JJJJ}\n";
    }
    tree.write("pnpm-lock.yaml", lockfile);

    pnpm_parser::ParseOptions options;
    options.max_file_bytes = 512;
    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.value.empty());
    BOMWERK_TEST_CHECK(result.value.size() < 200);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "exceeds size limit"));
  }

  // Given more entries than the package budget allows, when parsed, then the
  // run stops early with one warning rather than growing without bound.
  {
    TempTree tree;
    std::string lockfile = "lockfileVersion: '9.0'\n\npackages:\n\n";
    for (int index = 0; index < 10; ++index)
    {
      lockfile += "  pkg" + std::to_string(index) + "@1.0.0:\n";
      lockfile += "    resolution: {integrity: sha512-KKKK}\n";
    }
    tree.write("pnpm-lock.yaml", lockfile);

    pnpm_parser::ParseOptions options;
    options.max_total_packages = 4;
    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 4);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/pkg0@1.0.0");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:npm/pkg1@1.0.0");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:npm/pkg2@1.0.0");
    BOMWERK_TEST_CHECK(result.value[3].purl == "pkg:npm/pkg3@1.0.0");
    BOMWERK_TEST_CHECK(any_warning_contains(result, "pnpm: package limit 4 reached"));

    options.max_total_packages = 10;
    const Result<std::vector<Component>> exact_limit_result =
        pnpm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(exact_limit_result.complete);
    BOMWERK_TEST_CHECK(exact_limit_result.value.size() == 10);
    BOMWERK_TEST_CHECK(exact_limit_result.warnings.empty());
  }

  // Given no pnpm-lock.yaml anywhere, when parsed, then the producer is silent:
  // absence is not a gap.
  {
    TempTree tree;
    tree.write("README.md", "nothing here\n");

    const Result<std::vector<Component>> result = pnpm_parser::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given more pnpm-lock.yaml files than a caller-tightened max_scanned_files
  // allows, when parsed, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  {
    TempTree tree;
    tree.write("a/pnpm-lock.yaml", R"(lockfileVersion: '9.0'
packages:
  aaa@1.0.0:
    resolution: {integrity: sha512-AAAA}
)");
    tree.write("z/pnpm-lock.yaml", R"(lockfileVersion: '9.0'
packages:
  zzz@1.0.0:
    resolution: {integrity: sha512-ZZZZ}
)");
    pnpm_parser::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = pnpm_parser::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:npm/aaa@1.0.0");
  }

  std::puts("test_pnpm: OK");
  return 0;
}
