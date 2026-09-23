#include <cstddef>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "parsers/cpp/vcpkg.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::test::TempTree;
namespace vcpkg = bomwerk::parsers::cpp::vcpkg;

namespace
{

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream contents;
  contents << stream.rdbuf();
  return contents.str();
}

const Component* find_by_purl(const std::vector<Component>& components, const std::string& purl)
{
  for (const Component& component : components)
  {
    if (component.purl == purl)
    {
      return &component;
    }
  }
  return nullptr;
}

/// Copy a hand-written hostile byte-stream into a TempTree under the canonical
/// `vcpkg.json` name and parse it. Mirrors `test_conan.cpp`'s hostile flow.
bomwerk::core::Result<std::vector<Component>> parse_hostile(const std::string& fixture_name)
{
  const fs::path fixture = fs::path(BOMWERK_FIXTURES_DIR) / "vcpkg" / "hostile" / fixture_name;
  TempTree tree;
  tree.write("vcpkg.json", read_file(fixture));
  return vcpkg::parse(tree.root());
}

}  // namespace

int main()
{
  // Given a vcpkg.json in bomwerk's own dogfood shape: three bare-string
  // dependencies and a project name/version: when parsed, then exactly three
  // versionless Low-confidence pkg:vcpkg components result, purl-sorted, and
  // the consumer's own name is not treated as a dependency.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"name":"bomwerk","version-string":"0.1.0",)"
                             R"("dependencies":["spdlog","cli11","nlohmann-json"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/cli11");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:vcpkg/nlohmann-json");
    BOMWERK_TEST_CHECK(result.value[2].purl == "pkg:vcpkg/spdlog");
    BOMWERK_TEST_CHECK(result.value[0].name == "cli11");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
  }

  // Given an object dependency carrying only a `version>=` floor, when parsed,
  // then the purl stays versionless (a floor is a constraint, not the resolved
  // version) and Low, while the floor survives as evidence detail.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":[{"name":"fmt","version>=":"10.0.0"}]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component* fmt = find_by_purl(result.value, "pkg:vcpkg/fmt");
    BOMWERK_TEST_CHECK(fmt != nullptr);
    BOMWERK_TEST_CHECK(fmt->version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(*fmt) == Confidence::Low);
    BOMWERK_TEST_CHECK(fmt->evidence.size() == 1);
    BOMWERK_TEST_CHECK(fmt->evidence[0].detail.find("version>=10.0.0") != std::string::npos);
  }

  // Given an `overrides` entry pinning an exact version: vcpkg's in-manifest
  // lock: when parsed, then the dependency becomes a versioned, High-confidence
  // component and the pin is named in the evidence detail.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["zlib"],)"
                             R"("overrides":[{"name":"zlib","version":"1.3.1"}]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component* zlib = find_by_purl(result.value, "pkg:vcpkg/zlib@1.3.1");
    BOMWERK_TEST_CHECK(zlib != nullptr);
    BOMWERK_TEST_CHECK(zlib->version == "1.3.1");
    BOMWERK_TEST_CHECK(highest_confidence(*zlib) == Confidence::High);
    BOMWERK_TEST_CHECK(zlib->evidence[0].detail.find("override=1.3.1") != std::string::npos);
  }

  // Given a dependency that has BOTH a `version>=` floor and an exact override,
  // when parsed, then the override wins the identity version and confidence is
  // High: the lock supersedes the constraint.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":[{"name":"fmt","version>=":"9.0.0"}],)"
                             R"("overrides":[{"name":"fmt","version":"10.2.1"}]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component* fmt = find_by_purl(result.value, "pkg:vcpkg/fmt@10.2.1");
    BOMWERK_TEST_CHECK(fmt != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*fmt) == Confidence::High);
  }

  // Given an override declared under an alternate version key (`version-semver`),
  // when parsed, then it is still recognized as the pin.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["boost"],)"
                             R"("overrides":[{"name":"boost","version-semver":"1.85.0"}]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:vcpkg/boost@1.85.0") != nullptr);
  }

  // Given an object dependency with `features` and a `platform` guard, when
  // parsed, then neither leaks into the identity purl (it stays minimal) but
  // both are preserved as evidence detail.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":[{"name":"sdl2","features":["x11","wayland"],)"
                             R"("platform":"linux"}]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component* sdl2 = find_by_purl(result.value, "pkg:vcpkg/sdl2");
    BOMWERK_TEST_CHECK(sdl2 != nullptr);
    BOMWERK_TEST_CHECK(sdl2->evidence[0].detail.find("platform=linux") != std::string::npos);
    BOMWERK_TEST_CHECK(sdl2->evidence[0].detail.find("features=x11,wayland") != std::string::npos);
  }

  // Given an object dependency missing its `name`, when parsed, then it is
  // warned about and skipped while its well-formed siblings survive (rule 1:
  // partial output beats none, but never silently).
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":[{"features":["ssl"]},"curl"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/curl");
  }

  // Given a dependency element that is neither a string nor an object (a bare
  // number), when parsed, then it is warned about and skipped, siblings survive.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":[42,"zlib"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/zlib");
  }

  // Given a manifest with no `dependencies` key at all, when parsed, then it
  // yields no components and no warnings: a well-formed, dependency-free shape.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"name":"proj","version":"1.0.0"})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a ports-registry-shaped manifest (`ports/zlib/vcpkg.json`) with its
  // own name+version and a dependencies array, when parsed, then its own
  // identity is emitted as a High-confidence component AND its dependency is
  // still emitted normally.
  {
    TempTree tree;
    tree.write("ports/zlib/vcpkg.json",
               R"({"name":"zlib","version":"1.3.2","dependencies":["vcpkg-cmake"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    const Component* zlib = find_by_purl(result.value, "pkg:vcpkg/zlib@1.3.2");
    BOMWERK_TEST_CHECK(zlib != nullptr);
    BOMWERK_TEST_CHECK(zlib->version == "1.3.2");
    BOMWERK_TEST_CHECK(highest_confidence(*zlib) == Confidence::High);
    const Component* build_dependency = find_by_purl(result.value, "pkg:vcpkg/vcpkg-cmake");
    BOMWERK_TEST_CHECK(build_dependency != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*build_dependency) == Confidence::Low);
  }

  // Given a ports-registry manifest with only name+version and no
  // `dependencies` key, when parsed, then exactly one own-identity component
  // results: a dependency-free port previously vanished entirely without this
  // fix, the sharpest form of the bug.
  {
    TempTree tree;
    tree.write("ports/fmt/vcpkg.json", R"({"name":"fmt","version":"10.2.1"})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/fmt@10.2.1");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given the same name+version+no-dependencies shape but at a non-ports path,
  // when parsed, then it stays zero components: the path anchor, not the
  // manifest shape, is what triggers own-identity emission.
  {
    TempTree tree;
    tree.write("some/nested/vcpkg.json", R"({"name":"fmt","version":"10.2.1"})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a ports-registry manifest with no usable top-level `name` but a
  // well-formed `dependencies` array, when parsed, then the run warns once,
  // emits no own-identity component, and still emits the dependency.
  {
    TempTree tree;
    tree.write("ports/broken/vcpkg.json", R"({"version":"1.0.0","dependencies":["zlib"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/zlib");
  }

  // Given a ports-registry manifest whose `name` is present but whitespace-only,
  // when parsed, then it is treated the same as a missing name (trimmed empty).
  {
    TempTree tree;
    tree.write("ports/blank/vcpkg.json", R"({"name":"   ","dependencies":["zlib"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/zlib");
  }

  // Given a manifest nested one level deeper than the real registry layout
  // (`ports/<name>/nested/vcpkg.json`), when parsed, then it is treated as a
  // regular (non-port) manifest: confirms the exact-3-segment anchoring.
  {
    TempTree tree;
    tree.write("ports/zlib/nested/vcpkg.json", R"({"name":"zlib","version":"1.3.2"})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a port definition whose vcpkg.json declares a top-level `"license"`
  // (a plain SPDX id and a compound SPDX expression, the two real shapes seen
  // in vcpkg's own registry: e.g. ports/fmt and ports/curl), when parsed,
  // then the port's own-identity component carries it verbatim; a bare
  // dependency reference to the same package (no manifest of its own to read
  // a license from) stays license-less.
  {
    TempTree tree;
    tree.write("ports/fmt/vcpkg.json", R"({"name":"fmt","version":"11.0.2","license":"MIT"})");
    tree.write("ports/curl/vcpkg.json",
               R"({"name":"curl","version":"8.9.1",)"
               R"("license":"curl AND ISC AND BSD-3-Clause","dependencies":["zlib"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    const Component* fmt = find_by_purl(result.value, "pkg:vcpkg/fmt@11.0.2");
    BOMWERK_TEST_CHECK(fmt != nullptr);
    BOMWERK_TEST_CHECK(fmt->license == "MIT");
    const Component* curl = find_by_purl(result.value, "pkg:vcpkg/curl@8.9.1");
    BOMWERK_TEST_CHECK(curl != nullptr);
    BOMWERK_TEST_CHECK(curl->license == "curl AND ISC AND BSD-3-Clause");
    const Component* zlib_dependency = find_by_purl(result.value, "pkg:vcpkg/zlib");
    BOMWERK_TEST_CHECK(zlib_dependency != nullptr);
    BOMWERK_TEST_CHECK(zlib_dependency->license.empty());
  }

  // Given a port definition whose `"license"` is JSON `null` (vcpkg's own
  // convention for "not SPDX-expressed"), when parsed, then the own-identity
  // component is still emitted normally with an empty license and no warning
  //: a null license is a normal, well-formed shape, not hostile input.
  {
    TempTree tree;
    tree.write("ports/unlicensed/vcpkg.json",
               R"({"name":"unlicensed","version":"1.0.0","license":null})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].license.empty());
  }

  // Given a port with a name but no version-family key at all, when parsed,
  // then its own identity is still emitted (versionless purl) at High
  // confidence and no warning is raised: a versionless port is normal,
  // unlike a missing name.
  {
    TempTree tree;
    tree.write("ports/manifest-only/vcpkg.json", R"({"name":"manifest-only"})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/manifest-only");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given a `dependencies` value that is present but the wrong shape (an object,
  // not an array), when parsed, then the run warns and drops it rather than
  // silently reporting nothing.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":{"zlib":"1.0"}})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given an `overrides` value that is not an array, when parsed, then it is
  // warned about but the dependencies are still emitted (unpinned, Low).
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["zlib"],"overrides":"nope"})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component* zlib = find_by_purl(result.value, "pkg:vcpkg/zlib");
    BOMWERK_TEST_CHECK(zlib != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*zlib) == Confidence::Low);
  }

  // Given a malformed override entry (missing `name`), when parsed, then it is
  // warned about once and skipped; the dependency stays unpinned.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["zlib"],"overrides":[{"version":"1.0"}]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/zlib");
  }

  // Given invalid JSON, when parsed, then the run warns, produces no components
  // and stays complete: a hostile manifest never fails the scan (rule 1).
  {
    TempTree tree;
    tree.write("vcpkg.json", "{ this is not json ]");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given valid JSON whose root is an array rather than an object, when parsed,
  // then it is warned about and skipped.
  {
    TempTree tree;
    tree.write("vcpkg.json", "[1, 2, 3]");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given duplicate dependency names, when parsed, then they merge into one
  // component (rule 3: deduplicated, purl-ordered output).
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["zlib","zlib"]})");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:vcpkg/zlib");
  }

  // Given pathologically deep JSON nesting, when parsed, then the linear
  // depth pre-scan trips first and the file is skipped with a warning: never a
  // stack overflow (rule 1).
  {
    TempTree tree;
    std::string deep = R"({"dependencies":)";
    deep.append(200, '[');
    deep.append(200, ']');
    deep += "}";
    tree.write("vcpkg.json", deep);
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given a manifest larger than the read cap, when parsed with a tiny
  // max_file_bytes, then the truncated (unparseable) file is skipped with a
  // warning, never a crash.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["spdlog","fmt","zlib","boost"]})");
    vcpkg::ParseOptions options;
    options.max_file_bytes = 8;
    const auto result = vcpkg::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Given more dependencies than the requirement budget allows, when parsed,
  // then parsing stops early with a warning and the survivors are still
  // emitted: a bounded, complete-with-warnings run.
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["a","b","c","d"]})");
    vcpkg::ParseOptions options;
    options.max_total_requirements = 2;
    const auto result = vcpkg::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
  }

  // Given more vcpkg.json files than a caller-tightened max_scanned_files
  // allows, when parsed, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  // Regression: the real vcpkg ports registry has 2,862
  // ports/*/vcpkg.json files, well past the old hardcoded 2000 cap, which
  // silently dropped everything from roughly "poolstl" onward (including
  // zlib) with no way to raise the limit.
  {
    TempTree tree;
    tree.write("a/vcpkg.json", R"({"dependencies":["aaa"]})");
    tree.write("z/vcpkg.json", R"({"dependencies":["zzz"]})");
    vcpkg::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = vcpkg::parse(tree.root(), options);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    // "a/vcpkg.json" sorts before "z/vcpkg.json", so aaa is the
    // deterministic pick.
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:vcpkg/aaa") != nullptr);
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:vcpkg/zzz") == nullptr);
  }

  // Given two identical parses of the same manifest, when compared, then the
  // component ordering is byte-identical (rule 3: deterministic output).
  {
    TempTree tree;
    tree.write("vcpkg.json", R"({"dependencies":["spdlog","cli11","fmt","zlib"]})");
    const auto first = vcpkg::parse(tree.root());
    const auto second = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(first.value.size() == second.value.size());
    for (std::size_t index = 0; index < first.value.size(); ++index)
    {
      BOMWERK_TEST_CHECK(first.value[index].purl == second.value[index].purl);
    }
  }

  // Given a manifest prefixed with a UTF-8 byte-order mark (hostile fixture),
  // when parsed, then the BOM is stripped and the dependency parses normally.
  {
    const auto result = parse_hostile("bom.vcpkg.json");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:vcpkg/zlib") != nullptr);
  }

  // Given a hostile manifest mixing wrong-typed dependency and override entries,
  // when parsed, then the parser survives with warnings and still recovers the
  // one well-formed dependency.
  {
    const auto result = parse_hostile("wrong-types.vcpkg.json");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(find_by_purl(result.value, "pkg:vcpkg/fmt") != nullptr);
  }

  return 0;
}
