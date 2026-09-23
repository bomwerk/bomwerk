#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "parsers/cpp/conan.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::test::TempTree;
namespace conan = bomwerk::parsers::cpp::conan;

namespace
{

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream contents;
  contents << stream.rdbuf();
  return contents.str();
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

}  // namespace

int main()
{
  // Given a conanfile.txt with two [requires] entries and an ignored
  // [generators] section, when parsed, then exactly two Medium-confidence
  // pkg:conan components result, purl-sorted.
  {
    TempTree tree;
    tree.write("conanfile.txt",
               "[requires]\n"
               "zlib/1.2.13\n"
               "fmt/10.2.1\n"
               "\n"
               "[generators]\n"
               "CMakeDeps\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.warnings.empty());
    assert(result.value.size() == 2);
    assert(result.value[0].purl == "pkg:conan/fmt@10.2.1");
    assert(result.value[1].purl == "pkg:conan/zlib@1.2.13");
    assert(result.value[1].name == "zlib");
    assert(result.value[1].version == "1.2.13");
    assert(highest_confidence(result.value[0]) == Confidence::Medium);
    // No user/channel in the reference: no supplier is invented.
    assert(result.value[1].supplier.empty());
  }

  // Given a [requires] section header with stray surrounding whitespace
  // inside the brackets (a formatting quirk, not malformed input), when
  // parsed, then the section is still recognized: the header name is
  // trimmed before matching, so entries are not silently dropped.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[ requires ]\nzlib/1.2.13\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:conan/zlib@1.2.13");
  }

  // Given [tool_requires], [build_requires] and [test_requires] sections, when
  // parsed, then their entries are reported too, with the section named in the
  // evidence detail.
  {
    TempTree tree;
    tree.write("conanfile.txt",
               "[tool_requires]\ncmake/3.27.0\n"
               "[build_requires]\nninja/1.11.1\n"
               "[test_requires]\ngtest/1.14.0\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 3);
    const Component* cmake_component = find_by_purl_prefix(result.value, "pkg:conan/cmake");
    BOMWERK_TEST_CHECK(cmake_component != nullptr);
    BOMWERK_TEST_CHECK(cmake_component->evidence[0].detail.find("[tool_requires]") !=
                       std::string::npos);
  }

  // Given a reference with user/channel, when parsed, then the purl carries
  // channel and user qualifiers in sorted key order.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nopenssl/3.2.0@bincrafters/stable\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:conan/openssl@3.2.0?channel=stable&user=bincrafters");
    // The reference's user segment is conan's own publisher field.
    assert(result.value[0].supplier == "bincrafters");
  }

  // Given a revision-pinned reference, when parsed with defaults, then the
  // purl omits the revision (so declared and locked merge) but confidence is
  // High; when parsed with emit_recipe_revision_qualifier, the rrev qualifier
  // appears: the configurable identity the operator asked for.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nzlib/1.2.13#a5c1f2e3\n");
    const auto default_result = conan::parse(tree.root());
    assert(default_result.value.size() == 1);
    assert(default_result.value[0].purl == "pkg:conan/zlib@1.2.13");
    assert(highest_confidence(default_result.value[0]) == Confidence::High);

    conan::ParseOptions revision_options;
    revision_options.emit_recipe_revision_qualifier = true;
    const auto revision_result = conan::parse(tree.root(), revision_options);
    assert(revision_result.value.size() == 1);
    assert(revision_result.value[0].purl == "pkg:conan/zlib@1.2.13?rrev=a5c1f2e3");
  }

  // Given a version range, when parsed, then the component is reported at Low
  // confidence with the range kept verbatim: a constraint is not a pin.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nzlib/[>=1.2 <2.0]\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].version == "[>=1.2 <2.0]");
    assert(highest_confidence(result.value[0]) == Confidence::Low);
  }

  // Given comment lines, inline " #" comments and blank lines, when parsed,
  // then they are ignored while a '#' glued to the version stays a revision.
  {
    TempTree tree;
    tree.write("conanfile.txt",
               "[requires]\n"
               "# a full-line comment\n"
               "; another comment style\n"
               "zlib/1.2.13 # trailing comment\n"
               "fmt/10.2.1#abc123\n"
               "\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 2);
    assert(result.value[1].purl == "pkg:conan/zlib@1.2.13");
    assert(result.value[0].purl == "pkg:conan/fmt@10.2.1");
    assert(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given no conan files at all, when parsed, then the result is empty: not a
  // warning, not an error.
  {
    TempTree tree;
    tree.write("README.md", "no conan here\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.empty());
    assert(result.warnings.empty());
  }

  // Given two conanfile.txt in different directories naming the same
  // dependency, when parsed, then merge_all folds them into one component
  // with accumulated evidence.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nzlib/1.2.13\n");
    tree.write("app/conanfile.txt", "[requires]\nzlib/1.2.13\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].evidence.size() == 2);
  }

  // Given a file larger than max_file_bytes, when parsed, then a truncation
  // warning is emitted and the readable prefix still parses (rule 1).
  {
    TempTree tree;
    std::string contents = "[requires]\nzlib/1.2.13\n";
    contents.append(4096, '#');
    tree.write("conanfile.txt", contents);
    conan::ParseOptions tight_options;
    tight_options.max_file_bytes = 64;
    const auto result = conan::parse(tree.root(), tight_options);
    assert(result.complete);
    assert(result.value.size() == 1);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given a conanfile.py with a tuple-style requires attribute, when parsed,
  // then each literal becomes a Medium component -- the file is never
  // executed.
  {
    TempTree tree;
    tree.write("conanfile.py",
               "from conan import ConanFile\n"
               "class Pkg(ConanFile):\n"
               "    requires = \"zlib/1.2.13\", \"fmt/10.2.1\"\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 2);
    assert(result.value[1].purl == "pkg:conan/zlib@1.2.13");
    assert(highest_confidence(result.value[1]) == Confidence::Medium);
  }

  // Given a multi-line list attribute and a tool_requires attribute, when
  // parsed, then continuation lines inside brackets are followed.
  {
    TempTree tree;
    tree.write("conanfile.py",
               "class Pkg(ConanFile):\n"
               "    requires = [\n"
               "        \"boost/1.83.0\",\n"
               "        \"openssl/3.2.0@corp/stable\",\n"
               "    ]\n"
               "    tool_requires = \"cmake/3.27.0\"\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 3);
    const Component* openssl_component = find_by_purl_prefix(result.value, "pkg:conan/openssl");
    BOMWERK_TEST_CHECK(openssl_component != nullptr);
    assert(openssl_component->purl == "pkg:conan/openssl@3.2.0?channel=stable&user=corp");
  }

  // Given self.requires()/self.tool_requires() calls inside methods, when
  // parsed, then each first string argument is reported.
  {
    TempTree tree;
    tree.write("conanfile.py",
               "class Pkg(ConanFile):\n"
               "    def requirements(self):\n"
               "        self.requires(\"zlib/1.2.13\")\n"
               "        self.test_requires(\"gtest/1.14.0\")\n"
               "    def build_requirements(self):\n"
               "        self.tool_requires(\"cmake/[>=3.25]\")\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 3);
    const Component* cmake_component = find_by_purl_prefix(result.value, "pkg:conan/cmake");
    BOMWERK_TEST_CHECK(cmake_component != nullptr);
    assert(highest_confidence(*cmake_component) == Confidence::Low);  // range
  }

  // Given a docstring that merely MENTIONS self.requires("fake/1.0"), when
  // parsed, then no phantom component is reported.
  {
    TempTree tree;
    tree.write("conanfile.py",
               "class Pkg(ConanFile):\n"
               "    \"\"\"Example:\n"
               "    self.requires(\"fake/1.0\")\n"
               "    \"\"\"\n"
               "    requires = \"zlib/1.2.13\"\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:conan/zlib@1.2.13");
  }

  // Given a requires list with more than 50 continuation lines (kMaxPythonContinuationLines),
  // when parsed, then the list is truncated with a warning (Hard Rule 1: graceful degradation)
  // and parsing resumes normally for subsequent attributes.
  {
    TempTree tree;
    std::string conanfile =
        "class Pkg(ConanFile):\n"
        "    requires = [\n";
    // Add 51 distinct package entries to exceed the 50-line cap
    for (int package_index = 0; package_index < 51; ++package_index)
    {
      conanfile += "        \"pkg" + std::to_string(package_index) + "/1.0\",\n";
    }
    conanfile +=
        "    ]\n"
        "    tool_requires = \"cmake/3.27.0\"\n";
    tree.write("conanfile.py", conanfile);
    const auto result = conan::parse(tree.root());
    assert(result.complete);  // Truncation is a warning, not an error (Hard Rule 1)
    // Check that a truncation warning was emitted
    bool found_truncation_warning = false;
    for (const bomwerk::core::Warning& warning : result.warnings)
    {
      if (warning.message.find("requirement list too long, truncated") != std::string::npos)
      {
        found_truncation_warning = true;
        break;
      }
    }
    BOMWERK_TEST_CHECK(found_truncation_warning);
    // Verify that fewer than 52 components were parsed (51 requires + 1 tool_requires would be 52
    // if not truncated)
    BOMWERK_TEST_CHECK(result.value.size() < 52);
    // Check that the tool_requires attribute after the truncated list was still parsed
    const Component* cmake_component = find_by_purl_prefix(result.value, "pkg:conan/cmake");
    BOMWERK_TEST_CHECK(cmake_component != nullptr);
  }

  // Given an f-string version interpolation, when parsed, then the component
  // is still reported -- name intact, version empty, Low, with a warning
  // (never silently dropped); an interpolated NAME is warned about and
  // skipped since it has no identity.
  {
    TempTree tree;
    tree.write("conanfile.py",
               "class Pkg(ConanFile):\n"
               "    def requirements(self):\n"
               "        self.requires(f\"zlib/{self.zlib_version}\")\n"
               "        self.requires(f\"{name}/1.0\")\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(result.value[0].name == "zlib");
    assert(result.value[0].version.empty());
    assert(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(result.warnings.size() == 2);
  }

  // Given a python_requires attribute, when parsed, then the base recipe is
  // reported too -- recipe code is a dependency of the build.
  {
    TempTree tree;
    tree.write("conanfile.py",
               "class Pkg(ConanFile):\n"
               "    python_requires = \"mybase/1.0@corp/stable\"\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].evidence[0].detail.find("[python_requires]") !=
                       std::string::npos);
  }

  // Given a conan-2 lockfile with %timestamp suffixes, when parsed, then each
  // entry is a High-confidence component with the timestamp stripped and: by
  // default: the revision kept OUT of the purl so it merges with declared
  // entries.
  {
    TempTree tree;
    tree.write("conan.lock",
               "{\n"
               "  \"version\": \"0.5\",\n"
               "  \"requires\": [\n"
               "    \"zlib/1.2.13#a5c1f2e3%1708593606.497\",\n"
               "    \"fmt/10.2.1#f52e03ae%1708593599.001\"\n"
               "  ],\n"
               "  \"build_requires\": [\"cmake/3.27.0#11bb22cc%1700000000.0\"],\n"
               "  \"python_requires\": [\"mybase/1.0#dd44ee55%1700000001.0\"]\n"
               "}\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.warnings.empty());
    assert(result.value.size() == 4);
    const Component* zlib_component = find_by_purl_prefix(result.value, "pkg:conan/zlib");
    BOMWERK_TEST_CHECK(zlib_component != nullptr);
    assert(zlib_component->purl == "pkg:conan/zlib@1.2.13");
    assert(highest_confidence(*zlib_component) == Confidence::High);
    BOMWERK_TEST_CHECK(zlib_component->evidence[0].detail.find("rev=a5c1f2e3") !=
                       std::string::npos);
  }

  // Given a conan-1 graph_lock, when parsed, then node refs become components
  // and the consumer node "0" is skipped.
  {
    TempTree tree;
    tree.write("conan.lock",
               "{\n"
               "  \"graph_lock\": {\n"
               "    \"nodes\": {\n"
               "      \"0\": {\"path\": \"conanfile.py\"},\n"
               "      \"1\": {\"ref\": \"zlib/1.2.13@#abc123\"},\n"
               "      \"2\": {\"ref\": \"openssl/1.1.1w@corp/stable#def456\"}\n"
               "    }\n"
               "  },\n"
               "  \"version\": \"0.4\"\n"
               "}\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 2);
    const Component* openssl_component = find_by_purl_prefix(result.value, "pkg:conan/openssl");
    BOMWERK_TEST_CHECK(openssl_component != nullptr);
    assert(openssl_component->purl == "pkg:conan/openssl@1.1.1w?channel=stable&user=corp");
  }

  // Given a conan-1 graph_lock node missing its "ref" field, when parsed, then
  // the malformed node is skipped WITHOUT producing a spurious component, but
  // a warning surfaces so the operator knows the lockfile did not fully
  // parse: a silently empty result would hide missed dependencies (rule 1:
  // this stays a warning, never an error; complete stays true).
  {
    TempTree tree;
    tree.write("conan.lock",
               "{\n"
               "  \"graph_lock\": {\n"
               "    \"nodes\": {\n"
               "      \"0\": {\"path\": \"conanfile.py\"},\n"
               "      \"1\": {\"context\": \"host\"},\n"
               "      \"2\": {\"ref\": \"openssl/1.1.1w@corp/stable#def456\"}\n"
               "    }\n"
               "  },\n"
               "  \"version\": \"0.4\"\n"
               "}\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    const Component* openssl_component = find_by_purl_prefix(result.value, "pkg:conan/openssl");
    BOMWERK_TEST_CHECK(openssl_component != nullptr);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("graph_lock") != std::string::npos);
  }

  // Given invalid JSON in conan.lock, when parsed, then one warning and no
  // components: complete stays true (rule 1: partial beats none).
  {
    TempTree tree;
    tree.write("conan.lock", "{ not json ]\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
  }

  // Given absurdly deep JSON nesting, when parsed, then the depth guard warns
  // and refuses BEFORE the recursive parser can overflow the stack.
  {
    TempTree tree;
    std::string deep_json(50000, '[');
    tree.write("conan.lock", deep_json);
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.empty());
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given non-string entries in a requires array, when parsed, then they warn
  // and are skipped while string entries still parse.
  {
    TempTree tree;
    tree.write("conan.lock",
               "{\"version\": \"0.5\", \"requires\": [42, {\"a\": 1}, \"zlib/1.2.13#ab%1.0\"]}\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given a requires key that is present but the wrong JSON type (a bare
  // string instead of an array), when parsed, then a warning surfaces so the
  // operator knows the lockfile did not fully parse: a silently empty
  // result would hide missed dependencies, mirroring the same protection
  // already given to malformed graph_lock shapes.
  {
    TempTree tree;
    tree.write("conan.lock", "{\"version\": \"0.5\", \"requires\": \"zlib/1.2.13\"}\n");
    const auto result = conan::parse(tree.root());
    assert(result.complete);
    assert(result.value.empty());
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given the same dependency declared in conanfile.txt AND resolved in
  // conan.lock, when parsed, then merge_all folds them into ONE component
  // whose confidence is High.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nzlib/1.2.13\n");
    tree.write("conan.lock",
               "{\"version\": \"0.5\", \"requires\": [\"zlib/1.2.13#a5c1f2e3%1708593606.497\"]}\n");
    const auto result = conan::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:conan/zlib@1.2.13");
    assert(result.value[0].evidence.size() == 2);
    assert(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given the JSON `conan graph info --format=json` writes (user-run: bomwerk
  // executes nothing), when ingested, then every node except the consumer
  // root "0" becomes a High-confidence component.
  {
    TempTree tree;
    tree.write("graph.json",
               "{\n"
               "  \"graph\": {\n"
               "    \"nodes\": {\n"
               "      \"0\": {\"ref\": \"conanfile\", \"context\": \"host\"},\n"
               "      \"1\": {\"ref\": \"zlib/1.2.13#a5c1f2e3\", \"context\": \"host\"},\n"
               "      \"2\": {\"ref\": \"cmake/3.27.0#bb22\", \"context\": \"build\"}\n"
               "    }\n"
               "  }\n"
               "}\n");
    const auto result = conan::parse_graph_file(tree.root() / "graph.json", conan::ParseOptions{});
    assert(result.complete);
    assert(result.value.size() == 2);
    const Component* zlib_component = find_by_purl_prefix(result.value, "pkg:conan/zlib");
    BOMWERK_TEST_CHECK(zlib_component != nullptr);
    assert(highest_confidence(*zlib_component) == Confidence::High);
  }

  // Given a graph node missing its "ref" field, when ingested, then the
  // malformed node is skipped WITHOUT a spurious component, but a warning
  // surfaces so the operator knows the graph did not fully parse: a
  // silently empty result would hide missed dependencies, symmetric with the
  // same protection already given to malformed graph_lock shapes.
  {
    TempTree tree;
    tree.write("graph.json",
               "{\n"
               "  \"graph\": {\n"
               "    \"nodes\": {\n"
               "      \"0\": {\"ref\": \"conanfile\"},\n"
               "      \"1\": {\"context\": \"host\"},\n"
               "      \"2\": {\"ref\": \"cmake/3.27.0#bb22\"}\n"
               "    }\n"
               "  }\n"
               "}\n");
    const auto result = conan::parse_graph_file(tree.root() / "graph.json", conan::ParseOptions{});
    assert(result.complete);
    assert(result.value.size() == 1);
    const Component* cmake_component = find_by_purl_prefix(result.value, "pkg:conan/cmake");
    BOMWERK_TEST_CHECK(cmake_component != nullptr);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given an unreadable path or invalid JSON, when ingested, then a warning :
  // not a crash, not exit-2 (rule 1).
  {
    TempTree tree;
    tree.write("graph.json", "not json at all");
    const auto missing_result =
        conan::parse_graph_file(tree.root() / "no-such-file.json", conan::ParseOptions{});
    assert(missing_result.complete);
    assert(missing_result.value.empty());
    BOMWERK_TEST_CHECK(!missing_result.warnings.empty());

    const auto malformed_result =
        conan::parse_graph_file(tree.root() / "graph.json", conan::ParseOptions{});
    assert(malformed_result.complete);
    assert(malformed_result.value.empty());
    BOMWERK_TEST_CHECK(!malformed_result.warnings.empty());
  }

  // Given every file in the hostile corpus, when parsed under its canonical
  // manifest name, then the parser never crashes and never goes incomplete :
  // the ASan/UBSan guard for inputs nobody wrote in good faith.
  {
    const fs::path hostile_directory = fs::path(BOMWERK_FIXTURES_DIR) / "conan" / "hostile";
    for (const fs::directory_entry& entry : fs::directory_iterator(hostile_directory))
    {
      if (!entry.is_regular_file() || entry.path().filename() == "README.md")
      {
        continue;
      }
      const std::string fixture_name = entry.path().filename().string();
      std::string canonical_name;
      if (fixture_name.find(".conanfile.txt") != std::string::npos)
      {
        canonical_name = "conanfile.txt";
      }
      else if (fixture_name.find(".conanfile.py") != std::string::npos)
      {
        canonical_name = "conanfile.py";
      }
      else
      {
        canonical_name = "conan.lock";
      }
      TempTree tree;
      tree.write(canonical_name, read_file(entry.path()));
      const auto result = conan::parse(tree.root());
      BOMWERK_TEST_CHECK(result.complete);
    }
  }

  // Given the vendored real-world corpus (when the human has fetched it, per
  // fixtures/conan/SOURCES.md), when parsed, then components come out: the
  // "real conan project parses" criterion.
  {
    const fs::path real_conanfile =
        fs::path(BOMWERK_FIXTURES_DIR) / "conan" / "openssl-conanfile.py";
    if (fs::exists(real_conanfile))
    {
      TempTree tree;
      tree.write("conanfile.py", read_file(real_conanfile));
      const auto result = conan::parse(tree.root());
      BOMWERK_TEST_CHECK(result.complete);
      BOMWERK_TEST_CHECK(!result.value.empty());
    }
  }

  // Given more conanfile.txt files than a caller-tightened max_scanned_files
  // allows, when parsed, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  {
    TempTree tree;
    tree.write("a/conanfile.txt", "[requires]\naaa/1.0.0\n");
    tree.write("z/conanfile.txt", "[requires]\nzzz/1.0.0\n");
    conan::ParseOptions options;
    options.max_scanned_files = 1;
    const auto result = conan::parse(tree.root(), options);
    assert(result.complete);
    assert(!result.warnings.empty());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:conan/aaa@1.0.0");
  }

  std::puts("test_conan: OK");
  return 0;
}
