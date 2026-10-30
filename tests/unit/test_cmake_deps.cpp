// ctest unit test for the CMake FetchContent/CPM producer.
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/warning.hpp"
#include "parsers/cpp/cmake_deps.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::build_file_index;
using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::test::TempTree;
namespace cmake_deps = bomwerk::parsers::cpp::cmake_deps;

namespace
{

const std::string kSha = "0123456789abcdef0123456789abcdef01234567";  // 40-hex SHA-1
const std::string kSha256 =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";  // 64-hex

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

bool purl_contains(const Component& component, const std::string& needle)
{
  return component.purl.find(needle) != std::string::npos;
}

/// Upper-case spelling of a hex digest, for the case-normalization cases.
/// Written locally rather than via a core helper: a test that reused production
/// code to build its own expectation would pass even if that code were wrong.
std::string to_upper_hex(const std::string& hex_digest)
{
  std::string uppercased;
  uppercased.reserve(hex_digest.size());
  for (const char character : hex_digest)
  {
    if (character >= 'a' && character <= 'f')
    {
      uppercased.push_back(static_cast<char>(character - 'a' + 'A'));
    }
    else
    {
      uppercased.push_back(character);
    }
  }
  return uppercased;
}

}  // namespace

int main()
{
  // Given a FetchContent git declaration pinned to a commit SHA and made
  // available, when parsed, then one High-confidence github component results.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(googletest\n"
               "  GIT_REPOSITORY https://github.com/google/googletest.git\n"
               "  GIT_TAG " +
                   kSha +
                   ")\n"
                   "FetchContent_MakeAvailable(googletest)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/google/googletest@" + kSha);
    assert(result.value[0].version == kSha);
    assert(highest_confidence(result.value[0]) == Confidence::High);
    // GIT_REPOSITORY's owner segment doubles as NTIA/CRA supplier evidence.
    assert(result.value[0].supplier == "google");
  }

  // Given a FetchContent_Declare using CMake's first-seen capitalization
  // ("GoogleTest") and a FetchContent_MakeAvailable call naming the same
  // dependency in a different case ("googletest"), when parsed, then the two
  // calls are still matched as the same dependency: FetchContent treats the
  // name argument case-insensitively (cmake.org/cmake/help/latest/module/
  // FetchContent.html): so declare_only is never set and the pinned SHA still
  // earns High confidence rather than being knocked down a tier.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(GoogleTest\n"
               "  GIT_REPOSITORY https://github.com/google/googletest.git\n"
               "  GIT_TAG " +
                   kSha +
                   ")\n"
                   "FetchContent_MakeAvailable(googletest)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(highest_confidence(result.value[0]) == Confidence::High);
    assert(result.value[0].evidence[0].detail.find("declared, not confirmed built") ==
           std::string::npos);
  }

  // Given a git declaration pinned to a mutable branch, when parsed, then it is
  // Medium confidence (resolvable but not immutable).
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(dep GIT_REPOSITORY https://github.com/acme/dep.git "
               "GIT_TAG main)\nFetchContent_MakeAvailable(dep)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/acme/dep@main");
    assert(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given a declaration that is never made available, when parsed, then its
  // confidence is knocked down a level and the evidence records why.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(orphan GIT_REPOSITORY https://github.com/acme/orphan.git "
               "GIT_TAG main)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(highest_confidence(result.value[0]) == Confidence::Low);  // Medium -> Low
    assert(result.value[0].evidence[0].detail.find("declared, not confirmed built") !=
           std::string::npos);
  }

  // Given a CPM keyword form with GITHUB_REPOSITORY + VERSION, when parsed, then
  // a github purl is built from the owner/repo shorthand and the version.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "CPMAddPackage(NAME fmt GITHUB_REPOSITORY fmtlib/fmt VERSION 10.2.1)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/fmtlib/fmt@10.2.1");
    assert(highest_confidence(result.value[0]) == Confidence::Medium);
  }

  // Given the CPM single-arg shorthand with a '#ref', when parsed, then the host
  // prefix maps to github and the ref becomes the version.
  {
    TempTree tree;
    tree.write("CMakeLists.txt", "CPMAddPackage(\"gh:fmtlib/fmt#10.2.1\")\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/fmtlib/fmt@10.2.1");
  }

  // Given a GitLab subgroup shorthand, when parsed, then subgroups are preserved
  // in the gitlab namespace.
  {
    TempTree tree;
    tree.write("CMakeLists.txt", "CPMAddPackage(\"gl:group/sub/proj@1.0.0\")\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:gitlab/group/sub/proj@1.0.0");
  }

  // Given a raw GIT_REPOSITORY on an unmapped host, when parsed, then it falls
  // back to a generic purl carrying the vcs_url.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(x GIT_REPOSITORY https://example.com/a/y.git GIT_TAG v1.0)\n"
               "FetchContent_MakeAvailable(x)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl.rfind("pkg:generic/y@v1.0?vcs_url=", 0) == 0);
  }

  // Given a GIT_REPOSITORY that is entirely an unresolved variable (HDF5's
  // HDFLibMacros.cmake pattern), when parsed, then the repository and tag are
  // left out of the identity: the generic purl carries only the declared name
  // (no `${...}`, no version), a warning names file and line, and confidence
  // is Low.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(HDF5_ZLIB GIT_REPOSITORY ${ZLIB_URL} GIT_TAG ${ZLIB_BRANCH})\n"
               "FetchContent_MakeAvailable(HDF5_ZLIB)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "HDF5_ZLIB");
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/HDF5_ZLIB");
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].code ==
                       bomwerk::core::WarningCode::kUnresolvedVariableOrInterpolation);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("CMakeLists.txt:1") != std::string::npos);
  }

  // Given a FetchContent archive (URL + URL_HASH), when parsed, then a generic
  // purl carries checksum + download_url, sha256 is populated, version is
  // recovered from the filename, and confidence is High (hash pins the artifact).
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(zlib\n"
               "  URL https://zlib.net/zlib-1.3.1.tar.gz\n"
               "  URL_HASH SHA256=" +
                   kSha256 +
                   ")\n"
                   "FetchContent_MakeAvailable(zlib)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    const Component& component = result.value[0];
    BOMWERK_TEST_CHECK(component.version == "1.3.1");
    BOMWERK_TEST_CHECK(component.sha256 == kSha256);
    BOMWERK_TEST_CHECK(purl_contains(component, "pkg:generic/zlib@1.3.1"));
    BOMWERK_TEST_CHECK(purl_contains(component, "checksum=sha256:" + kSha256));
    BOMWERK_TEST_CHECK(purl_contains(component, "download_url=https%3A%2F%2Fzlib.net"));
    BOMWERK_TEST_CHECK(highest_confidence(component) == Confidence::High);
    // A URL archive has no reliable owner to parse out: supplier stays
    // empty rather than misreading the download URL's path as one.
    BOMWERK_TEST_CHECK(component.supplier.empty());
  }

  // Given the same archive declared twice, once with an upper-case URL_HASH
  // digest and once lower-case, when parsed, then the two collapse into ONE
  // component: purl-spec defines the checksum qualifier as lower-case hex, and
  // one artifact must be one identity (rule 3) regardless of how a manifest
  // happens to capitalize it.
  {
    const std::string upper_sha256 = to_upper_hex(kSha256);
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(zlib\n"
               "  URL https://zlib.net/zlib-1.3.1.tar.gz\n"
               "  URL_HASH SHA256=" +
                   upper_sha256 +
                   ")\n"
                   "FetchContent_MakeAvailable(zlib)\n"
                   "FetchContent_Declare(zlib\n"
                   "  URL https://zlib.net/zlib-1.3.1.tar.gz\n"
                   "  URL_HASH SHA256=" +
                   kSha256 +
                   ")\n"
                   "FetchContent_MakeAvailable(zlib)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component& component = result.value[0];
    BOMWERK_TEST_CHECK(component.sha256 == kSha256);
    BOMWERK_TEST_CHECK(purl_contains(component, "checksum=sha256:" + kSha256));
    BOMWERK_TEST_CHECK(!purl_contains(component, upper_sha256));
  }

  // Given the same commit pinned with an upper-case GIT_TAG in one declaration
  // and lower-case in another, when parsed, then they are one component and the
  // emitted version field agrees with the purl's version.
  {
    const std::string upper_commit = to_upper_hex(kSha);
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(gtest GIT_REPOSITORY "
               "https://github.com/google/googletest.git GIT_TAG " +
                   upper_commit +
                   ")\n"
                   "FetchContent_MakeAvailable(gtest)\n"
                   "FetchContent_Declare(gtest GIT_REPOSITORY "
                   "https://github.com/google/googletest.git GIT_TAG " +
                   kSha +
                   ")\n"
                   "FetchContent_MakeAvailable(gtest)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    const Component& component = result.value[0];
    BOMWERK_TEST_CHECK(component.purl == "pkg:github/google/googletest@" + kSha);
    BOMWERK_TEST_CHECK(component.version == kSha);
  }

  // Given a GIT_TAG that is a tag rather than an object id, when parsed, then
  // its case is preserved: a tag is operator text with no canonical spelling,
  // so normalizing it would invent an identity the manifest never declared.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(dep GIT_REPOSITORY https://github.com/acme/dep.git "
               "GIT_TAG v2.0-RC1)\n"
               "FetchContent_MakeAvailable(dep)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/dep@v2.0-RC1");
    BOMWERK_TEST_CHECK(result.value[0].version == "v2.0-RC1");
  }

  // Given archive URLs using the short compound extensions CMake's own
  // extraction step accepts (.7z, .tzst: Modules/ExternalProject.cmake), when
  // parsed, then the version is still recovered from the filename.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(seven URL https://example.com/seven-2.4.7z)\n"
               "FetchContent_MakeAvailable(seven)\n"
               "FetchContent_Declare(zstd URL https://example.com/zstd-1.5.6.tzst)\n"
               "FetchContent_MakeAvailable(zstd)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 2);
    assert(purl_contains(result.value[0], "pkg:generic/seven@2.4"));
    assert(purl_contains(result.value[1], "pkg:generic/zstd@1.5.6"));
  }

  // Given a URL_HASH value that is not valid hex (e.g. crafted to look like it
  // carries a second '&'-separated qualifier), when parsed, then the checksum
  // is rejected rather than injected raw into the purl query string or into
  // Component::sha256: the purl carries only the legitimate download_url, and
  // a warning names the problem.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(zlib\n"
               "  URL https://zlib.net/zlib-1.3.1.tar.gz\n"
               "  URL_HASH SHA256=deadbeef&download_url=https://evil.example/payload.tgz)\n"
               "FetchContent_MakeAvailable(zlib)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    const Component& component = result.value[0];
    BOMWERK_TEST_CHECK(component.sha256.empty());
    BOMWERK_TEST_CHECK(!purl_contains(component, "evil.example"));
    BOMWERK_TEST_CHECK(component.purl.find("checksum=") == std::string::npos);
    BOMWERK_TEST_CHECK(purl_contains(component, "download_url=https%3A%2F%2Fzlib.net"));
    BOMWERK_TEST_CHECK(!result.warnings.empty());
  }

  // Given a FetchContent_MakeAvailable call that is itself malformed (an
  // unterminated quote truncates it), when parsed, then the dependency it
  // names is NOT trusted as "confirmed built" from that malformed call: its
  // declare_only confidence penalty still applies.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(evil GIT_REPOSITORY https://github.com/acme/evil.git "
               "GIT_TAG main)\n"
               "FetchContent_MakeAvailable(evil \"unterminated\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    // Medium (resolvable git tag) lowered one tier by declare_only, since the
    // malformed MakeAvailable call must not count as confirming it was built.
    assert(highest_confidence(result.value[0]) == Confidence::Low);
    bool malformed_make_available_warned = false;
    for (const bomwerk::core::Warning& warning : result.warnings)
    {
      if (warning.message.find("malformed") != std::string::npos &&
          warning.message.find("MakeAvailable") != std::string::npos)
      {
        malformed_make_available_warned = true;
      }
    }
    BOMWERK_TEST_CHECK(malformed_make_available_warned);
  }

  // Given an unresolved ${VAR} tag, when parsed, then the component is kept
  // WITHOUT a version (never with the literal `${DEP_VERSION}`), at Low
  // confidence, with a warning, and the run stays complete: never exit-2
  // (Hard Rule 1).
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(dep GIT_REPOSITORY https://github.com/acme/dep.git "
               "GIT_TAG ${DEP_VERSION})\nFetchContent_MakeAvailable(dep)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/dep");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
  }

  // Given a variable set in ANOTHER CMake file (protobuf's dependencies.cmake
  // pattern), when parsed, then the declaration expands it: the real version
  // reaches the purl and nothing warns.
  {
    TempTree tree;
    tree.write("cmake/dependencies.cmake", "set(abseil-cpp-version \"20250512.1\")\n");
    tree.write("cmake/abseil-cpp.cmake",
               "FetchContent_Declare(abseil GIT_REPOSITORY https://github.com/abseil/abseil-cpp\n"
               "  GIT_TAG \"${abseil-cpp-version}\")\nFetchContent_MakeAvailable(abseil)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/abseil/abseil-cpp@20250512.1");
    BOMWERK_TEST_CHECK(result.value[0].version == "20250512.1");
  }

  // Given a variable that is set twice to different values, and a `set` with a
  // list value, when a declaration uses each, then neither expands: both
  // versions are left out, so a wrong value never reaches a purl.
  {
    TempTree tree;
    tree.write(
        "CMakeLists.txt",
        "set(TWICE v1)\nif(OLD)\n  set(TWICE v2)\nendif()\nset(PAIR a b)\n"
        "FetchContent_Declare(one GIT_REPOSITORY https://github.com/acme/one GIT_TAG ${TWICE})\n"
        "FetchContent_Declare(two GIT_REPOSITORY https://github.com/acme/two GIT_TAG ${PAIR})\n"
        "FetchContent_MakeAvailable(one two)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/one");
    BOMWERK_TEST_CHECK(result.value[1].purl == "pkg:github/acme/two");
    BOMWERK_TEST_CHECK(result.warnings.size() == 2);
  }

  // Given a variable that is a function parameter (protobuf's
  // add_examples_build(NAME)) and an unrelated set(NAME ...) elsewhere, when a
  // declaration inside the function names itself `${NAME}`, then it is
  // dropped with a warning naming file and line: the parameter is ambiguous,
  // never the unrelated value.
  {
    TempTree tree;
    tree.write("cmake/examples.cmake",
               "function(add_examples_build NAME)\n"
               "  ExternalProject_Add(${NAME} URL https://example.com/x-1.0.tar.gz)\n"
               "endfunction()\n");
    tree.write("CMakeLists.txt", "set(NAME unrelated)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].code ==
                       bomwerk::core::WarningCode::kUnresolvedVariableOrInterpolation);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("examples.cmake:2") != std::string::npos);
  }

  // Given a name that is a variable but a literal GIT_REPOSITORY, when parsed,
  // then the dependency is named after the repository instead of being dropped.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(${DEP_NAME} GIT_REPOSITORY https://github.com/acme/widget.git "
               "GIT_TAG v3.0)\nFetchContent_MakeAvailable(${DEP_NAME})\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].name == "widget");
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/widget@v3.0");
  }

  // Given a literal name whose URL is an unresolved variable (neovim's
  // ExternalProject_Add(treesitter_lua_wasm URL ${...})), when parsed, then
  // the component keeps its name without the URL, at Low confidence, and the
  // only warning is the unresolved-variable one, not "no repository or URL".
  {
    TempTree tree;
    tree.write("CMakeLists.txt", "ExternalProject_Add(treesitter_lua_wasm URL ${LUA_WASM_URL})\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/treesitter_lua_wasm");
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].code ==
                       bomwerk::core::WarningCode::kUnresolvedVariableOrInterpolation);
  }

  // Given two variables that reference each other, when a declaration uses
  // one, then expansion gives up (no hang) and the version is left out.
  {
    TempTree tree;
    tree.write(
        "CMakeLists.txt",
        "set(FIRST ${SECOND})\nset(SECOND ${FIRST})\n"
        "FetchContent_Declare(loop GIT_REPOSITORY https://github.com/acme/loop GIT_TAG ${FIRST})\n"
        "FetchContent_MakeAvailable(loop)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/loop");
  }

  // Given every hostile CMake fixture, when parsed, then no purl carries a
  // variable reference in any of its spellings.
  {
    const fs::path hostile_directory = fs::path(BOMWERK_FIXTURES_DIR) / "cmake" / "hostile";
    const auto result = cmake_deps::parse(hostile_directory);
    BOMWERK_TEST_CHECK(result.complete);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.purl.find("${") == std::string::npos);
      BOMWERK_TEST_CHECK(component.purl.find("%24%7B") == std::string::npos);
      BOMWERK_TEST_CHECK(component.purl.find("$<") == std::string::npos);
      BOMWERK_TEST_CHECK(component.purl.find("%24%3C") == std::string::npos);
    }
  }

  // Given the same dependency declared in two files, when parsed, then it is
  // deduplicated to one component (merge_all), proving *.cmake files are walked.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(dep GIT_REPOSITORY https://github.com/acme/dep.git "
               "GIT_TAG v2.0)\nFetchContent_MakeAvailable(dep)\n");
    tree.write("cmake/extra.cmake",
               "FetchContent_Declare(dep GIT_REPOSITORY https://github.com/acme/dep.git "
               "GIT_TAG v2.0)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/acme/dep@v2.0");
    BOMWERK_TEST_CHECK(find_by_purl_prefix(result.value, "pkg:github/acme/dep") != nullptr);
  }

  // Given no CMake files at all, when parsed, then the result is empty: not a
  // warning, not an error.
  {
    TempTree tree;
    tree.write("README.md", "no cmake here\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.empty());
    assert(result.warnings.empty());
  }

  // Given an ExternalProject SVN dependency pinned to a numeric revision, when
  // parsed, then it is reported as a generic component carrying an svn+ vcs_url
  // qualifier: High confidence, because an SVN revision number is immutable.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "ExternalProject_Add(legacy_lib\n"
               "  SVN_REPOSITORY https://svn.example.com/legacy/trunk\n"
               "  SVN_REVISION -r1234)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(result.value[0].version == "1234");
    assert(result.value[0].purl.rfind("pkg:generic/legacy_lib@1234?vcs_url=svn%2B", 0) == 0);
    assert(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given a CPM shorthand with a prefix CPM does not define (e.g. a Perforce
  // depot), when parsed, then the dependency is still reported as a generic
  // named component and a warning names the unrecognized prefix: recognized
  // and informed, never silently guessed or dropped.
  {
    TempTree tree;
    tree.write("CMakeLists.txt", "CPMAddPackage(\"p4:depot/lib@2.0\")\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    bool prefix_was_reported = false;
    for (const bomwerk::core::Warning& warning : result.warnings)
    {
      if (warning.message.find("p4") != std::string::npos)
      {
        prefix_was_reported = true;
      }
    }
    BOMWERK_TEST_CHECK(prefix_was_reported);
  }

  // Given more CMake files than a caller-tightened ParseLimits allows, when
  // parsed with that limit, then a warning reports the cap, the run stays
  // complete, and the scanned subset is the path-sorted (deterministic) one.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "CPMAddPackage(NAME aaa GITHUB_REPOSITORY acme/aaa VERSION 1.0)\n");
    tree.write("cmake/extra.cmake",
               "CPMAddPackage(NAME zzz GITHUB_REPOSITORY acme/zzz VERSION 2.0)\n");
    cmake_deps::ParseLimits limits;
    limits.max_scanned_files = 1;
    const auto result = cmake_deps::parse(tree.root(), limits);
    assert(result.complete);
    assert(!result.warnings.empty());
    assert(result.value.size() == 1);
    // "CMakeLists.txt" sorts before "cmake/…", so aaa is the deterministic pick.
    assert(result.value[0].purl == "pkg:github/acme/aaa@1.0");
  }

  // Given a malformed declaration (an unterminated quote) that leaks a stray
  // ')' into the repository value, when parsed, then the component is still
  // emitted but its purl is well-formed: the ')' is percent-encoded, never
  // raw, so it is safe for the downstream SBOM writer and vuln matcher: and it
  // is Low confidence because the scanner flagged the command not-well-formed.
  {
    TempTree tree;
    tree.write("CMakeLists.txt", "CPMAddPackage(NAME broken GITHUB_REPOSITORY \"acme/broken)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    const Component& component = result.value[0];
    BOMWERK_TEST_CHECK(component.purl.find(')') == std::string::npos);  // no raw structural byte
    BOMWERK_TEST_CHECK(purl_contains(component, "pkg:github/acme/broken%29"));
    BOMWERK_TEST_CHECK(highest_confidence(component) == Confidence::Low);
  }

  // Given a generator expression `$<...>` as a version, when parsed, then it is
  // treated as unresolvable (Low confidence) and the emitted purl percent-
  // encodes the '<' '>' ':' so it stays well-formed.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(gx GIT_REPOSITORY https://github.com/acme/gx.git "
               "GIT_TAG $<CONFIG:Debug>)\nFetchContent_MakeAvailable(gx)\n");
    const auto result = cmake_deps::parse(tree.root());
    assert(result.value.size() == 1);
    const Component& component = result.value[0];
    BOMWERK_TEST_CHECK(component.purl.find('<') == std::string::npos);
    BOMWERK_TEST_CHECK(component.purl.find('>') == std::string::npos);
    BOMWERK_TEST_CHECK(highest_confidence(component) == Confidence::Low);
  }

  // Given a subtree named in ParseLimits.excluded_subtrees (e.g. a git
  // submodule's working tree, reported elsewhere as one component), when
  // parsed, then its CMake files are never walked at all: not double-counted,
  // not even charged against max_scanned_files. Regression for a live scan
  // where the vcpkg submodule's ~4000 port recipes were scanned as if they
  // belonged to the project.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "CPMAddPackage(NAME real GITHUB_REPOSITORY acme/real VERSION 1.0)\n");
    tree.write("vendored/CMakeLists.txt",
               "CPMAddPackage(NAME vendored GITHUB_REPOSITORY acme/vendored VERSION 9.0)\n");
    cmake_deps::ParseLimits limits;
    limits.excluded_subtrees.insert(fs::path("vendored"));
    const auto result = cmake_deps::parse(tree.root(), limits);
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/acme/real@1.0");
  }

  // Given every hostile fixture as a lone CMakeLists.txt, when parsed, then the
  // producer never crashes and never returns exit-2 (ASan/UBSan guard, rule 1).
  {
    const fs::path hostile_dir = fs::path(BOMWERK_FIXTURES_DIR) / "cmake" / "hostile";
    if (fs::exists(hostile_dir))
    {
      for (const auto& entry : fs::directory_iterator(hostile_dir))
      {
        if (!entry.is_regular_file() || entry.path().extension() != ".cmake")
        {
          continue;
        }
        TempTree tree;
        tree.write("CMakeLists.txt", read_file(entry.path()));
        const auto result = cmake_deps::parse(tree.root());
        assert(result.complete);
      }
    }
  }

  // Given the whole fixtures/cmake tree (real vendored samples once added, plus
  // the hostile corpus), when parsed, then the run stays complete.
  {
    const fs::path cmake_fixtures = fs::path(BOMWERK_FIXTURES_DIR) / "cmake";
    if (fs::exists(cmake_fixtures))
    {
      const auto result = cmake_deps::parse(cmake_fixtures);
      assert(result.complete);
    }
  }

  // Given a pre-built FileIndex (as run_scan now builds once and hands to
  // every producer), when parsed via the FileIndex overload, then the result
  // matches what the self-walking overload would have found: the shared
  // primitive and the producer-local walk agree.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(googletest\n"
               "  GIT_REPOSITORY https://github.com/google/googletest.git\n"
               "  GIT_TAG        " +
                   kSha +
                   ")\n"
                   "FetchContent_MakeAvailable(googletest)\n");
    const auto file_index = build_file_index(tree.root(), {}, {});
    const auto result = cmake_deps::parse(file_index.value, tree.root(), cmake_deps::ParseLimits{});
    assert(result.value.size() == 1);
    assert(purl_contains(result.value[0], "pkg:github/google/googletest@" + kSha));
  }

  // Given ParseLimits' default max_file_bytes, when checked, then it is sized
  // for real large CMakeLists.txt files (8 MiB), not the 1 MiB JSON-manifest
  // default it used to inherit: grpc's root CMakeLists.txt (2.4 MiB) fits
  // comfortably under it (Issue: CMake parser's 1 MiB cap truncates
  // real-world large CMakeLists.txt).
  {
    BOMWERK_TEST_CHECK(cmake_deps::ParseLimits{}.max_file_bytes == 8u * 1024u * 1024u);
  }

  // Given a CMakeLists.txt larger than max_file_bytes, when parsed, then the
  // read is truncated mid-command and only ONE warning is reported for it :
  // the byte-cap warning: not also a redundant "unterminated command"
  // warning from the scanner hitting the same truncated EOF.
  {
    TempTree tree;
    std::string content =
        "FetchContent_Declare(googletest\n"
        "  GIT_REPOSITORY https://github.com/google/googletest.git\n"
        "  GIT_TAG        " +
        kSha + ")\n";
    content.append(4096, ' ');
    content +=
        "FetchContent_Declare(evil GIT_REPOSITORY https://github.com/acme/evil.git "
        "GIT_TAG main)\n";
    tree.write("CMakeLists.txt", content);

    cmake_deps::ParseLimits limits;
    limits.max_file_bytes = content.size() - 10;
    const auto result = cmake_deps::parse(tree.root(), limits);
    assert(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("byte cap") != std::string::npos);
    for (const bomwerk::core::Warning& warning : result.warnings)
    {
      BOMWERK_TEST_CHECK(warning.message.find("unterminated command") == std::string::npos);
    }
  }

  std::puts("test_cmake_deps: OK");
  return 0;
}
