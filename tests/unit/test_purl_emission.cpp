// ctest unit test for the cross-producer purl-emission invariant.
//
// The per-producer tests each assert the exact purl their own shape yields.
// This test asserts the property that must hold across ALL of them at once,
// and that no single-producer test can: every component any C/C++ producer
// emits carries a non-empty purl of the expected type that `core::Purl` can
// parse back. bomwerk is the identity source of truth for every downstream
// consumer, so a component without a usable purl breaks those consumers'
// vulnerability matching, not just ours.
//
// It drives the real producers over synthesized trees rather than hand-built
// Component values: a hand-built value would prove only that this test can
// set a string, while a producer that grows a new branch which forgets a purl
// must fail here.
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#include "core/file_index.hpp"
#include "core/model.hpp"
#include "core/purl.hpp"
#include "core/result.hpp"
#include "heuristics/vendored_cpp.hpp"
#include "parsers/cpp/cmake_deps.hpp"
#include "parsers/cpp/conan.hpp"
#include "parsers/cpp/submodules.hpp"
#include "parsers/cpp/vcpkg.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Purl;
using bomwerk::test::TempTree;
namespace cmake_deps = bomwerk::parsers::cpp::cmake_deps;
namespace conan = bomwerk::parsers::cpp::conan;
namespace submodules = bomwerk::parsers::cpp::submodules;
namespace vcpkg = bomwerk::parsers::cpp::vcpkg;
namespace vendored_cpp = bomwerk::heuristics::vendored_cpp;

namespace
{

// A valid 40-hex (SHA-1) object id for synthesized HEADs and pinned tags.
const std::string kSha = "0123456789abcdef0123456789abcdef01234567";
const std::string kSha256 =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";  // 64-hex

/// The invariant itself, applied to one producer's whole output. `shape` names
/// the dependency shape under test so a failure says which producer regressed.
void check_purl_invariant(const std::vector<Component>& components, const std::string& shape,
                          const std::string& expected_purl_type_prefix)
{
  // A producer that found nothing would pass every assertion below vacuously,
  // which is exactly how this test would rot into a no-op.
  BOMWERK_TEST_CHECK(!components.empty());

  for (const Component& component : components)
  {
    // The ticket's headline requirement: zero components with an empty purl.
    if (component.purl.empty())
    {
      std::fprintf(stderr, "%s: component '%s' was emitted with an EMPTY purl\n", shape.c_str(),
                   component.name.c_str());
      std::abort();
    }

    // A purl we cannot parse back is a builder bug, not degraded input.
    const bomwerk::core::Result<Purl> parsed = Purl::parse(component.purl);
    if (!parsed.complete)
    {
      std::fprintf(stderr, "%s: component '%s' produced an unparsable purl '%s'\n", shape.c_str(),
                   component.name.c_str(), component.purl.c_str());
      std::abort();
    }

    // The type must be the one this shape is supposed to claim: a `pkg:npm`
    // sneaking out of a C/C++ producer is a silent identity error, not a
    // formatting one, so type is checked as well as parseability.
    if (component.purl.rfind(expected_purl_type_prefix, 0) != 0)
    {
      std::fprintf(stderr, "%s: component '%s' has purl '%s', expected type prefix '%s'\n",
                   shape.c_str(), component.name.c_str(), component.purl.c_str(),
                   expected_purl_type_prefix.c_str());
      std::abort();
    }

    // Canonicalization must be a fixed point: whatever the producer emitted is
    // already what the identity key will be, so `merge_all` grouping and the
    // UUIDv5 bom-refs derived from it cannot drift from the emitted string.
    BOMWERK_TEST_CHECK(parsed.value.canonical() == component.purl);
  }
}

/// Build the shared FileIndex the way `run_scan` does, for the producers that
/// take one.
bomwerk::core::FileIndex index_of(const TempTree& tree)
{
  const bomwerk::core::Result<bomwerk::core::FileIndex> file_index =
      bomwerk::core::build_file_index(tree.root(), {}, {});
  BOMWERK_TEST_CHECK(file_index.complete);
  return file_index.value;
}

}  // namespace

int main()
{
  // Given a git submodule pinned at a commit, when parsed, then the emitted
  // component carries a parseable forge purl.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/a\"]\n"
               "\tpath = libs/a\n"
               "\turl = https://github.com/acme/a.git\n");
    tree.write("libs/a/.git/HEAD", kSha + "\n");
    const auto result = submodules::parse(tree.root());
    check_purl_invariant(result.value, "git submodule", "pkg:github/");
  }

  // Given a submodule that declares no URL at all, when parsed, then it still
  // gets a purl: the shape most likely to produce an empty one.
  {
    TempTree tree;
    tree.write(".gitmodules", "[submodule \"libs/nourl\"]\n\tpath = libs/nourl\n");
    tree.write("libs/nourl/.git/HEAD", kSha + "\n");
    const auto result = submodules::parse(tree.root());
    check_purl_invariant(result.value, "git submodule without url", "pkg:generic/");
  }

  // Given FetchContent declarations covering all four cmake branches at once :
  // git repository, archive with a checksum, a legacy VCS keyword, and a bare
  // name with no source: when parsed, then every one of them yields a
  // parseable purl. The bare-name branch is the weakest identity bomwerk will
  // emit and must still never be empty.
  {
    TempTree tree;
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(gtest GIT_REPOSITORY "
               "https://github.com/google/googletest.git GIT_TAG " +
                   kSha +
                   ")\n"
                   "FetchContent_MakeAvailable(gtest)\n"
                   "FetchContent_Declare(zlib URL https://zlib.net/zlib-1.3.1.tar.gz URL_HASH "
                   "SHA256=" +
                   kSha256 +
                   ")\n"
                   "FetchContent_MakeAvailable(zlib)\n"
                   "ExternalProject_Add(oldlib SVN_REPOSITORY https://svn.example/oldlib "
                   "SVN_REVISION 1234)\n"
                   "FetchContent_Declare(bare VERSION 1.0.0)\n"
                   "FetchContent_MakeAvailable(bare)\n");
    const auto result = cmake_deps::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 4);
    check_purl_invariant(result.value, "cmake FetchContent/ExternalProject", "pkg:");
  }

  // Given a conanfile with a plain reference and one carrying user/channel,
  // when parsed, then both yield parseable `pkg:conan` purls.
  {
    TempTree tree;
    tree.write("conanfile.txt",
               "[requires]\n"
               "zlib/1.2.13\n"
               "openssl/3.2.0@corp/stable\n");
    const auto result = conan::parse(tree.root());
    check_purl_invariant(result.value, "conan", "pkg:conan/");
  }

  // Given a conan reference with a version RANGE rather than a resolved
  // version, when parsed, then it still carries a purl: an unresolved
  // constraint is a weaker identity, never an absent one.
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nfmt/[>=10.0 <11]\n");
    const auto result = conan::parse(tree.root());
    check_purl_invariant(result.value, "conan version range", "pkg:conan/");
  }

  // Given a vcpkg manifest with one pinned override and one unpinned
  // dependency, when parsed, then both carry purls: the unpinned one has no
  // version, which must not degrade into no identity.
  {
    TempTree tree;
    tree.write("vcpkg.json",
               "{\n"
               "  \"dependencies\": [ \"spdlog\", { \"name\": \"fmt\", \"version>=\": \"10.0.0\" } "
               "],\n"
               "  \"overrides\": [ { \"name\": \"spdlog\", \"version\": \"1.14.1\" } ]\n"
               "}\n");
    const auto result = vcpkg::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    check_purl_invariant(result.value, "vcpkg", "pkg:vcpkg/");
  }

  // Given vendored source in its three recognizable states: a resolvable
  // `.git` fork, a version-defining header, and a folder with no clue at all :
  // when parsed, then each yields a purl. The clueless folder is the heuristic's
  // weakest output and the likeliest place for an empty purl to appear.
  {
    TempTree tree;
    tree.write("third_party/mbedtls/.git/HEAD", kSha + "\n");
    tree.write("third_party/mbedtls/.git/config",
               "[remote \"origin\"]\n\turl = https://github.com/Mbed-TLS/mbedtls.git\n");
    tree.write("third_party/zlib/zlib.h", "#define ZLIB_VERSION \"1.2.11\"\n");
    tree.write("third_party/mystery/mystery.c", "int mystery(void) { return 0; }\n");
    const auto result = vendored_cpp::parse(index_of(tree), tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    check_purl_invariant(result.value, "vendored source", "pkg:");
  }

  // Given hostile-shaped input across the C/C++ producers: names and versions
  // carrying purl structural bytes: when parsed, then the emitted purls are
  // still parseable: percent-encoding must hold under bytes that would
  // otherwise forge a qualifier or a second path segment (Hard Rule 1).
  {
    TempTree tree;
    tree.write("conanfile.txt", "[requires]\nev?il&x=1/1.0?a=b\n");
    tree.write("vcpkg.json", "{ \"dependencies\": [ \"ev/il?x=1\" ] }\n");
    tree.write("CMakeLists.txt",
               "FetchContent_Declare(ev?il&name URL https://example.com/x.tar.gz)\n"
               "FetchContent_MakeAvailable(ev?il&name)\n");
    check_purl_invariant(conan::parse(tree.root()).value, "conan hostile", "pkg:conan/");
    check_purl_invariant(vcpkg::parse(tree.root()).value, "vcpkg hostile", "pkg:vcpkg/");
    check_purl_invariant(cmake_deps::parse(tree.root()).value, "cmake hostile", "pkg:generic/");
  }

  std::puts("test_purl_emission: OK");
  return 0;
}
