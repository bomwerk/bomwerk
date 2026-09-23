// ctest unit test for the git submodules producer
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>

#include "core/model.hpp"
#include "parsers/cpp/submodules.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::test::TempTree;
namespace submodules = bomwerk::parsers::cpp::submodules;

namespace
{

// A valid 40-hex (SHA-1) object id for synthesized HEADs.
const std::string kSha = "0123456789abcdef0123456789abcdef01234567";
// A second, distinct valid object id: used to prove a value never leaks from
// outside the scanned tree into the result (it must never appear anywhere).
const std::string kOutsideSha = "fedcba9876543210fedcba9876543210fedcba9";

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

}  // namespace

int main()
{
  // Given a tree with exactly three initialized submodules, when parsed, then
  // three components are detected.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/a\"]\n\tpath = libs/a\n\turl = https://github.com/acme/a.git\n"
               "[submodule \"libs/b\"]\n\tpath = libs/b\n\turl = https://github.com/acme/b.git\n"
               "[submodule \"libs/c\"]\n\tpath = libs/c\n\turl = https://github.com/acme/c.git\n");
    tree.write("libs/a/.git/HEAD", kSha + "\n");
    tree.write("libs/b/.git/HEAD", kSha + "\n");
    tree.write("libs/c/.git/HEAD", kSha + "\n");

    const auto result = submodules::parse(tree.root());
    assert(result.complete);
    assert(result.warnings.empty());
    assert(result.value.size() == 3);
    // Output is purl-sorted (rule 3), so 'a' comes first, resolved to High.
    assert(result.value[0].purl == "pkg:github/acme/a@" + kSha);
    assert(result.value[0].version == kSha);
    assert(result.value[0].root == fs::path("libs/a"));
    assert(highest_confidence(result.value[0]) == Confidence::High);
    // The origin's owner segment doubles as NTIA/CRA supplier evidence.
    assert(result.value[0].supplier == "acme");
  }

  // Given a submodule declared but never checked out, when parsed, then it is
  // still reported: versionless, Low confidence, with a warning naming the fix
  //: never fabricating a commit (plan §9).
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/u\"]\n\tpath = libs/u\n\turl = https://github.com/acme/u.git\n");
    const auto result = submodules::parse(tree.root());
    assert(result.complete);
    assert(result.value.size() == 1);
    assert(result.value[0].version.empty());
    assert(result.value[0].purl == "pkg:github/acme/u");  // no @commit
    assert(highest_confidence(result.value[0]) == Confidence::Low);
    assert(!result.warnings.empty());
  }

  // Given a relative submodule URL and a superproject origin, when parsed, then
  // the URL resolves against origin (the esp-idf case) into a github purl.
  {
    TempTree tree;
    tree.write(".git/config",
               "[remote \"origin\"]\n\turl = https://github.com/espressif/esp-idf.git\n");
    tree.write(
        ".gitmodules",
        "[submodule \"c/micro-ecc\"]\n\tpath = c/micro-ecc\n\turl = ../../kmackay/micro-ecc.git\n");
    tree.write("c/micro-ecc/.git/HEAD", kSha + "\n");

    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:github/kmackay/micro-ecc@" + kSha);
    // Resolved through the superproject origin, the owner is still real
    // supplier evidence even though the .gitmodules URL itself was relative.
    assert(result.value[0].supplier == "kmackay");
  }

  // Given a HEAD that points at a loose ref, when parsed, then the ref is
  // followed to its commit.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/r\"]\n\tpath = libs/r\n\turl = https://github.com/acme/r.git\n");
    tree.write("libs/r/.git/HEAD", "ref: refs/heads/main\n");
    tree.write("libs/r/.git/refs/heads/main", kSha + "\n");
    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].version == kSha);
    assert(highest_confidence(result.value[0]) == Confidence::High);
  }

  // Given a HEAD ref that lives only in packed-refs, when parsed, then the
  // packed-refs fallback resolves the commit.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/p\"]\n\tpath = libs/p\n\turl = https://github.com/acme/p.git\n");
    tree.write("libs/p/.git/HEAD", "ref: refs/heads/main\n");
    tree.write("libs/p/.git/packed-refs",
               "# pack-refs with: peeled fully-peeled sorted\n" + kSha + " refs/heads/main\n");
    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].version == kSha);
  }

  // Given a submodule whose path escapes the repo, when parsed, then it is
  // rejected with a warning and never touched on disk (CVE-2018-11235 shape).
  {
    TempTree tree;
    tree.write(
        ".gitmodules",
        "[submodule \"evil\"]\n\tpath = ../../evil\n\turl = https://github.com/acme/evil.git\n");
    const auto result = submodules::parse(tree.root());
    assert(result.value.empty());
    assert(!result.warnings.empty());
  }

  // Given a submodule's `.git` file whose `gitdir:` pointer escapes the whole
  // scanned tree (not just its own directory: that's legitimate, real git
  // does that), when parsed, then the commit is never read from outside the
  // scanned root: the submodule is reported unresolved, and the outside
  // file's content never leaks into the result (CVE-2018-11235 shape, applied
  // to `.git` rather than `.gitmodules` path=).
  {
    TempTree outside;
    outside.write("HEAD", kOutsideSha + "\n");

    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/x\"]\n\tpath = libs/x\n\turl = https://github.com/acme/x.git\n");
    const fs::path work_dir = tree.root() / "libs/x";
    fs::create_directories(work_dir);
    const std::string escape_target = fs::relative(outside.root(), work_dir).string();
    tree.write("libs/x/.git", "gitdir: " + escape_target + "\n");

    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].version.empty());         // never resolved from outside root
    assert(result.value[0].version != kOutsideSha);  // the outside commit never leaks
  }

  // Given a submodule's checked-out HEAD containing a `ref:` line that itself
  // attempts path traversal, when parsed, then the ref is rejected before ever
  // being joined onto a path: no read outside the submodule's own git dir.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/y\"]\n\tpath = libs/y\n\turl = https://github.com/acme/y.git\n");
    tree.write("libs/y/.git/HEAD", "ref: ../../../../../etc/passwd\n");
    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].version.empty());
  }

  // Given a submodule that declares a `path` but no `url` key, when parsed,
  // then it is still reported: as a generic component named from its path,
  // with a warning: never silently dropped.
  {
    TempTree tree;
    tree.write(".gitmodules", "[submodule \"libs/nourl\"]\n\tpath = libs/nourl\n");
    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 1);
    assert(result.value[0].purl == "pkg:generic/nourl");
    assert(result.value[0].name == "nourl");
    assert(!result.warnings.empty());
    // No url, no remote, no owner to attribute: supplier stays honest.
    assert(result.value[0].supplier.empty());
  }

  // Given checked-out HEADs written in upper-case hex: git writes lower-case,
  // but a hand-edited or synthesized checkout may not: when parsed, then both
  // the forge purl and the no-URL generic fallback carry the lower-cased object
  // id, so one commit is one identity. The generic path is the producer's
  // only purl not built by core::build_git_purl, hence checked here too.
  {
    const std::string upper_sha = "0123456789ABCDEF0123456789ABCDEF01234567";
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/forge\"]\n"
               "\tpath = libs/forge\n"
               "\turl = https://github.com/acme/forge.git\n"
               "[submodule \"libs/nourl\"]\n"
               "\tpath = libs/nourl\n");
    tree.write("libs/forge/.git/HEAD", upper_sha + "\n");
    tree.write("libs/nourl/.git/HEAD", upper_sha + "\n");
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    const Component* forge = find_by_purl_prefix(result.value, "pkg:github/acme/forge@");
    const Component* nourl = find_by_purl_prefix(result.value, "pkg:generic/nourl@");
    BOMWERK_TEST_CHECK(forge != nullptr);
    BOMWERK_TEST_CHECK(nourl != nullptr);
    BOMWERK_TEST_CHECK(forge->purl == "pkg:github/acme/forge@" + kSha);
    BOMWERK_TEST_CHECK(nourl->purl == "pkg:generic/nourl@" + kSha);
  }

  // Given no .gitmodules at all, when parsed, then the result is simply empty :
  // not a warning, not an error.
  {
    TempTree tree;
    const auto result = submodules::parse(tree.root());
    assert(result.complete);
    assert(result.value.empty());
    assert(result.warnings.empty());
  }

  // Given a real vendored .gitmodules (pico-sdk), when parsed with no checkouts,
  // then all five submodules are reported (Low, uninitialized) with github
  // purls built from their URLs.
  {
    TempTree tree;
    tree.write(".gitmodules",
               read_file(fs::path(BOMWERK_FIXTURES_DIR) / "gitmodules" / "pico-sdk.gitmodules"));
    const auto result = submodules::parse(tree.root());
    assert(result.value.size() == 5);
    BOMWERK_TEST_CHECK(find_by_purl_prefix(result.value, "pkg:github/lwip-tcpip/lwip") != nullptr);
  }

  // Given every hostile fixture, when parsed, then the producer never crashes
  // and never returns the exit-2 (incomplete) state for a merely-malformed
  // file: it warns and continues (rule 1). Under ASan/UBSan this is the guard
  // against out-of-bounds reads on crafted input.
  {
    const fs::path hostile_dir = fs::path(BOMWERK_FIXTURES_DIR) / "gitmodules" / "hostile";
    for (const auto& entry : fs::directory_iterator(hostile_dir))
    {
      if (!entry.is_regular_file() || entry.path().extension() != ".gitmodules")
      {
        continue;
      }
      TempTree tree;
      tree.write(".gitmodules", read_file(entry.path()));
      const auto result = submodules::parse(tree.root());
      assert(result.complete);  // malformed => warnings, never exit-2
    }
  }

  std::puts("test_submodules: OK");
  return 0;
}
