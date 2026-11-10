// ctest unit test for the git submodules producer
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <sstream>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning_code.hpp"
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

std::size_t count_code(const bomwerk::core::Result<std::vector<Component>>& result,
                       bomwerk::core::WarningCode code)
{
  std::size_t count = 0;
  for (const bomwerk::core::Warning& warning : result.warnings)
  {
    if (warning.code == code)
    {
      ++count;
    }
  }
  return count;
}

bool has_evidence(const Component& component, const std::string& detail)
{
  for (const auto& evidence : component.evidence)
  {
    if (evidence.detail == detail)
    {
      return true;
    }
  }
  return false;
}

/// A real superproject index (fixtures/gitindex/SOURCES.md) pinning libs/zlib,
/// libs/mbedtls and third_party/openssl.
std::string gitindex_fixture(const std::string& name)
{
  return read_file(fs::path(BOMWERK_FIXTURES_DIR) / "gitindex" / name);
}

const std::string kIndexZlibCommit = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c";
const std::string kZlibGitmodules =
    "[submodule \"libs/zlib\"]\n\tpath = libs/zlib\n\turl = https://github.com/madler/zlib.git\n";

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
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    // Output is purl-sorted (rule 3), so 'a' comes first, resolved to High.
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/a@" + kSha);
    BOMWERK_TEST_CHECK(result.value[0].version == kSha);
    BOMWERK_TEST_CHECK(result.value[0].root == fs::path("libs/a"));
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    // The origin's owner segment doubles as NTIA/CRA supplier evidence.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "acme");
  }

  // Given a submodule declared but never checked out, when parsed, then it is
  // still reported: versionless, Low confidence, with a warning naming the fix
  //: never fabricating a commit (plan §9).
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/u\"]\n\tpath = libs/u\n\turl = https://github.com/acme/u.git\n");
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/acme/u");  // no @commit
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::Low);
    BOMWERK_TEST_CHECK(!result.warnings.empty());
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
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/kmackay/micro-ecc@" + kSha);
    // Resolved through the superproject origin, the owner is still real
    // supplier evidence even though the .gitmodules URL itself was relative.
    BOMWERK_TEST_CHECK(result.value[0].supplier == "kmackay");
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
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == kSha);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
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
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == kSha);
  }

  // Given a submodule whose path escapes the repo, when parsed, then it is
  // rejected with a warning and never touched on disk (CVE-2018-11235 shape).
  {
    TempTree tree;
    tree.write(
        ".gitmodules",
        "[submodule \"evil\"]\n\tpath = ../../evil\n\turl = https://github.com/acme/evil.git\n");
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(!result.warnings.empty());
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
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());         // never resolved from outside root
    BOMWERK_TEST_CHECK(result.value[0].version != kOutsideSha);  // the outside commit never leaks
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
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
  }

  // Given a submodule that declares a `path` but no `url` key, when parsed,
  // then it is still reported: as a generic component named from its path,
  // with a warning: never silently dropped.
  {
    TempTree tree;
    tree.write(".gitmodules", "[submodule \"libs/nourl\"]\n\tpath = libs/nourl\n");
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:generic/nourl");
    BOMWERK_TEST_CHECK(result.value[0].name == "nourl");
    BOMWERK_TEST_CHECK(!result.warnings.empty());
    // No url, no remote, no owner to attribute: supplier stays honest.
    BOMWERK_TEST_CHECK(result.value[0].supplier.empty());
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
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a real vendored .gitmodules (pico-sdk), when parsed with no checkouts,
  // then all five submodules are reported (Low, uninitialized) with github
  // purls built from their URLs.
  {
    TempTree tree;
    tree.write(".gitmodules",
               read_file(fs::path(BOMWERK_FIXTURES_DIR) / "gitmodules" / "pico-sdk.gitmodules"));
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 5);
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
      BOMWERK_TEST_CHECK(result.complete);  // malformed => warnings, never exit-2
    }
  }

  // --- T110: a submodule that was never checked out, pinned in the index ------

  // Given a default CI clone: the superproject's .git holds an index pinning
  // libs/zlib, and the submodule was never checked out, when parsed, then the
  // component carries the pinned commit at High confidence with index
  // evidence, and raises the informational BW-GIT-006 instead of BW-GIT-004.
  {
    TempTree tree;
    tree.write(".gitmodules", kZlibGitmodules);
    tree.write(".git/index", gitindex_fixture("v2-sha1.index"));
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].purl == "pkg:github/madler/zlib@" + kIndexZlibCommit);
    BOMWERK_TEST_CHECK(result.value[0].version == kIndexZlibCommit);
    BOMWERK_TEST_CHECK(highest_confidence(result.value[0]) == Confidence::High);
    BOMWERK_TEST_CHECK(has_evidence(result.value[0], ".git/index -> gitlink libs/zlib"));
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kSubmoduleCommitFromIndex) ==
                       1);
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kSubmoduleNotInitialized) ==
                       0);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
  }

  // Given the same index but the submodule checked out at a different commit,
  // when parsed, then the checked-out HEAD wins: it is what is on disk.
  {
    TempTree tree;
    tree.write(".gitmodules", kZlibGitmodules);
    tree.write(".git/index", gitindex_fixture("v2-sha1.index"));
    tree.write("libs/zlib/.git/HEAD", kSha + "\n");
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version == kSha);
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given every submodule checked out and an index that is not an index at
  // all, when parsed, then nothing warns: the index is opened only when a
  // submodule needs it, so fully initialized repositories never pay for it.
  {
    TempTree tree;
    tree.write(".gitmodules", kZlibGitmodules);
    tree.write(".git/index", "not an index");
    tree.write("libs/zlib/.git/HEAD", kSha + "\n");
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given an index the reader refuses (a split index), when parsed, then the
  // submodule falls back to today's answer, unversioned with BW-GIT-004, and
  // BW-GIT-007 says why the index did not help.
  {
    TempTree tree;
    tree.write(".gitmodules", kZlibGitmodules);
    tree.write(".git/index", gitindex_fixture("split.index"));
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kGitIndexUnreadable) == 1);
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kSubmoduleNotInitialized) ==
                       1);
  }

  // Given two uninitialized submodules, one pinned in the index and one the
  // index does not mention, when parsed, then the pinned one is versioned and
  // the other keeps BW-GIT-004; and a trailing '/' in the declared path still
  // finds the gitlink, which git stores without one.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"zlib\"]\n\tpath = libs/zlib/\n"
               "\turl = https://github.com/madler/zlib.git\n"
               "[submodule \"gone\"]\n\tpath = libs/gone\n"
               "\turl = https://github.com/acme/gone.git\n");
    tree.write(".git/index", gitindex_fixture("v4-sha1.index"));
    const auto result = submodules::parse(tree.root());
    const Component* zlib = find_by_purl_prefix(result.value, "pkg:github/madler/zlib");
    const Component* gone = find_by_purl_prefix(result.value, "pkg:github/acme/gone");
    BOMWERK_TEST_CHECK(zlib != nullptr && zlib->version == kIndexZlibCommit);
    BOMWERK_TEST_CHECK(gone != nullptr && gone->version.empty());
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kSubmoduleCommitFromIndex) ==
                       1);
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kSubmoduleNotInitialized) ==
                       1);
  }

  // Given a SHA-256 superproject (extensions.objectformat in .git/config), when
  // parsed, then the index is read with 32-byte ids and the purl carries the
  // full 64-character pin.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"third_party/openssl\"]\n\tpath = third_party/openssl\n"
               "\turl = https://github.com/openssl/openssl.git\n");
    tree.write(".git/config",
               "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n");
    tree.write(".git/index", gitindex_fixture("v2-sha256.index"));
    const auto result = submodules::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.size() == 64);
    BOMWERK_TEST_CHECK(result.value[0].purl ==
                       "pkg:github/openssl/openssl@" + result.value[0].version);
  }

  // Given .gitmodules held in memory (parse_bytes, the fuzz entry point), when
  // parsed, then no index is ever consulted: there is no checkout to read.
  {
    const auto result = submodules::parse_bytes(kZlibGitmodules);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value[0].version.empty());
    BOMWERK_TEST_CHECK(count_code(result, bomwerk::core::WarningCode::kSubmoduleNotInitialized) ==
                       1);
  }

  std::puts("test_submodules: OK");
  return 0;
}
