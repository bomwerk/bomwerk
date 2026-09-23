// ctest unit test for git-dir resolution, promoted to core so the
// vendored-code heuristic can reuse it without depending on parsers/)
#include <cstdio>
#include <filesystem>
#include <string>
#include <system_error>

#include "core/git_dir.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::is_contained_relative_path;
using bomwerk::core::read_head_commit;
using bomwerk::core::resolve_git_dir;
using bomwerk::test::TempTree;

namespace
{

// A valid 40-hex (SHA-1) object id for synthesized HEADs.
const std::string kSha = "0123456789abcdef0123456789abcdef01234567";
// A second, distinct valid object id: used to prove a value never leaks from
// outside the containment root into a resolved commit.
const std::string kOutsideSha = "fedcba9876543210fedcba9876543210fedcba9";

}  // namespace

int main()
{
  // Given a relative path with no ".." segments, when checked, then it is safe.
  BOMWERK_TEST_CHECK(is_contained_relative_path(fs::path("libs/a")));

  // Given an absolute path, when checked, then it is rejected.
  BOMWERK_TEST_CHECK(!is_contained_relative_path(fs::path("/etc/passwd")));

  // Given a path escaping via "..", when checked, then it is rejected: the
  // CVE-2018-11235 shape this guards against.
  BOMWERK_TEST_CHECK(!is_contained_relative_path(fs::path("../../evil")));

  // Given an empty path, when checked, then it is rejected.
  BOMWERK_TEST_CHECK(!is_contained_relative_path(fs::path()));

  // Given a working tree with a detached-HEAD ".git" directory, when the git
  // dir is resolved and its HEAD read, then the commit comes back directly.
  {
    TempTree tree;
    tree.write(".git/HEAD", kSha + "\n");
    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    const fs::path git_dir = resolve_git_dir(tree.root(), containment_root);
    BOMWERK_TEST_CHECK(!git_dir.empty());
    BOMWERK_TEST_CHECK(read_head_commit(git_dir) == kSha);
  }

  // Given a HEAD that points at a loose ref, when read, then the ref is
  // followed to its commit.
  {
    TempTree tree;
    tree.write(".git/HEAD", "ref: refs/heads/main\n");
    tree.write(".git/refs/heads/main", kSha + "\n");
    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    const fs::path git_dir = resolve_git_dir(tree.root(), containment_root);
    BOMWERK_TEST_CHECK(read_head_commit(git_dir) == kSha);
  }

  // Given a HEAD ref that lives only in packed-refs, when read, then the
  // packed-refs fallback resolves the commit.
  {
    TempTree tree;
    tree.write(".git/HEAD", "ref: refs/heads/main\n");
    tree.write(".git/packed-refs",
               "# pack-refs with: peeled fully-peeled sorted\n" + kSha + " refs/heads/main\n");
    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    const fs::path git_dir = resolve_git_dir(tree.root(), containment_root);
    BOMWERK_TEST_CHECK(read_head_commit(git_dir) == kSha);
  }

  // Given a working tree with no ".git" at all, when the git dir is resolved,
  // then it comes back empty rather than fabricating one.
  {
    TempTree tree;
    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    BOMWERK_TEST_CHECK(resolve_git_dir(tree.root(), containment_root).empty());
  }

  // Given a symlinked ".git", when the git dir is resolved, then it is never
  // followed: treated the same as absent.
  {
    TempTree tree;
    TempTree target;
    target.write("HEAD", kSha + "\n");
    std::error_code symlink_error;
    fs::create_directory_symlink(target.root(), tree.root() / ".git", symlink_error);
    BOMWERK_TEST_CHECK(!symlink_error);
    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    BOMWERK_TEST_CHECK(resolve_git_dir(tree.root(), containment_root).empty());
  }

  // Given a ".git" file whose "gitdir:" pointer escapes the containment root
  // (not just the working directory: that's legitimate; real git lays a
  // submodule's gitdir out at "<root>/.git/modules/<name>"), when resolved,
  // then it is rejected and the outside commit never leaks into the result.
  {
    TempTree outside;
    outside.write("HEAD", kOutsideSha + "\n");

    TempTree tree;
    const fs::path work_dir = tree.root() / "libs/x";
    fs::create_directories(work_dir);
    const std::string escape_target = fs::relative(outside.root(), work_dir).string();
    tree.write("libs/x/.git", "gitdir: " + escape_target + "\n");

    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    const fs::path git_dir = resolve_git_dir(work_dir, containment_root);
    BOMWERK_TEST_CHECK(git_dir.empty());
  }

  // Given a HEAD containing a "ref:" line that itself attempts path traversal,
  // when read, then the ref is rejected before ever being joined onto a path.
  {
    TempTree tree;
    tree.write(".git/HEAD", "ref: ../../../../../etc/passwd\n");
    const fs::path containment_root = fs::absolute(tree.root()).lexically_normal();
    const fs::path git_dir = resolve_git_dir(tree.root(), containment_root);
    BOMWERK_TEST_CHECK(read_head_commit(git_dir).empty());
  }

  std::puts("test_git_dir: OK");
  return 0;
}
