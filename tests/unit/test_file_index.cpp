// ctest unit test for the shared directory-walk primitive (core/file_index).
#include <cstdio>
#include <filesystem>
#include <set>
#include <vector>

#include "core/file_index.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::build_file_index;
using bomwerk::core::FileIndex;
using bomwerk::core::normalized_subtree_path;
using bomwerk::core::path_in_scan_scope;
using bomwerk::test::TempTree;

int main()
{
  // Given a small tree with no exclusions, when indexed, then every regular
  // file is present as a root-relative path, sorted.
  {
    TempTree tree;
    tree.write("a.txt", "1");
    tree.write("sub/b.txt", "2");
    tree.write("sub/deeper/c.txt", "3");
    const auto result = build_file_index(tree.root(), {}, {});
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    const std::vector<fs::path> expected{"a.txt", "sub/b.txt", "sub/deeper/c.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
  }

  // Given a directory named in excluded_dir_names, when indexed, then none of
  // its contents (however deep) appear in the index. Neither file inside is a
  // recognized manifest name, so: a genuine build-output shape: this must
  // stay silent (most "build/" directories are exactly this, and the
  // new shallow-manifest peek must not turn every one of them noisy).
  {
    TempTree tree;
    tree.write("keep.txt", "1");
    tree.write("build/generated.txt", "2");
    tree.write("build/nested/also_generated.txt", "3");
    const auto result = build_file_index(tree.root(), {"build"}, {});
    const std::vector<fs::path> expected{"keep.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a collision-prone excluded directory that holds a recognized
  // manifest two levels below it: vscode's real shape,
  // build/win32/Cargo.lock: when indexed, then the directory is still fully
  // pruned (nothing under it enters the index) but one warning names it, so
  // the loss is visible instead of silent.
  {
    TempTree tree;
    tree.write("keep.txt", "1");
    tree.write("build/win32/Cargo.lock", "2");
    const auto result = build_file_index(tree.root(), {"build"}, {});
    const std::vector<fs::path> expected{"keep.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
    BOMWERK_TEST_CHECK(result.warnings[0].message.find("build") != std::string::npos);
  }

  // Given the same shadowed-manifest shape but directly one level below
  // (rather than two), when indexed, then the peek still finds it. Uses
  // Cargo.lock, not package.json: default_manifest_names() lists the
  // *lockfile*, not the loose npm manifest, so package.json here would not
  // actually be a recognized name and must not be mistaken for one.
  {
    TempTree tree;
    tree.write("build/Cargo.lock", "1");
    const auto result = build_file_index(tree.root(), {"build"}, {});
    BOMWERK_TEST_CHECK(result.value.files.empty());
    BOMWERK_TEST_CHECK(result.warnings.size() == 1);
  }

  // Given the identical shadowed-manifest shape under a NON-collision-prone
  // excluded name (a dependency cache, never expected to hold first-party
  // source by convention), when indexed, then no warning fires: that
  // distinction is the whole point of collision_prone_excluded_dir_names().
  {
    TempTree tree;
    tree.write(".cache/win32/Cargo.lock", "2");
    const auto result = build_file_index(tree.root(), {".cache"}, {});
    BOMWERK_TEST_CHECK(result.value.files.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a manifest three levels below a collision-prone excluded directory
  //: past the two-level bound: when indexed, then the peek does not reach
  // it and no warning fires. Documents the known, bounded limit rather than
  // asserting an accident.
  {
    TempTree tree;
    tree.write("build/a/b/Cargo.lock", "2");
    const auto result = build_file_index(tree.root(), {"build"}, {});
    BOMWERK_TEST_CHECK(result.value.files.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Given a subtree rooted at a path in excluded_subtrees (a vendored
  // submodule), when indexed, then that subtree is skipped even though its
  // directory name is not otherwise excluded.
  {
    TempTree tree;
    tree.write("keep.txt", "1");
    tree.write("vendor/thirdparty/inside.txt", "2");
    const std::set<fs::path> excluded_subtrees{fs::path("vendor/thirdparty")};
    const auto result = build_file_index(tree.root(), {}, excluded_subtrees);
    const std::vector<fs::path> expected{"keep.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
  }

  // Given a root that is not a directory, when indexed, then the result is an
  // empty, complete index: never an error, never a crash.
  {
    TempTree tree;
    const auto result = build_file_index(tree.root() / "does_not_exist", {}, {});
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.files.empty());
  }

  // Given included subtrees (bomwerk.toml [scan] include), when indexed,
  // then only files inside them appear: a root-level file and a sibling tree
  // stay out, while a nested include is still reached through its ancestor.
  {
    TempTree tree;
    tree.write("root_level.txt", "1");
    tree.write("app/a.txt", "2");
    tree.write("app/deeper/b.txt", "3");
    tree.write("libs/core/c.txt", "4");
    tree.write("libs/other/d.txt", "5");
    tree.write("outside/e.txt", "6");
    const std::set<fs::path> included_subtrees{fs::path("app"), fs::path("libs/core")};
    const auto result = build_file_index(tree.root(), {}, {}, included_subtrees);
    const std::vector<fs::path> expected{"app/a.txt", "app/deeper/b.txt", "libs/core/c.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
  }

  // Given a component-wise near-miss ("src2" vs include "src"), when indexed,
  // then it stays out: inclusion matches path components, never a textual
  // prefix.
  {
    TempTree tree;
    tree.write("src/in.txt", "1");
    tree.write("src2/out.txt", "2");
    const std::set<fs::path> included_subtrees{fs::path("src")};
    const auto result = build_file_index(tree.root(), {}, {}, included_subtrees);
    const std::vector<fs::path> expected{"src/in.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
  }

  // Given an excluded subtree nested inside an included one, when indexed,
  // then exclusion beats inclusion.
  {
    TempTree tree;
    tree.write("app/keep.txt", "1");
    tree.write("app/playground/drop.txt", "2");
    const std::set<fs::path> included_subtrees{fs::path("app")};
    const std::set<fs::path> excluded_subtrees{fs::path("app/playground")};
    const auto result = build_file_index(tree.root(), {}, excluded_subtrees, included_subtrees);
    const std::vector<fs::path> expected{"app/keep.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
  }

  // Given an empty include set, when indexed, then everything is present :
  // "no includes" means "no restriction", the earlier behavior.
  {
    TempTree tree;
    tree.write("a.txt", "1");
    tree.write("sub/b.txt", "2");
    const auto result = build_file_index(tree.root(), {}, {}, {});
    const std::vector<fs::path> expected{"a.txt", "sub/b.txt"};
    BOMWERK_TEST_CHECK(result.value.files == expected);
  }

  // Given a path outside every included subtree, when checked directly (not
  // via a directory walk: the shape a producer like submodules::parse needs,
  // since it discovers its components from .gitmodules rather than file_index
  // itself), then it is out of scan scope.
  {
    const std::set<fs::path> included_subtrees{fs::path("app")};
    BOMWERK_TEST_CHECK(!path_in_scan_scope(fs::path("vendor/lib"), {}, included_subtrees));
    BOMWERK_TEST_CHECK(path_in_scan_scope(fs::path("app/vendored"), {}, included_subtrees));
  }

  // Given an empty include set (no restriction) and a path inside an excluded
  // subtree, when checked, then exclusion still applies even with nothing
  // included yet: exclusion never depends on inclusion being configured.
  {
    const std::set<fs::path> excluded_subtrees{fs::path("vendor/lib")};
    BOMWERK_TEST_CHECK(!path_in_scan_scope(fs::path("vendor/lib"), excluded_subtrees, {}));
    BOMWERK_TEST_CHECK(path_in_scan_scope(fs::path("app"), excluded_subtrees, {}));
  }

  // Given no include or exclude restriction at all, when checked, then every
  // path is in scope: the earlier default.
  {
    BOMWERK_TEST_CHECK(path_in_scan_scope(fs::path("anything/at/all"), {}, {}));
  }

  // Given the spellings that must collapse to one subtree, when normalized,
  // then they do. Both sides of every subtree comparison in the codebase go
  // through here (bomwerk.toml's include/exclude lists, and the component
  // roots a build trace is matched against), so a disagreement here looks
  // like "that subtree was never configured" rather than like a bug.
  {
    BOMWERK_TEST_CHECK(normalized_subtree_path("third_party/zlib/") ==
                       fs::path("third_party/zlib"));
    BOMWERK_TEST_CHECK(normalized_subtree_path("third_party/./zlib") ==
                       fs::path("third_party/zlib"));
    BOMWERK_TEST_CHECK(normalized_subtree_path("third_party/zlib") == fs::path("third_party/zlib"));
    BOMWERK_TEST_CHECK(normalized_subtree_path("") == fs::path(""));
  }

  // Given a bare filesystem root, when normalized, then it comes back rather
  // than hanging. This is the input that used to spin forever: "/" has an
  // EMPTY filename and is its own parent, so a strip-trailing-separators loop
  // that only tests emptiness never terminates. It is reachable from
  // untrusted input in two places: a scanned repo's own bomwerk.toml
  // (`[scan] include = ["/"]`) and a component location in an SBOM handed to
  // `bomwerk trim`: and both reach here BEFORE the guard that rejects an
  // absolute path, so this function has to survive it on its own (rule 1: a
  // hang on hostile input is worse than a crash). If this test ever times out
  // instead of failing, that is the regression.
  {
    BOMWERK_TEST_CHECK(normalized_subtree_path("/") == fs::path("/"));
    BOMWERK_TEST_CHECK(!normalized_subtree_path("/").empty());
  }

  std::puts("test_file_index: OK");
  return 0;
}
