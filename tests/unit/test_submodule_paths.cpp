// ctest unit test for the submodule walk-scoping rule
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <ios>
#include <set>
#include <sstream>
#include <string>

#include "core/model.hpp"
#include "core/submodule_paths.hpp"
#include "parsers/cpp/submodules.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::submodule_subtrees;
using bomwerk::core::with_submodule_subtrees;
using bomwerk::test::TempTree;
namespace submodules = bomwerk::parsers::cpp::submodules;

namespace
{

std::string read_file(const fs::path& path)
{
  std::ifstream stream(path, std::ios::binary);
  std::ostringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

/// The submodule working-tree paths the submodules producer actually reported, in the
/// same normalized shape submodule_subtrees() returns. The drift guard below
/// compares the two: both read the same `.gitmodules`, and a scoping rule that
/// disagreed with the components it is supposed to stand in for would silently
/// either walk into a reported submodule or skip a subtree nothing reports.
std::set<fs::path> reported_roots(const fs::path& root)
{
  std::set<fs::path> roots;
  for (const Component& component : submodules::parse(root).value)
  {
    if (!component.root.empty())
    {
      roots.insert(component.root.lexically_normal());
    }
  }
  return roots;
}

}  // namespace

int main()
{
  // Given three declared submodules, when the scoping rule is queried, then all
  // three working-tree paths come back root-relative: this is the set the file
  // walk prunes so a vendored submodule costs ONE component, not thousands of
  // files.
  {
    TempTree tree;
    tree.write(
        ".gitmodules",
        "[submodule \"libs/a\"]\n\tpath = libs/a\n\turl = https://github.com/acme/a.git\n"
        "[submodule \"libs/b\"]\n\tpath = libs/b\n\turl = https://github.com/acme/b.git\n"
        "[submodule \"vendor/c\"]\n\tpath = vendor/c\n\turl = https://github.com/acme/c.git\n");

    const std::set<fs::path> subtrees = submodule_subtrees(tree.root());
    BOMWERK_TEST_CHECK(subtrees.size() == 3);
    BOMWERK_TEST_CHECK(subtrees.count(fs::path("libs/a")) == 1);
    BOMWERK_TEST_CHECK(subtrees.count(fs::path("libs/b")) == 1);
    BOMWERK_TEST_CHECK(subtrees.count(fs::path("vendor/c")) == 1);
  }

  // Given a declared path written with a leading "./", when queried, then it
  // comes back normalized: the walker compares against lexically-normal
  // root-relative paths, so "./libs/foo" must match "libs/foo" or the subtree
  // would be walked anyway.
  {
    TempTree tree;
    tree.write(
        ".gitmodules",
        "[submodule \"libs/foo\"]\n\tpath = ./libs/foo\n\turl = https://github.com/a/f.git\n");

    const std::set<fs::path> subtrees = submodule_subtrees(tree.root());
    BOMWERK_TEST_CHECK(subtrees.size() == 1);
    BOMWERK_TEST_CHECK(subtrees.count(fs::path("libs/foo")) == 1);
  }

  // Given no .gitmodules at all, when queried, then the set is empty: a repo
  // without submodules is the common case, not an error.
  {
    TempTree tree;
    BOMWERK_TEST_CHECK(submodule_subtrees(tree.root()).empty());
  }

  // Given paths that escape the scanned root (CVE-2018-11235 shape) or are
  // absolute, when queried, then both are dropped: an excluded subtree outside
  // the tree is meaningless, and honoring it would let a hostile .gitmodules
  // steer the walk.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"evil\"]\n\tpath = ../../evil\n\turl = https://github.com/a/e.git\n"
               "[submodule \"abs\"]\n\tpath = /etc\n\turl = https://github.com/a/x.git\n"
               "[submodule \"ok\"]\n\tpath = libs/ok\n\turl = https://github.com/a/o.git\n");

    const std::set<fs::path> subtrees = submodule_subtrees(tree.root());
    BOMWERK_TEST_CHECK(subtrees.size() == 1);
    BOMWERK_TEST_CHECK(subtrees.count(fs::path("libs/ok")) == 1);
  }

  // Given a submodule section declaring no path, when queried, then it
  // contributes nothing: there is no subtree to skip.
  {
    TempTree tree;
    tree.write(".gitmodules", "[submodule \"nopath\"]\n\turl = https://github.com/acme/n.git\n");
    BOMWERK_TEST_CHECK(submodule_subtrees(tree.root()).empty());
  }

  // Given a caller's own excluded subtrees, when unioned, then both the
  // caller's and the submodules' subtrees survive: a standalone producer
  // entrypoint must honor what it was asked to skip AND the submodule rule.
  {
    TempTree tree;
    tree.write(".gitmodules",
               "[submodule \"libs/a\"]\n\tpath = libs/a\n\turl = https://github.com/acme/a.git\n");

    const std::set<fs::path> combined =
        with_submodule_subtrees(tree.root(), {fs::path("build"), fs::path("docs")});
    BOMWERK_TEST_CHECK(combined.size() == 3);
    BOMWERK_TEST_CHECK(combined.count(fs::path("libs/a")) == 1);
    BOMWERK_TEST_CHECK(combined.count(fs::path("build")) == 1);
    BOMWERK_TEST_CHECK(combined.count(fs::path("docs")) == 1);
  }

  // Given a repo with no submodules, when unioned, then the caller's set comes
  // back untouched: the rule never widens a skip set on its own.
  {
    TempTree tree;
    const std::set<fs::path> combined = with_submodule_subtrees(tree.root(), {fs::path("build")});
    BOMWERK_TEST_CHECK(combined.size() == 1);
    BOMWERK_TEST_CHECK(combined.count(fs::path("build")) == 1);
  }

  // DRIFT GUARD. Given a real vendored .gitmodules (pico-sdk, 5 submodules),
  // when both the scoping rule and the submodules producer read it, then they agree
  // exactly on the set of working-tree paths. Two code paths read this file for
  // two purposes (what to skip vs. what to report); this is what keeps them
  // from diverging.
  {
    TempTree tree;
    tree.write(".gitmodules",
               read_file(fs::path(BOMWERK_FIXTURES_DIR) / "gitmodules" / "pico-sdk.gitmodules"));
    const std::set<fs::path> subtrees = submodule_subtrees(tree.root());
    BOMWERK_TEST_CHECK(subtrees.size() == 5);
    BOMWERK_TEST_CHECK(subtrees == reported_roots(tree.root()));
  }

  // Given every hostile fixture, when the scoping rule reads it, then it never
  // crashes and still agrees with the producer. Malformed input must fail
  // toward scanning MORE (an empty skip set), never toward silently pruning a
  // subtree nothing reported: under ASan/UBSan this is also the guard against
  // out-of-bounds reads on crafted input.
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
      BOMWERK_TEST_CHECK(submodule_subtrees(tree.root()) == reported_roots(tree.root()));
    }
  }

  std::puts("test_submodule_paths: OK");
  return 0;
}
