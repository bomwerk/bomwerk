#include "core/exclusions.hpp"

#include "core/name_list.hpp"

namespace bomwerk::core
{

// Note: git submodule trees are skipped separately by `scan`: each
// submodule surfaces as ONE component via the .gitmodules parser, and its
// working-tree path is pruned from the walk. Honoring nested .gitignore files
// is not implemented. The names below are the build/VCS/cache dirs skipped by
// default (or all, with --all).

const std::set<std::string>& default_excluded_dir_names()
{
  static const std::set<std::string> kExcludedDirNames = {
      // version control
      ".git", ".svn", ".hg",
      // IDE / editor state
      ".idea", ".vscode",
      // build outputs: collision-prone (see collision_prone_excluded_dir_names
      // below): common enough that a project can legitimately use one
      // of these names for real, checked-in source rather than only ever
      // generated output.
      "build", "cmake-build-debug", "cmake-build-release", "out",
      // dependency / build-tool caches. These names never hold first-party
      // source, so they are safe to skip. Note we deliberately do NOT list
      // collision-prone names like "packages" (pnpm/npm workspaces put real
      // source there): telling those apart needs .gitignore awareness,
      // which the walk does not have.
      ".cache", "vcpkg_installed", "buildtrees", "downloads", "_deps"};
  return kExcludedDirNames;
}

const std::set<std::string>& collision_prone_excluded_dir_names()
{
  static const std::set<std::string> kCollisionProneNames = {"build", "cmake-build-debug",
                                                             "cmake-build-release", "out"};
  return kCollisionProneNames;
}

Result<std::set<std::string>> load_excluded_dir_names(const std::filesystem::path& list_path)
{
  return load_name_list(list_path, "exclude list", default_excluded_dir_names());
}

}  // namespace bomwerk::core
