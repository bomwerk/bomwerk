#include "core/submodule_paths.hpp"

#include <system_error>

#include "core/git_config.hpp"
#include "core/git_dir.hpp"

namespace fs = std::filesystem;

namespace bomwerk::core
{

std::set<fs::path> submodule_subtrees(const fs::path& root)
{
  std::set<fs::path> subtrees;

  const fs::path gitmodules_path = root / ".gitmodules";
  std::error_code exists_error;
  if (!fs::exists(gitmodules_path, exists_error) || exists_error)
  {
    return subtrees;  // no .gitmodules => no submodules; not an error
  }

  // Warnings are deliberately dropped here: see the header: the submodules
  // producer owns reporting this file, and it warns about every section this
  // loop skips below.
  const Result<GitConfig> modules = read_git_config(gitmodules_path);
  for (const GitConfigSection& section : modules.value.sections)
  {
    if (section.name != "submodule")
    {
      continue;
    }
    const std::string* path_value = section.find("path");
    if (path_value == nullptr || path_value->empty())
    {
      continue;
    }
    const fs::path relative_path(*path_value);
    if (!is_contained_relative_path(relative_path))
    {
      continue;
    }
    // Normalized because the walker compares against lexically-normal
    // root-relative paths: a declared "./libs/foo" must match "libs/foo".
    subtrees.insert(relative_path.lexically_normal());
  }

  return subtrees;
}

std::set<fs::path> with_submodule_subtrees(const fs::path& root, std::set<fs::path> caller_excluded)
{
  const std::set<fs::path> subtrees = submodule_subtrees(root);
  caller_excluded.insert(subtrees.begin(), subtrees.end());
  return caller_excluded;
}

}  // namespace bomwerk::core
