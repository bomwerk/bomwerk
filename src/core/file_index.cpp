#include "core/file_index.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <system_error>
#include <utility>

#include "core/exclusions.hpp"
#include "core/manifest_names.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::core
{
namespace
{

/// True when `directory_path`: about to be pruned as a collision-prone
/// build-output directory: directly holds, or holds one level below it, a
/// file whose name is a recognized manifest (`default_manifest_names()`).
/// Bounded to two levels (vscode's real shape, `build/win32/Cargo.lock`, is
/// exactly this deep) so the cost is at most one extra `directory_iterator`
/// pass per child directory of the about-to-be-excluded tree, never
/// proportional to the whole pruned subtree's size. A best-effort heuristic,
/// not exhaustive: exact filename match only, no manifest-family variants
/// (see `matches_manifest_name`), and nothing past two levels. Filesystem
/// errors degrade to "nothing found" (rule 1): a permission error here must
/// never turn into a scan failure over a directory that is being skipped
/// either way.
bool excluded_directory_may_hide_a_manifest(const fs::path& directory_path)
{
  const std::set<std::string>& manifest_names = default_manifest_names();
  std::error_code walk_error;
  for (auto entry = fs::directory_iterator(
           directory_path, fs::directory_options::skip_permission_denied, walk_error);
       !walk_error && entry != fs::directory_iterator(); entry.increment(walk_error))
  {
    if (walk_error)
    {
      break;
    }
    std::error_code type_error;
    if (entry->is_regular_file(type_error) && !type_error &&
        manifest_names.count(entry->path().filename().string()) > 0)
    {
      return true;
    }
    if (!entry->is_directory(type_error) || type_error)
    {
      continue;
    }
    std::error_code nested_walk_error;
    for (auto nested_entry = fs::directory_iterator(
             entry->path(), fs::directory_options::skip_permission_denied, nested_walk_error);
         !nested_walk_error && nested_entry != fs::directory_iterator();
         nested_entry.increment(nested_walk_error))
    {
      if (nested_walk_error)
      {
        break;
      }
      std::error_code nested_type_error;
      if (nested_entry->is_regular_file(nested_type_error) && !nested_type_error &&
          manifest_names.count(nested_entry->path().filename().string()) > 0)
      {
        return true;
      }
    }
  }
  return false;
}

/// True when `candidate` equals `prefix` or lies inside it, compared
/// component-wise (a textual prefix would wrongly match "src2" under "src").
/// Both paths are root-relative and lexically normal.
bool path_is_within(const fs::path& candidate, const fs::path& prefix)
{
  auto candidate_iterator = candidate.begin();
  for (auto prefix_iterator = prefix.begin(); prefix_iterator != prefix.end();
       ++prefix_iterator, ++candidate_iterator)
  {
    if (candidate_iterator == candidate.end() || *candidate_iterator != *prefix_iterator)
    {
      return false;
    }
  }
  return true;
}

/// True when the walk must enter `relative_dir`: either the directory leads
/// down to an included subtree (it is an ancestor of one) or it lies inside
/// one. Only called when `included_subtrees` is non-empty.
bool directory_reaches_include(const fs::path& relative_dir,
                               const std::set<fs::path>& included_subtrees)
{
  for (const fs::path& included_subtree : included_subtrees)
  {
    if (path_is_within(included_subtree, relative_dir) ||
        path_is_within(relative_dir, included_subtree))
    {
      return true;
    }
  }
  return false;
}

/// True when a file at `relative_path` belongs to the index under the include
/// restriction. Only called when `included_subtrees` is non-empty: an
/// ancestor directory of an include is traversed to reach it, but its own
/// files are outside every included subtree and stay out.
bool file_is_included(const fs::path& relative_path, const std::set<fs::path>& included_subtrees)
{
  for (const fs::path& included_subtree : included_subtrees)
  {
    if (path_is_within(relative_path, included_subtree))
    {
      return true;
    }
  }
  return false;
}

}  // namespace

Result<FileIndex> build_file_index(const fs::path& root,
                                   const std::set<std::string>& excluded_dir_names,
                                   const std::set<fs::path>& excluded_subtrees,
                                   const std::set<fs::path>& included_subtrees)
{
  Result<FileIndex> result;

  std::error_code directory_error;
  if (!fs::is_directory(root, directory_error) || directory_error)
  {
    spdlog::debug("file index: '{}' is not a scannable directory", root.string());
    return result;  // nothing to index; not an error
  }

  std::error_code walk_error;
  for (auto iterator = fs::recursive_directory_iterator(
           root, fs::directory_options::skip_permission_denied, walk_error);
       iterator != fs::recursive_directory_iterator(); iterator.increment(walk_error))
  {
    if (walk_error)
    {
      result.warn(WarningCode::kDirectoryWalkError,
                  std::string{"directory walk stopped early: "} + walk_error.message());
      break;
    }
    const fs::path& entry_path = iterator->path();

    if (iterator->is_directory(walk_error))
    {
      if (walk_error)
      {
        continue;
      }
      const std::string entry_name = entry_path.filename().string();
      if (excluded_dir_names.count(entry_name) > 0)
      {
        if (collision_prone_excluded_dir_names().contains(entry_name) &&
            excluded_directory_may_hide_a_manifest(entry_path))
        {
          result.warn(WarningCode::kBuildOutputDirectoryHoldsManifest,
                      "directory walk: skipped '" +
                          entry_path.lexically_relative(root).generic_string() +
                          "' as a build-output directory, but it holds a recognized manifest file "
                          "within two levels: if this is real source rather than build output, "
                          "rerun with -A/--all or configure [scan] include for this path");
        }
        iterator.disable_recursion_pending();  // skip build/VCS/cache trees
        continue;
      }
      if (!excluded_subtrees.empty() || !included_subtrees.empty())
      {
        // The iterator built entry_path by appending to root, so the relative
        // form is recoverable textually. Never fs::relative here: it
        // re-resolves both paths against the filesystem (one stat per path
        // component) on every call, which dominates the whole scan on a large
        // tree.
        const fs::path relative_dir = entry_path.lexically_relative(root).lexically_normal();
        if (excluded_subtrees.contains(relative_dir))
        {
          // A vendored submodule or a configured [scan] exclude: already
          // reported as one component elsewhere (submodule) or deliberately
          // out of scope (config): never re-scanned as if it were this
          // project's own files. Checked before the include filter so
          // exclusion always beats inclusion.
          iterator.disable_recursion_pending();
          continue;
        }
        if (!included_subtrees.empty() &&
            !directory_reaches_include(relative_dir, included_subtrees))
        {
          iterator.disable_recursion_pending();  // outside every [scan] include subtree
        }
      }
      continue;
    }

    if (walk_error || !iterator->is_regular_file(walk_error))
    {
      continue;
    }

    // Same textual recovery as above (never fs::relative in this per-file hot
    // path). The appended component chain contains no '.'/'..', so the result
    // is already lexically normal, and a textual split cannot fail.
    fs::path relative_path = entry_path.lexically_relative(root);
    if (!included_subtrees.empty() && !file_is_included(relative_path, included_subtrees))
    {
      continue;  // e.g. a root-level file when only "src" is included
    }
    result.value.files.push_back(std::move(relative_path));
  }

  // Deterministic order (Hard Rule 3): directory iteration order is
  // unspecified, so sort before any caller applies its own cap.
  std::sort(result.value.files.begin(), result.value.files.end());
  return result;
}

fs::path normalized_subtree_path(const fs::path& raw_path)
{
  fs::path normalized = raw_path.lexically_normal();
  // Strip trailing separators. Termination compares against the PREVIOUS
  // value rather than testing emptiness alone, because `parent_path()` is a
  // fixed point at the filesystem root: "/" has an empty filename AND is its
  // own parent, so the obvious loop never ends. That input is reachable: a
  // scanned repo's own bomwerk.toml can say `include = ["/"]`, and an SBOM
  // handed to `bomwerk trim` can carry `"location": "/"`: and both reach
  // here BEFORE the guards that would reject an absolute path. A hang on
  // hostile input is worse than a crash (rule 1), and pre-screening is not
  // the caller's job.
  while (!normalized.empty() && normalized.filename().empty())
  {
    fs::path parent = normalized.parent_path();
    if (parent == normalized)
    {
      break;
    }
    normalized = std::move(parent);
  }
  return normalized;
}

bool path_in_scan_scope(const fs::path& relative_path, const std::set<fs::path>& excluded_subtrees,
                        const std::set<fs::path>& included_subtrees)
{
  for (const fs::path& excluded_subtree : excluded_subtrees)
  {
    if (path_is_within(relative_path, excluded_subtree))
    {
      return false;
    }
  }
  if (included_subtrees.empty())
  {
    return true;
  }
  return file_is_included(relative_path, included_subtrees);
}

}  // namespace bomwerk::core
