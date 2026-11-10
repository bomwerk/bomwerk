#include "parsers/cpp/submodules.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include "core/git_config.hpp"
#include "core/git_dir.hpp"
#include "core/git_index.hpp"
#include "core/git_url.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::cpp::submodules
{
namespace
{

constexpr std::string_view kProducerName = "submodules";
constexpr std::string_view kGitmodulesName = ".gitmodules";

/// Normalize the superproject's origin URL to a `scheme://host/owner/repo` base
/// so relative submodule URLs resolve with '/'-separated path popping even when
/// origin is an scp-like `git@host:owner/repo` remote.
std::string origin_resolution_base(const std::string& origin_url)
{
  const core::GitRemote remote = core::parse_git_remote(origin_url);
  if (remote.host.empty())
  {
    return origin_url;
  }
  std::string base = "https://" + remote.host + "/";
  if (!remote.owner.empty())
  {
    base += remote.owner + "/";
  }
  base += remote.repo;
  return base;
}

/// Generic purl used when a submodule declares no URL: name from the
/// working-tree path's last segment, no vcs_url qualifier (there is no URL).
/// The commit is case-normalized for the same reason `core::build_git_purl`
/// does it: this is the one purl-building path in the producer that does not
/// go through that function, so it needs its own call to stay consistent.
std::string generic_purl_from_path(const fs::path& relative_path, const std::string& commit)
{
  std::string name = relative_path.filename().string();
  if (name.empty())
  {
    name = "unknown";
  }
  const std::string version = core::normalized_object_id(commit);
  std::string purl = "pkg:generic/" + core::percent_encode(name);
  if (!version.empty())
  {
    purl += "@" + core::percent_encode(version);
  }
  return purl;
}

/// Where a submodule's commit came from.
enum class PinSource
{
  None,               ///< neither checked out nor recorded: no version
  CheckedOutHead,     ///< the submodule's own git dir: its HEAD
  SuperprojectIndex,  ///< the superproject's `.git/index` gitlink; contents absent
};

struct PinnedCommit
{
  std::string commit;
  PinSource source = PinSource::None;
};

/// The pinned commit of the submodule whose working tree is at a root-relative
/// path, and where it was read from.
using PinnedCommitLookup = std::function<PinnedCommit(const fs::path&)>;

/// The key a submodule's `.gitmodules` path has in the index: '/'-separated,
/// lexically normal, no trailing separator, exactly how git stores the gitlink.
std::string index_path_key(const fs::path& relative_path)
{
  std::string key = relative_path.lexically_normal().generic_string();
  while (!key.empty() && key.back() == '/')
  {
    key.pop_back();
  }
  return key;
}

/// One component per `[submodule]` section of an already-parsed `.gitmodules`.
/// `origin_base` (empty when unknown) resolves relative submodule URLs, and
/// `pinned_commit_for` answers each submodule's pinned commit: the only two
/// things that come from outside the `.gitmodules` text itself.
void append_submodule_components(const core::GitConfig& modules, const std::string& origin_base,
                                 const PinnedCommitLookup& pinned_commit_for,
                                 core::Result<std::vector<core::Component>>& result)
{
  std::size_t resolved_count = 0;
  std::size_t declared_count = 0;
  for (const core::GitConfigSection& section : modules.sections)
  {
    if (section.name != "submodule")
    {
      continue;
    }
    const std::string* path_value = section.find("path");
    const std::string declared_name =
        section.subsection.empty() ? std::string{"<unnamed>"} : section.subsection;
    if (path_value == nullptr || path_value->empty())
    {
      result.warn(core::WarningCode::kSubmoduleMissingPath,
                  "submodule '" + declared_name + "' has no path; skipping");
      continue;
    }

    const fs::path relative_path(*path_value);
    if (!core::is_contained_relative_path(relative_path))
    {
      result.warn(
          core::WarningCode::kSubmoduleUnsafePath,
          "submodule '" + declared_name + "' has an unsafe path '" + *path_value + "'; skipping");
      continue;
    }
    ++declared_count;

    const std::string* url_value = section.find("url");
    const std::string* branch_value = section.find("branch");

    const PinnedCommit pinned = pinned_commit_for(relative_path);
    const std::string& commit = pinned.commit;
    const bool resolved = !commit.empty();
    if (resolved)
    {
      ++resolved_count;
    }
    if (pinned.source == PinSource::SuperprojectIndex)
    {
      // Informational (BW-GIT-006): the version is exact, the files are not
      // here. See docs/warning-codes.md for why this does not cost exit 1.
      result.warn(core::WarningCode::kSubmoduleCommitFromIndex,
                  "submodule '" + relative_path.string() + "' not checked out; version " + commit +
                      " read from the superproject's index (the commit `git submodule update` "
                      "would check out)");
    }
    else if (!resolved)
    {
      result.warn(core::WarningCode::kSubmoduleNotInitialized,
                  "submodule '" + relative_path.string() +
                      "' not initialized (no checked-out commit); run "
                      "`git submodule update --init` to include it");
    }

    std::string resolved_url;
    if (url_value != nullptr && !url_value->empty())
    {
      resolved_url = core::resolve_relative_url(origin_base, *url_value);
      const bool still_relative =
          resolved_url.rfind("./", 0) == 0 || resolved_url.rfind("../", 0) == 0;
      if (still_relative)
      {
        result.warn(core::WarningCode::kSubmoduleNoUrl,
                    "submodule '" + relative_path.string() + "' has a relative url '" + *url_value +
                        "' but the superproject origin is unknown; purl may be imprecise");
      }
    }
    else
    {
      result.warn(core::WarningCode::kSubmoduleNoUrl,
                  "submodule '" + relative_path.string() +
                      "' declares no url; reported as a generic component");
    }

    core::Component component;
    component.version = commit;
    component.root = relative_path;
    if (!resolved_url.empty())
    {
      const core::GitRemote remote = core::parse_git_remote(resolved_url);
      component.name = remote.repo.empty() ? relative_path.filename().string() : remote.repo;
      component.purl = core::build_git_purl(resolved_url, commit, component.name);
      // The remote's owner segment is NTIA/CRA supplier evidence straight
      // from .gitmodules: empty when the origin URL itself has no owner
      // segment (e.g. an unresolved relative URL), never guessed.
      component.supplier = remote.owner;
    }
    else
    {
      component.name = relative_path.filename().string();
      component.purl = generic_purl_from_path(relative_path, commit);
    }

    // A purl we cannot parse back is a bug in the builder, not degraded
    // input: the shared helper surfaces it as kPurlValidationFailed so tests
    // and the fuzz harness catch it. The purl itself is left as built.
    core::validate_purl(component.purl, kProducerName, result.warnings);

    const core::Confidence declared_confidence =
        resolved ? core::Confidence::High : core::Confidence::Low;
    component.evidence.push_back(
        {core::Source::Manifest, ".gitmodules -> " + declared_name, declared_confidence});
    // An index pin rates High like a checked-out HEAD: the gitlink is the
    // exact commit the superproject records (a checked-out HEAD can even drift
    // from it). What is missing is the submodule's files, not its identity,
    // and BW-GIT-006 says so.
    if (pinned.source == PinSource::CheckedOutHead)
    {
      component.evidence.push_back({core::Source::Manifest,
                                    relative_path.string() + "/.git -> HEAD",
                                    core::Confidence::High});
    }
    else if (pinned.source == PinSource::SuperprojectIndex)
    {
      component.evidence.push_back({core::Source::Manifest,
                                    ".git/index -> gitlink " + index_path_key(relative_path),
                                    core::Confidence::High});
    }
    if (branch_value != nullptr && !branch_value->empty())
    {
      component.evidence.push_back({core::Source::Manifest,
                                    ".gitmodules -> " + declared_name + " branch=" + *branch_value,
                                    declared_confidence});
    }

    spdlog::debug("submodule {} -> {} ({})", relative_path.string(), component.purl,
                  pinned.source == PinSource::CheckedOutHead      ? "checked out"
                  : pinned.source == PinSource::SuperprojectIndex ? "pinned in index"
                                                                  : "uninitialized");
    result.value.push_back(std::move(component));
  }

  // Deterministic order (rule 3); merge in scan re-sorts, but a producer should
  // be self-consistent regardless of the caller.
  std::sort(result.value.begin(), result.value.end(),
            [](const core::Component& left, const core::Component& right)
            { return left.purl < right.purl; });

  spdlog::debug("parsed .gitmodules: {} submodules, {}/{} commits resolved", result.value.size(),
                resolved_count, declared_count);
}

}  // namespace

core::Result<std::vector<core::Component>> parse(const fs::path& root)
{
  core::Result<std::vector<core::Component>> result;

  const fs::path gitmodules_path = root / kGitmodulesName;
  std::error_code exists_error;
  if (!fs::exists(gitmodules_path, exists_error) || exists_error)
  {
    return result;  // no .gitmodules => no submodules; not an error
  }

  core::Result<core::GitConfig> modules = core::read_git_config(gitmodules_path);
  for (core::Warning& warning : modules.warnings)
  {
    result.warnings.push_back(std::move(warning));
  }

  // Bounds every gitdir resolution below (see core::resolve_git_dir): a
  // submodule's `.git` file legitimately points outside its OWN directory, but
  // never outside this scanned tree as a whole.
  std::error_code root_absolute_error;
  const fs::path containment_root = fs::absolute(root, root_absolute_error).lexically_normal();

  // Origin URL (for relative submodule URLs), read from the superproject's own
  // config: same file-only path, never a git subprocess.
  std::string origin_base;
  core::GitObjectFormat object_format = core::GitObjectFormat::Sha1;
  const fs::path superproject_git_dir =
      root_absolute_error ? fs::path{} : core::resolve_git_dir(root, containment_root);
  if (!superproject_git_dir.empty())
  {
    core::Result<core::GitConfig> config = core::read_git_config(superproject_git_dir / "config");
    const std::string* origin_url = config.value.find("remote", "origin", "url");
    if (origin_url != nullptr)
    {
      origin_base = origin_resolution_base(*origin_url);
    }
    object_format = core::object_format_of(config.value);
  }

  // The superproject's gitlinks, read on first need only: a repository whose
  // submodules are all checked out never opens its index (T110).
  std::optional<std::vector<core::Gitlink>> superproject_gitlinks;
  const auto gitlink_commit_for = [&](const fs::path& relative_path) -> std::string
  {
    if (superproject_git_dir.empty())
    {
      return {};
    }
    if (!superproject_gitlinks)
    {
      core::Result<std::vector<core::Gitlink>> index =
          core::read_git_index_gitlinks(superproject_git_dir, object_format);
      for (core::Warning& warning : index.warnings)
      {
        result.warnings.push_back(std::move(warning));
      }
      superproject_gitlinks = std::move(index.value);
    }
    const std::string key = index_path_key(relative_path);
    const auto match = std::lower_bound(
        superproject_gitlinks->begin(), superproject_gitlinks->end(), key,
        [](const core::Gitlink& gitlink, const std::string& path) { return gitlink.path < path; });
    if (match == superproject_gitlinks->end() || match->path != key)
    {
      return {};
    }
    return match->commit;
  };

  append_submodule_components(
      modules.value, origin_base,
      [&](const fs::path& relative_path) -> PinnedCommit
      {
        if (root_absolute_error)
        {
          return {};
        }
        const fs::path submodule_git_dir =
            core::resolve_git_dir(root / relative_path, containment_root);
        if (!submodule_git_dir.empty())
        {
          std::string head = core::read_head_commit(submodule_git_dir);
          if (!head.empty())
          {
            return {std::move(head), PinSource::CheckedOutHead};
          }
        }
        std::string gitlink_commit = gitlink_commit_for(relative_path);
        if (!gitlink_commit.empty())
        {
          return {std::move(gitlink_commit), PinSource::SuperprojectIndex};
        }
        return {};
      },
      result);
  return result;
}

core::Result<std::vector<core::Component>> parse_bytes(std::string_view gitmodules_bytes)
{
  core::Result<std::vector<core::Component>> result;
  core::Result<core::GitConfig> modules =
      core::parse_git_config(gitmodules_bytes, std::string(kGitmodulesName));
  for (core::Warning& warning : modules.warnings)
  {
    result.warnings.push_back(std::move(warning));
  }
  append_submodule_components(
      modules.value, std::string{}, [](const fs::path&) { return PinnedCommit{}; }, result);
  return result;
}

}  // namespace bomwerk::parsers::cpp::submodules
