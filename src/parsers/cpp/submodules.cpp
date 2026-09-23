#include "parsers/cpp/submodules.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstddef>
#include <string>
#include <system_error>

#include "core/git_config.hpp"
#include "core/git_dir.hpp"
#include "core/git_url.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace fs = std::filesystem;

namespace bomwerk::parsers::cpp::submodules
{
namespace
{

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

}  // namespace

core::Result<std::vector<core::Component>> parse(const fs::path& root)
{
  core::Result<std::vector<core::Component>> result;

  const fs::path gitmodules_path = root / ".gitmodules";
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
  }

  std::size_t resolved_count = 0;
  std::size_t declared_count = 0;
  for (const core::GitConfigSection& section : modules.value.sections)
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

    const fs::path submodule_work_dir = root / relative_path;
    const fs::path submodule_git_dir =
        root_absolute_error ? fs::path{}
                            : core::resolve_git_dir(submodule_work_dir, containment_root);
    std::string commit;
    if (!submodule_git_dir.empty())
    {
      commit = core::read_head_commit(submodule_git_dir);
    }
    const bool resolved = !commit.empty();
    if (resolved)
    {
      ++resolved_count;
    }
    else
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

    // Dogfood core::Purl: a purl we cannot parse back is a bug in the builder,
    // not merely degraded input: surface it so tests and fuzzers catch it.
    const core::Result<core::Purl> validated = core::Purl::parse(component.purl);
    if (!validated.complete)
    {
      result.warn(core::WarningCode::kPurlValidationFailed, "submodule '" + relative_path.string() +
                                                                "' produced an unparsable purl '" +
                                                                component.purl + "'");
    }

    const core::Confidence declared_confidence =
        resolved ? core::Confidence::High : core::Confidence::Low;
    component.evidence.push_back(
        {core::Source::Manifest, ".gitmodules -> " + declared_name, declared_confidence});
    if (resolved)
    {
      component.evidence.push_back({core::Source::Manifest,
                                    relative_path.string() + "/.git -> HEAD",
                                    core::Confidence::High});
    }
    if (branch_value != nullptr && !branch_value->empty())
    {
      component.evidence.push_back({core::Source::Manifest,
                                    ".gitmodules -> " + declared_name + " branch=" + *branch_value,
                                    declared_confidence});
    }

    spdlog::debug("submodule {} -> {} ({})", relative_path.string(), component.purl,
                  resolved ? "resolved" : "uninitialized");
    result.value.push_back(std::move(component));
  }

  // Deterministic order (rule 3); merge in scan re-sorts, but a producer should
  // be self-consistent regardless of the caller.
  std::sort(result.value.begin(), result.value.end(),
            [](const core::Component& left, const core::Component& right)
            { return left.purl < right.purl; });

  spdlog::debug("parsed .gitmodules: {} submodules, {}/{} commits resolved", result.value.size(),
                resolved_count, declared_count);
  return result;
}

}  // namespace bomwerk::parsers::cpp::submodules
