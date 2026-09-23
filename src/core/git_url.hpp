#pragma once
#include <string>

#include "core/percent.hpp"

namespace bomwerk::core
{

/// A git remote URL reduced to host / owner / repo, with the scheme, any
/// userinfo, a trailing ".git" and trailing slashes removed. `host` is empty
/// when the input is not a recognizable URL (e.g. an unresolved relative path),
/// which callers use to fall back to a generic purl.
struct GitRemote
{
  std::string host;   ///< lower-cased, e.g. "github.com"
  std::string owner;  ///< namespace, e.g. "microsoft"; may contain '/' (gitlab subgroups)
  std::string repo;   ///< last path segment, e.g. "vcpkg"
};

/// Reduce a git remote URL to host/owner/repo. Handles `https://`, `http://`,
/// `git://`, `ssh://[user@]host/…` and the scp-like `git@host:owner/repo` form;
/// drops userinfo, a trailing ".git" and trailing slashes. Never throws; an
/// unrecognized input yields an all-empty result.
[[nodiscard]] GitRemote parse_git_remote(const std::string& url);

/// Resolve a submodule URL that may be relative (`./`, `../`) against the
/// superproject's remote URL, mirroring git: each leading `../` drops the last
/// path segment of `base`. Absolute URLs are returned unchanged. If `relative`
/// is relative but `base` is empty, `relative` is returned unchanged (the
/// caller then warns and emits a generic purl).
[[nodiscard]] std::string resolve_relative_url(const std::string& base,
                                               const std::string& relative);

/// Build a Package URL string for a VCS component pinned at `commit`. Known
/// forges map to their purl type with a lower-cased namespace/name:
/// `pkg:github/<owner>/<repo>@<commit>` (also gitlab, bitbucket). Anything else
/// becomes `pkg:generic/<repo>@<commit>?vcs_url=git%2B<percent-encoded-url>`.
/// When no repo name is recoverable from `url` (e.g. an unresolved `${VAR}`),
/// the generic purl uses `fallback_name`: the name the caller's manifest
/// declared: and only an empty `fallback_name` degrades to "unknown".
/// An empty `commit` (uninitialized submodule) omits the `@<version>`. A
/// `commit` that is a git object id is lower-cased (`core::normalized_object_id`)
/// so the same commit written in capitals by one manifest and in lower case by
/// another stays one identity; a tag is operator text and stays byte-exact. The
/// result is meant to be validated/canonicalized by `core::Purl`. Deterministic.
[[nodiscard]] std::string build_git_purl(const std::string& url, const std::string& commit,
                                         const std::string& fallback_name);

}  // namespace bomwerk::core
