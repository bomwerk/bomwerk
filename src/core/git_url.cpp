#include "core/git_url.hpp"

#include <cstddef>
#include <string_view>

#include "core/text.hpp"

namespace bomwerk::core
{
namespace
{

/// The forges mapped to a first-class purl type; anything else falls back to
/// `pkg:generic` with a vcs_url qualifier. Extending support to another forge
/// is one row here.
struct ForgeHost
{
  std::string_view host;       ///< lower-cased remote host
  std::string_view purl_type;  ///< purl type for that forge
};
constexpr ForgeHost kForgeHosts[] = {
    {"github.com", "github"}, {"gitlab.com", "gitlab"}, {"bitbucket.org", "bitbucket"}};

/// purl type for the forges we map to a first-class namespace; empty otherwise.
std::string forge_type_for_host(const std::string& host)
{
  for (const ForgeHost& forge : kForgeHosts)
  {
    if (host == forge.host)
    {
      return std::string(forge.purl_type);
    }
  }
  return {};
}

}  // namespace

GitRemote parse_git_remote(const std::string& url)
{
  GitRemote remote;
  const std::string working = trimmed(url);
  if (working.empty())
  {
    return remote;
  }

  // Reduce every recognized form to "host/owner/repo…"; anything else is left
  // for the generic fallback (host stays empty).
  std::string host_and_path;
  constexpr const char* kSchemeSeparator = "://";
  const std::size_t scheme_position = working.find(kSchemeSeparator);
  if (scheme_position != std::string::npos)
  {
    host_and_path = working.substr(scheme_position + 3);
  }
  else
  {
    // scp-like `[user@]host:owner/repo`: the first ':' separates host and path.
    const std::size_t colon_position = working.find(':');
    if (colon_position == std::string::npos)
    {
      return remote;
    }
    const std::string before_colon = working.substr(0, colon_position);
    const std::string after_colon = working.substr(colon_position + 1);
    host_and_path = before_colon + "/" + after_colon;
  }

  const std::size_t first_slash = host_and_path.find('/');
  std::string host_segment =
      (first_slash == std::string::npos) ? host_and_path : host_and_path.substr(0, first_slash);
  std::string path_segment =
      (first_slash == std::string::npos) ? std::string{} : host_and_path.substr(first_slash + 1);

  // Drop userinfo (`user@`) and any `:port` from the host.
  const std::size_t at_position = host_segment.find('@');
  if (at_position != std::string::npos)
  {
    host_segment = host_segment.substr(at_position + 1);
  }
  const std::size_t port_position = host_segment.find(':');
  if (port_position != std::string::npos)
  {
    host_segment = host_segment.substr(0, port_position);
  }
  remote.host = to_lower_ascii(host_segment);

  // Trim trailing slashes, then a single trailing ".git".
  while (!path_segment.empty() && path_segment.back() == '/')
  {
    path_segment.pop_back();
  }
  constexpr std::string_view kGitSuffix = ".git";
  if (path_segment.size() > kGitSuffix.size() && path_segment.ends_with(kGitSuffix))
  {
    path_segment.erase(path_segment.size() - kGitSuffix.size());
  }

  // Split into owner (everything before the last segment) and repo (the last).
  const std::size_t last_slash = path_segment.find_last_of('/');
  if (last_slash == std::string::npos)
  {
    remote.repo = path_segment;
  }
  else
  {
    remote.owner = path_segment.substr(0, last_slash);
    remote.repo = path_segment.substr(last_slash + 1);
  }
  return remote;
}

std::string resolve_relative_url(const std::string& base, const std::string& relative)
{
  const bool is_relative = relative.rfind("./", 0) == 0 || relative.rfind("../", 0) == 0;
  if (!is_relative || base.empty())
  {
    return relative;
  }

  std::string resolved_base = base;
  while (!resolved_base.empty() && resolved_base.back() == '/')
  {
    resolved_base.pop_back();
  }

  std::string remainder = relative;
  while (true)
  {
    if (remainder.rfind("./", 0) == 0)
    {
      remainder = remainder.substr(2);
    }
    else if (remainder.rfind("../", 0) == 0)
    {
      remainder = remainder.substr(3);
      const std::size_t last_slash = resolved_base.find_last_of('/');
      if (last_slash == std::string::npos)
      {
        break;  // no path segment left to drop; stop rather than corrupt the scheme
      }
      resolved_base.erase(last_slash);
    }
    else
    {
      break;
    }
  }

  if (resolved_base.empty())
  {
    return remainder;
  }
  return resolved_base + "/" + remainder;
}

std::string build_git_purl(const std::string& url, const std::string& commit,
                           const std::string& fallback_name)
{
  const GitRemote remote = parse_git_remote(url);
  const std::string forge_type = forge_type_for_host(remote.host);
  // One artifact must be one identity (rule 3): an object id spelled in capitals
  // is the same commit as its lower-case spelling. A tag is left exact: only an
  // object id has a canonical case to normalize to.
  const std::string version = normalized_object_id(commit);

  if (!forge_type.empty() && !remote.owner.empty() && !remote.repo.empty())
  {
    // Percent-encode each purl component so a value carrying a structural byte
    // (from a malformed manifest) can never produce an invalid purl.
    std::string purl = "pkg:" + forge_type + "/" +
                       percent_encode_purl_namespace(to_lower_ascii(remote.owner)) + "/" +
                       percent_encode(to_lower_ascii(remote.repo));
    if (!version.empty())
    {
      purl += "@" + percent_encode(version);
    }
    return purl;
  }

  // Generic fallback: prefer the repo name recovered from the URL, then the
  // caller's declared name, then "unknown"; pin the exact URL in a vcs_url
  // qualifier so two different remotes never collide.
  std::string name = remote.repo.empty() ? fallback_name : remote.repo;
  if (name.empty())
  {
    name = "unknown";
  }
  std::string purl = "pkg:generic/" + percent_encode(name);
  if (!version.empty())
  {
    purl += "@" + percent_encode(version);
  }
  purl += "?vcs_url=" + percent_encode("git+" + trimmed(url));
  return purl;
}

}  // namespace bomwerk::core
