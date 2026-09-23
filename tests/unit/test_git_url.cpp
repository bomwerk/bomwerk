// ctest unit test for git remote URL -> purl building
#include <cassert>
#include <cstdio>
#include <string>

#include "core/git_url.hpp"

using bomwerk::core::build_git_purl;
using bomwerk::core::GitRemote;
using bomwerk::core::parse_git_remote;
using bomwerk::core::percent_encode;
using bomwerk::core::resolve_relative_url;

int main()
{
  // Given an https remote with a .git suffix, when it is parsed, then host,
  // owner and repo come out clean.
  const GitRemote https_remote = parse_git_remote("https://github.com/microsoft/vcpkg.git");
  assert(https_remote.host == "github.com");
  assert(https_remote.owner == "microsoft");
  assert(https_remote.repo == "vcpkg");

  // Given an scp-like remote (git@host:owner/repo), when it is parsed, then it
  // is reduced the same way (userinfo dropped, ':' treated as the path start).
  const GitRemote scp_remote = parse_git_remote("git@github.com:acme/tool.git");
  assert(scp_remote.host == "github.com");
  assert(scp_remote.owner == "acme");
  assert(scp_remote.repo == "tool");

  // Given a gitlab subgroup path, when it is parsed, then the owner keeps the
  // nested namespace and repo is the last segment.
  const GitRemote subgroup_remote = parse_git_remote("https://gitlab.com/group/sub/proj.git");
  assert(subgroup_remote.host == "gitlab.com");
  assert(subgroup_remote.owner == "group/sub");
  assert(subgroup_remote.repo == "proj");

  // Given a URL without a .git suffix (mbedtls case), when parsed, repo is intact.
  const GitRemote no_suffix_remote = parse_git_remote("https://github.com/acme/nosuffix");
  assert(no_suffix_remote.repo == "nosuffix");

  // Given a github remote and a commit, when a purl is built, then it uses the
  // github type with a lower-cased namespace/name and the pinned commit.
  const std::string sha = "0123456789abcdef0123456789abcdef01234567";
  assert(build_git_purl("https://github.com/microsoft/vcpkg.git", sha, "") ==
         "pkg:github/microsoft/vcpkg@" + sha);
  assert(build_git_purl("https://github.com/Mbed-TLS/mbedtls.git", sha, "") ==
         "pkg:github/mbed-tls/mbedtls@" + sha);

  // Given no commit (uninitialized submodule), when a purl is built, then the
  // "@<version>" part is omitted.
  assert(build_git_purl("https://github.com/acme/thing.git", "", "") == "pkg:github/acme/thing");

  // Given a host we do not map, when a purl is built, then it is generic and
  // pins the exact URL in a percent-encoded vcs_url qualifier.
  const std::string generic = build_git_purl("https://example.com/x/y.git", sha, "");
  assert(generic ==
         "pkg:generic/y@" + sha + "?vcs_url=git%2Bhttps%3A%2F%2Fexample.com%2Fx%2Fy.git");

  // Given a URL that is an unresolved variable (no repo name recoverable), when
  // a purl is built with the manifest's declared name as fallback, then the
  // generic purl carries that declared name instead of "unknown".
  const std::string unresolved_url_purl =
      build_git_purl("${ZLIB_URL}", "${ZLIB_BRANCH}", "HDF5_ZLIB");
  assert(unresolved_url_purl.rfind("pkg:generic/HDF5_ZLIB@", 0) == 0);

  // Given the same unresolvable URL and an empty fallback name, when a purl is
  // built, then the name degrades to "unknown" as the last resort.
  const std::string no_fallback_purl = build_git_purl("${ZLIB_URL}", "", "");
  assert(no_fallback_purl.rfind("pkg:generic/unknown?vcs_url=", 0) == 0);

  // Given a URL whose repo name is recoverable, when a fallback name is also
  // supplied, then the URL-derived name still wins (the URL is authoritative).
  const std::string url_wins_purl = build_git_purl("https://example.com/x/y.git", sha, "declared");
  assert(url_wins_purl.rfind("pkg:generic/y@", 0) == 0);

  // Given a relative submodule URL and the superproject origin, when resolved,
  // then each "../" drops a path segment of the origin (git's rule).
  assert(
      resolve_relative_url("https://github.com/espressif/esp-idf", "../../kmackay/micro-ecc.git") ==
      "https://github.com/kmackay/micro-ecc.git");

  // Given an absolute URL, when "resolved", then it is returned unchanged; and
  // a relative URL with no base is left as-is.
  assert(resolve_relative_url("https://github.com/a/b", "https://github.com/c/d.git") ==
         "https://github.com/c/d.git");
  assert(resolve_relative_url("", "../x/y.git") == "../x/y.git");

  // Given text with reserved characters, when percent-encoded, then only
  // unreserved characters pass through.
  assert(percent_encode("git+https://a/b") == "git%2Bhttps%3A%2F%2Fa%2Fb");

  // ---- object-id case normalization ---------------------------------

  // Given the same commit spelled in capitals and in lower case, when purls are
  // built, then both yield one identity: an object id has a canonical case, so
  // a manifest's capitalization must not fork the artifact in two.
  const std::string upper_sha = "0123456789ABCDEF0123456789ABCDEF01234567";
  assert(build_git_purl("https://github.com/acme/thing.git", upper_sha, "") ==
         build_git_purl("https://github.com/acme/thing.git", sha, ""));
  assert(build_git_purl("https://github.com/acme/thing.git", upper_sha, "") ==
         "pkg:github/acme/thing@" + sha);

  // Given the same, on the generic vcs_url fallback path, then the object id is
  // lower-cased there too (both branches share one normalization).
  assert(build_git_purl("https://example.com/x/y.git", upper_sha, "") ==
         build_git_purl("https://example.com/x/y.git", sha, ""));

  // Given a tag that merely contains upper-case letters, when a purl is built,
  // then it is emitted byte-exact: only an object id has a canonical case, and
  // "v2.0-RC1" is operator text we must never rewrite.
  assert(build_git_purl("https://github.com/acme/thing.git", "v2.0-RC1", "") ==
         "pkg:github/acme/thing@v2.0-RC1");

  // Given a 64-hex SHA-256 object id in capitals, when a purl is built, then it
  // is normalized as well (git's other object-id length).
  const std::string upper_sha256(64, 'A');
  const std::string lower_sha256(64, 'a');
  assert(build_git_purl("https://github.com/acme/thing.git", upper_sha256, "") ==
         "pkg:github/acme/thing@" + lower_sha256);

  // Given hex-looking text of a length git never uses, when a purl is built,
  // then it is left exact: it is not an object id, so it has no canonical case.
  assert(build_git_purl("https://github.com/acme/thing.git", "ABCDEF", "") ==
         "pkg:github/acme/thing@ABCDEF");

  std::puts("test_git_url: OK");
  return 0;
}
