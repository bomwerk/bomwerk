#pragma once
#include <cstddef>
#include <iterator>
#include <span>
#include <string_view>

namespace bomwerk::vuln
{

/// The OSV.dev batch endpoint: used to detect which
/// purls have any advisory (cheap, batched; returns only id stubs).
inline constexpr std::string_view kOsvQueryBatchUrl = "https://api.osv.dev/v1/querybatch";

/// The OSV.dev single-query endpoint. `querybatch` returns only `{id}` stubs,
/// so each purl that has hits is re-queried here for the FULL advisory objects
/// (which carry the `severity` CVSS vectors).
inline constexpr std::string_view kOsvQueryUrl = "https://api.osv.dev/v1/query";

/// NVD's CVE API 2.0: the CPE-native feed. OSV's API has no CPE query
/// of any kind (`/v1/query` accepts only `commit`, `version`,
/// `package{name,ecosystem,purl}`), so a component whose purl type has no OSV
/// ecosystem can only be matched here. This host has no official mirror: when
/// it is unreachable the run degrades per rule 1 (warning, stale cache, exit 1)
/// rather than falling back to some other source of truth.
inline constexpr std::string_view kNvdCveApiUrl =
    "https://services.nvd.nist.gov/rest/json/cves/2.0";

/// Public package-registry APIs used only by `scan --license-fallback`.
/// These are route roots because the already-validated package name/version
/// form path segments; `FeedEndpoint::allows_subpaths` and the transport-side
/// allowlist constrain every dynamic suffix before a socket opens.
inline constexpr std::string_view kCratesIoCrateVersionApiUrl = "https://crates.io/api/v1/crates/";
inline constexpr std::string_view kPyPiProjectVersionApiUrl = "https://pypi.org/pypi/";
inline constexpr std::string_view kRubyGemsVersionApiUrl = "https://rubygems.org/api/v2/rubygems/";

/// One outbound endpoint bomwerk may contact, described well enough that a
/// customer's security team can open a firewall from `bomwerk --endpoints`
/// without reading the source.
struct FeedEndpoint
{
  std::string_view name;     ///< short label, e.g. "OSV querybatch"
  std::string_view url;      ///< exact URL, or pinned route root when allows_subpaths is true
  std::string_view purpose;  ///< one line: what bomwerk asks this host for
  bool allows_subpaths;      ///< safe package-coordinate path segments may follow url
};

/// **The** registry of every network connection bomwerk can make. This array is
/// the single source of truth for the pinned-host allowlist that defends against
/// feed spoofing / MITM:
/// `is_allowlisted_feed_url` is enforced inside the curl transport before any
/// socket opens, and `bomwerk --endpoints` prints this array plus anything registered
/// alongside it: so what the
/// security team is told and what the binary can reach cannot drift apart.
///
/// REVIEW RULE: a new outbound URL is a row in this table or it does not exist.
/// Never build a request URL from a string literal at a call site.
///
/// Customer source code never leaves the machine; the only thing
/// sent to these hosts is a package coordinate (a purl, a commit sha, or a CPE
/// match string). `--offline` makes every one of them unnecessary.
inline constexpr FeedEndpoint kFeedEndpoints[] = {
    {"OSV querybatch", kOsvQueryBatchUrl,
     "batched advisory detection for components with an OSV-supported ecosystem", false},
    {"OSV query", kOsvQueryUrl,
     "full advisory records (CVSS severity) for a component already known to be affected", false},
    {"NVD CVE API 2.0", kNvdCveApiUrl,
     "CPE-based advisory lookup for Conan/vcpkg/generic components OSV cannot match "
     "(--cpe-fallback only)",
     false},
    {"crates.io crate version API", kCratesIoCrateVersionApiUrl,
     "declared license for an exact Cargo package version (--license-fallback only)", true},
    {"PyPI project version API", kPyPiProjectVersionApiUrl,
     "declared license metadata for an exact Python package version (--license-fallback only)",
     true},
    {"RubyGems version API", kRubyGemsVersionApiUrl,
     "declared licenses for an exact gem version (--license-fallback only)", true},
};

inline constexpr std::size_t kFeedEndpointCount = std::size(kFeedEndpoints);

/// True when `url` names an endpoint in `kFeedEndpoints`.
///
/// Matching is deliberately NOT a raw substring or prefix test. Fixed
/// endpoints must either match exactly or be followed by `?` and a query
/// string. Registry route roots additionally accept only non-empty path
/// segments made from `[a-z0-9._+-]`, with `.` and `..` segments refused.
/// A naive prefix test would accept
/// `https://api.osv.dev/v1/query.attacker.example/…`, and a substring test
/// would accept `https://attacker.example/?u=https://api.osv.dev/v1/query` :
/// both are refused here. It also keeps `…/v1/query` from silently
/// authorizing `…/v1/querybatch`; each is registered on its own.
/// Endpoints contributed by a module composed on top of this library, registered once at
/// startup before any request is made. `is_allowlisted_feed_url` and `bomwerk --endpoints`
/// both read them, so a composed build cannot reach a host it does not also disclose. This
/// build registers none unless something calls `register_feed_endpoints`.
///
/// `endpoints` must name storage that outlives the process's requests (a `constexpr` table),
/// because only the views are kept.
void register_feed_endpoints(std::span<const FeedEndpoint> endpoints);

/// Everything registered so far, empty in a build that composes nothing.
[[nodiscard]] std::span<const FeedEndpoint> registered_feed_endpoints();

[[nodiscard]] bool is_allowlisted_feed_url(std::string_view url);

}  // namespace bomwerk::vuln
