#include <string>
#include <string_view>

#include "support/check.hpp"
#include "vuln/endpoints.hpp"

namespace vuln = bomwerk::vuln;

int main()
{
  // Given the endpoint registry, when it is inspected, then every entry is
  // fully described: `bomwerk --endpoints` is what a security team opens a
  // firewall from, so it must never print a blank name, URL or purpose.
  {
    BOMWERK_TEST_CHECK(vuln::kFeedEndpointCount > 0);
    for (const vuln::FeedEndpoint& endpoint : vuln::kFeedEndpoints)
    {
      BOMWERK_TEST_CHECK(!endpoint.name.empty());
      BOMWERK_TEST_CHECK(!endpoint.url.empty());
      BOMWERK_TEST_CHECK(!endpoint.purpose.empty());
      // Plain HTTP would expose which packages a customer builds with.
      BOMWERK_TEST_CHECK(endpoint.url.starts_with("https://"));
      // A registered URL carries no query string of its own; callers append one.
      BOMWERK_TEST_CHECK(endpoint.url.find('?') == std::string_view::npos);
    }
  }

  // Given each registered endpoint, when the allowlist is consulted, then its
  // pinned root is permitted. Fixed endpoints also accept query strings;
  // registry route roots accept validated path segments instead.
  {
    for (const vuln::FeedEndpoint& endpoint : vuln::kFeedEndpoints)
    {
      BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(endpoint.url));
      if (endpoint.allows_subpaths)
      {
        BOMWERK_TEST_CHECK(
            vuln::is_allowlisted_feed_url(std::string(endpoint.url) + "package/1.2.3/json"));
        BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url(std::string(endpoint.url) + "../admin"));
        BOMWERK_TEST_CHECK(
            !vuln::is_allowlisted_feed_url(std::string(endpoint.url) + "package/%2fadmin"));
        BOMWERK_TEST_CHECK(
            !vuln::is_allowlisted_feed_url(std::string(endpoint.url) + "package/1.0?redirect=x"));
      }
      else
      {
        BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(std::string(endpoint.url) + "?a=b&c=d"));
      }
    }
    // Representative URLs the production code actually names.
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(vuln::kOsvQueryBatchUrl));
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(vuln::kOsvQueryUrl));
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(vuln::kNvdCveApiUrl));
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(
        std::string(vuln::kCratesIoCrateVersionApiUrl) + "serde/1.0.219"));
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(std::string(vuln::kPyPiProjectVersionApiUrl) +
                                                     "requests/2.32.3/json"));
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(std::string(vuln::kRubyGemsVersionApiUrl) +
                                                     "rails/versions/8.0.2.json"));
  }

  // Given a URL that merely CONTAINS an allowlisted endpoint, when the
  // allowlist is consulted, then it is refused. This is the substring trap: a
  // naive `find() != npos` check would exfiltrate every query to the attacker's
  // host.
  {
    BOMWERK_TEST_CHECK(
        !vuln::is_allowlisted_feed_url("https://attacker.example/?u=https://api.osv.dev/v1/query"));
    BOMWERK_TEST_CHECK(
        !vuln::is_allowlisted_feed_url("https://attacker.example/https://api.osv.dev/v1/query"));
  }

  // Given a URL that merely STARTS WITH an allowlisted endpoint, when the
  // allowlist is consulted, then it is refused unless the very next character
  // begins a query string. This is the prefix trap: a look-alike host suffix or
  // an extra path segment must not inherit the parent's permission.
  {
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("https://api.osv.dev/v1/query.evil.example"));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("https://api.osv.dev/v1/query/../../admin"));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("https://api.osv.dev.evil.example/v1/query"));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url(
        "https://services.nvd.nist.gov/rest/json/cves/2.0.evil.example"));
  }

  // Given the OSV single-query endpoint, when the allowlist is consulted, then
  // it does not silently authorize `/v1/querybatch` (of which it is a prefix)
  // nor anything else that merely extends it. Each is registered on its own.
  {
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("https://api.osv.dev/v1/querybatchXXX"));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("https://api.osv.dev/v1/queryable"));
  }

  // Given a downgraded or otherwise unregistered scheme and host, when the
  // allowlist is consulted, then it is refused: the scheme is baked into each
  // registered URL rather than checked separately.
  {
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("http://api.osv.dev/v1/query"));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("https://nvd.nist.gov/rest/json/cves/2.0"));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url(""));
    BOMWERK_TEST_CHECK(!vuln::is_allowlisted_feed_url("api.osv.dev/v1/query"));
  }

  return 0;
}
