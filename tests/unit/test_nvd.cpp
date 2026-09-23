#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"
#include "vuln/endpoints.hpp"
#include "vuln/http.hpp"
#include "vuln/nvd.hpp"

using bomwerk::core::Component;
using bomwerk::core::Result;
using bomwerk::test::TempTree;
namespace vuln = bomwerk::vuln;
namespace core = bomwerk::core;

namespace
{

constexpr std::int64_t kNow = 1'750'000'000;
constexpr std::int64_t kOneDaySeconds = 24 * 60 * 60;

// A conan purl: versioned, and of a type with no OSV ecosystem at all, so it
// is exactly the class the CPE fallback exists for.
constexpr const char* kConanZlibPurl = "pkg:conan/zlib@1.2.11";

// The percent-encoded form of `cpe:2.3:a:*:zlib:1.2.11`, which is what a real
// request carries: pinned here so a change to either the CPE shape or the
// encoding has to be deliberate.
constexpr const char* kEncodedZlibCpe = "cpe%3A2.3%3Aa%3A%2A%3Azlib%3A1.2.11";

// A trimmed but structurally faithful CVE API 2.0 response, recorded from the
// live endpoint while building this feature: `virtualMatchString=
// cpe:2.3:a:*:zlib:1.2.11` really does return these CVEs, and CVE-2022-37434
// really does carry this CVSS v3.1 vector (9.8, Critical) from nvd@nist.gov.
constexpr const char* kZlibResponse = R"({
  "totalResults": 2,
  "vulnerabilities": [
    {"cve": {"id": "CVE-2022-37434", "metrics": {"cvssMetricV31": [
      {"source": "nvd@nist.gov", "type": "Primary",
       "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}}},
    {"cve": {"id": "CVE-2018-25032", "metrics": {"cvssMetricV31": [
      {"source": "nvd@nist.gov", "type": "Primary",
       "cvssData": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"}}]}}}
  ]
})";

constexpr const char* kEmptyResponse = R"({"totalResults": 0, "vulnerabilities": []})";

Component component_with_purl(const std::string& purl)
{
  Component component;
  component.purl = purl;
  return component;
}

/// Canned GET transport: counts calls, records every request, replies with a
/// fixed status and body. status_code == 0 simulates an unreachable host.
struct FakeTransport
{
  long status_code = 200;
  std::string response_body = kEmptyResponse;
  int call_count = 0;
  std::vector<std::string> requested_urls;
  std::vector<std::string> last_request_headers;

  vuln::HttpGetFunction as_function()
  {
    return [this](const vuln::HttpGetRequest& request) -> Result<vuln::HttpResponse>
    {
      ++call_count;
      requested_urls.push_back(request.url);
      last_request_headers = request.headers;
      Result<vuln::HttpResponse> result;
      if (status_code == 0)
      {
        result.warn(core::WarningCode::kVulnHttpRequestFailed, "transport unreachable (test)");
        return result;
      }
      result.value.status_code = status_code;
      result.value.body = response_body;
      return result;
    };
  }
};

/// Counting stand-in for the throttle: records what was asked for without ever
/// making a test wait.
struct FakeSleeper
{
  int call_count = 0;
  std::chrono::milliseconds total{0};
  std::chrono::milliseconds last{0};

  std::function<void(std::chrono::milliseconds)> as_function()
  {
    return [this](std::chrono::milliseconds interval)
    {
      ++call_count;
      total += interval;
      last = interval;
    };
  }
};

std::function<std::int64_t()> fixed_clock(std::int64_t now_epoch_seconds)
{
  return [now_epoch_seconds] { return now_epoch_seconds; };
}

vuln::NvdOptions options_with_cache(const TempTree& tree)
{
  vuln::NvdOptions options;
  options.cache_database_path = tree.root() / "vuln_cache.sqlite3";
  return options;
}

bool warnings_mention(const std::vector<core::Warning>& warnings, const std::string& needle)
{
  for (const core::Warning& warning : warnings)
  {
    if (warning.message.find(needle) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

bool any_mentions(const std::vector<std::string>& values, const std::string& needle)
{
  for (const std::string& value : values)
  {
    if (value.find(needle) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

}  // namespace

int main()
{
  // Given a conan component OSV cannot match, when NVD answers its CPE query,
  // then one lower-confidence hit carries the advisories worst-severity-first
  // with the CVSS scores parsed from the v3.1 vectors.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.response_body = kZlibResponse;

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options_with_cache(tree),
                            transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(outcome.value.hits[0].purl == kConanZlibPurl);
    BOMWERK_TEST_CHECK(outcome.value.hits[0].provenance == vuln::MatchProvenance::CpeFallback);
    BOMWERK_TEST_CHECK(!vuln::is_high_confidence_provenance(outcome.value.hits[0].provenance));
    BOMWERK_TEST_CHECK(outcome.value.hits[0].advisories.size() == 2);
    // Worst first: 9.8 Critical before 7.5 High.
    BOMWERK_TEST_CHECK(outcome.value.hits[0].advisories[0].id == "CVE-2022-37434");
    BOMWERK_TEST_CHECK(outcome.value.hits[0].advisories[0].severity.has_score);
    BOMWERK_TEST_CHECK(outcome.value.hits[0].advisories[0].severity.rating ==
                       bomwerk::core::SeverityRating::Critical);
    BOMWERK_TEST_CHECK(outcome.value.hits[0].advisories[1].id == "CVE-2018-25032");
    // The component was checked, and says so through the list every surface reads.
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.size() == 1);
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls[0] == kConanZlibPurl);
    // This pass never classifies OSV coverage: that is the OSV pass's fact.
    BOMWERK_TEST_CHECK(outcome.value.components_without_osv_coverage == 0);

    // The request went to the pinned NVD endpoint with the percent-encoded CPE.
    BOMWERK_TEST_CHECK(transport.call_count == 1);
    BOMWERK_TEST_CHECK(transport.requested_urls[0].starts_with(std::string(vuln::kNvdCveApiUrl)));
    BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(transport.requested_urls[0]));
    BOMWERK_TEST_CHECK(transport.requested_urls[0].find(std::string("virtualMatchString=") +
                                                        kEncodedZlibCpe) != std::string::npos);
    // A single request never waits: the throttle spaces requests, it does not
    // prefix them.
    BOMWERK_TEST_CHECK(sleeper.call_count == 0);
  }

  // Given a component OSV CAN match, when the CPE fallback runs, then no
  // request is made at all: sending it would only add false positives on top
  // of an exact match that already exists.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    const std::vector<Component> components = {
        component_with_purl("pkg:npm/left-pad@1.3.0"),
        component_with_purl("pkg:pypi/flask@3.0.0"),
        // Commit-pinned generic: OSV's commit index matches it, so coverage
        // classifies it Matched and it must not come here either.
        component_with_purl("pkg:generic/vendored@" + std::string(40, 'a')),
        // Version-less: classifies as UnversionedPurl, not UnmappedPurlType.
        component_with_purl("pkg:vcpkg/zlib"),
    };

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe(components, options_with_cache(tree), transport.as_function(),
                            fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(transport.call_count == 0);
    BOMWERK_TEST_CHECK(outcome.value.hits.empty());
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.empty());
  }

  // Given two uncached components, when they are queried, then the throttle
  // fires exactly once: between them, never before the first.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    const std::vector<Component> components = {component_with_purl(kConanZlibPurl),
                                               component_with_purl("pkg:vcpkg/openssl@3.2.0")};

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe(components, options_with_cache(tree), transport.as_function(),
                            fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(transport.call_count == 2);
    BOMWERK_TEST_CHECK(sleeper.call_count == 1);
    // Unauthenticated: NVD allows 5 requests per rolling 30 s.
    BOMWERK_TEST_CHECK(sleeper.last == vuln::kNvdIntervalWithoutApiKey);
  }

  // Given an API key, when components are queried, then it travels in the
  // request header and the faster interval is used: and it appears in NO
  // warning text, because a key leaked into a report is a leaked credential.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.status_code = 403;  // force the warning path
    vuln::NvdOptions options = options_with_cache(tree);
    options.api_key = "super-secret-key-value";
    const std::vector<Component> components = {component_with_purl(kConanZlibPurl),
                                               component_with_purl("pkg:vcpkg/openssl@3.2.0")};

    const Result<vuln::MatchOutcome> outcome = vuln::match_via_cpe(
        components, options, transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(
        any_mentions(transport.last_request_headers, "apiKey: super-secret-key-value"));
    BOMWERK_TEST_CHECK(sleeper.last == vuln::kNvdIntervalWithApiKey);
    BOMWERK_TEST_CHECK(!warnings_mention(outcome.warnings, "super-secret-key-value"));
    // The key must not reach the URL either: a query string lands in proxy logs.
    BOMWERK_TEST_CHECK(!any_mentions(transport.requested_urls, "super-secret-key-value"));
  }

  // Given a purl whose name cannot form a safe CPE, when the fallback runs,
  // then nothing is sent and the component is counted as unchecked rather than
  // silently dropped.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;

    const Result<vuln::MatchOutcome> outcome = vuln::match_via_cpe(
        {component_with_purl("pkg:conan/bad name@1.0")}, options_with_cache(tree),
        transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(transport.call_count == 0);
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.empty());
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "cannot form a safe CPE"));
  }

  // Given a fresh cache entry, when the same component is matched again, then
  // the cache answers: no request, no wait.
  {
    TempTree tree;
    const vuln::NvdOptions options = options_with_cache(tree);
    {
      FakeTransport transport;
      FakeSleeper sleeper;
      transport.response_body = kZlibResponse;
      const Result<vuln::MatchOutcome> first =
          vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options,
                              transport.as_function(), fixed_clock(kNow), sleeper.as_function());
      BOMWERK_TEST_CHECK(transport.call_count == 1);
      BOMWERK_TEST_CHECK(first.value.hits.size() == 1);
    }
    {
      FakeTransport transport;
      FakeSleeper sleeper;
      const Result<vuln::MatchOutcome> second =
          vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options,
                              transport.as_function(), fixed_clock(kNow), sleeper.as_function());
      BOMWERK_TEST_CHECK(transport.call_count == 0);
      BOMWERK_TEST_CHECK(sleeper.call_count == 0);
      BOMWERK_TEST_CHECK(second.value.hits.size() == 1);
      BOMWERK_TEST_CHECK(second.value.hits[0].advisories.size() == 2);
    }
  }

  // Given a cache entry older than the refresh horizon and a failing fetch,
  // when the component is matched, then the stale answer is used and said so :
  // partial output beats none (rule 1), but never silently.
  {
    TempTree tree;
    const vuln::NvdOptions options = options_with_cache(tree);
    {
      FakeTransport transport;
      FakeSleeper sleeper;
      transport.response_body = kZlibResponse;
      static_cast<void>(vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options,
                                            transport.as_function(), fixed_clock(kNow),
                                            sleeper.as_function()));
    }
    {
      FakeTransport transport;
      FakeSleeper sleeper;
      transport.status_code = 0;  // unreachable host
      const Result<vuln::MatchOutcome> outcome = vuln::match_via_cpe(
          {component_with_purl(kConanZlibPurl)}, options, transport.as_function(),
          fixed_clock(kNow + 2 * kOneDaySeconds), sleeper.as_function());

      BOMWERK_TEST_CHECK(outcome.complete);  // a feed problem degrades, never aborts
      BOMWERK_TEST_CHECK(transport.call_count == 1);
      BOMWERK_TEST_CHECK(outcome.value.hits.size() == 1);
      BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "older than the refresh horizon"));
    }
  }

  // Given no cached data and a failing fetch, when the component is matched,
  // then it is reported as still unchecked: never as checked-and-clean.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.status_code = 0;

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options_with_cache(tree),
                            transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.hits.empty());
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.empty());
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "remain unchecked"));
  }

  // Given an HTTP error status, when the component is matched, then the status
  // is named in a warning and the run still completes.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.status_code = 403;

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options_with_cache(tree),
                            transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "HTTP 403"));
    BOMWERK_TEST_CHECK(outcome.value.hits.empty());
  }

  // Given a malformed or hostile payload, when the component is matched, then
  // it degrades to a warning and never crashes (rule 1).
  {
    const std::vector<std::string> hostile_bodies = {
        "not json at all",
        "[]",
        R"({"vulnerabilities": "not an array"})",
        R"({"totalResults": 1})",  // no vulnerabilities key
        R"({"vulnerabilities": [{"cve": "not object"}]})",
        R"({"vulnerabilities": [{"cve": {"id": 42}}]})",  // id not a string
    };
    for (const std::string& body : hostile_bodies)
    {
      TempTree tree;
      FakeTransport transport;
      FakeSleeper sleeper;
      transport.response_body = body;

      const Result<vuln::MatchOutcome> outcome =
          vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options_with_cache(tree),
                              transport.as_function(), fixed_clock(kNow), sleeper.as_function());

      BOMWERK_TEST_CHECK(outcome.complete);
      BOMWERK_TEST_CHECK(outcome.value.hits.empty());
    }
  }

  // Given a well-formed answer with no advisories, when the component is
  // matched, then it counts as CHECKED with no hits: the whole point of the
  // fallback is that "checked, clean" becomes sayable for these components.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options_with_cache(tree),
                            transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.hits.empty());
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.size() == 1);
    BOMWERK_TEST_CHECK(outcome.warnings.empty());
  }

  // Given more advisories than one page holds, when the component is matched,
  // then the incompleteness is stated rather than hidden.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.response_body =
        R"({"totalResults": 5000, "vulnerabilities": [{"cve": {"id": "CVE-2022-37434"}}]})";

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options_with_cache(tree),
                            transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(outcome.complete);
    BOMWERK_TEST_CHECK(outcome.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "may be incomplete"));
  }

  // Given --offline, when components are matched, then the cache alone answers
  // and the network is never touched.
  {
    TempTree tree;
    vuln::NvdOptions options = options_with_cache(tree);
    {
      FakeTransport transport;
      FakeSleeper sleeper;
      transport.response_body = kZlibResponse;
      static_cast<void>(vuln::match_via_cpe({component_with_purl(kConanZlibPurl)}, options,
                                            transport.as_function(), fixed_clock(kNow),
                                            sleeper.as_function()));
    }
    options.offline = true;
    {
      FakeTransport transport;
      FakeSleeper sleeper;
      const std::vector<Component> components = {
          component_with_purl(kConanZlibPurl),
          component_with_purl("pkg:vcpkg/never-cached@1.0"),
      };
      // Well past the refresh horizon, so the cached entry is stale: offline,
      // old knowledge beats none, and the hole is stated too.
      const Result<vuln::MatchOutcome> outcome =
          vuln::match_via_cpe(components, options, transport.as_function(),
                              fixed_clock(kNow + 30 * kOneDaySeconds), sleeper.as_function());

      BOMWERK_TEST_CHECK(transport.call_count == 0);
      BOMWERK_TEST_CHECK(sleeper.call_count == 0);
      BOMWERK_TEST_CHECK(outcome.value.hits.size() == 1);
      BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "older than the refresh horizon"));
      BOMWERK_TEST_CHECK(warnings_mention(outcome.warnings, "remain unchecked"));
    }
  }

  // Given two components whose purls collapse to the SAME CPE, when they are
  // matched, then one request answers both and each purl gets its own hit.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.response_body = kZlibResponse;
    const std::vector<Component> components = {component_with_purl("pkg:conan/zlib@1.2.11"),
                                               component_with_purl("pkg:vcpkg/zlib@1.2.11")};

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe(components, options_with_cache(tree), transport.as_function(),
                            fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(transport.call_count == 1);
    BOMWERK_TEST_CHECK(outcome.value.hits.size() == 2);
    BOMWERK_TEST_CHECK(outcome.value.hits[0].purl == "pkg:conan/zlib@1.2.11");
    BOMWERK_TEST_CHECK(outcome.value.hits[1].purl == "pkg:vcpkg/zlib@1.2.11");
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.size() == 2);
  }

  // Given a component whose purl carries qualifiers, when it is matched, then
  // the query strips them but the RESULT is keyed by the purl verbatim: every
  // consumer joins on `Component::purl` as stored, so a stripped key here would
  // silently fail to tag the row it belongs to.
  {
    TempTree tree;
    FakeTransport transport;
    FakeSleeper sleeper;
    transport.response_body = kZlibResponse;
    const std::string qualified_purl = "pkg:conan/zlib@1.2.11?os=linux";

    const Result<vuln::MatchOutcome> outcome =
        vuln::match_via_cpe({component_with_purl(qualified_purl)}, options_with_cache(tree),
                            transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(transport.requested_urls.size() == 1);
    BOMWERK_TEST_CHECK(transport.requested_urls[0].find(std::string("virtualMatchString=") +
                                                        kEncodedZlibCpe) != std::string::npos);
    BOMWERK_TEST_CHECK(!any_mentions(transport.requested_urls, "os%3Dlinux"));
    BOMWERK_TEST_CHECK(outcome.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(outcome.value.hits[0].purl == qualified_purl);
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls.size() == 1);
    BOMWERK_TEST_CHECK(outcome.value.cpe_checked_purls[0] == qualified_purl);
  }

  // Given the same inputs in a different order, when they are matched, then the
  // output is identical: determinism does not depend on input order (rule 3).
  {
    const std::vector<Component> forward = {component_with_purl("pkg:conan/zlib@1.2.11"),
                                            component_with_purl("pkg:vcpkg/openssl@3.2.0"),
                                            component_with_purl("pkg:generic/libpng@1.6.40")};
    const std::vector<Component> reversed = {component_with_purl("pkg:generic/libpng@1.6.40"),
                                             component_with_purl("pkg:vcpkg/openssl@3.2.0"),
                                             component_with_purl("pkg:conan/zlib@1.2.11")};

    const auto matched_purl_order = [](const std::vector<Component>& components)
    {
      TempTree tree;
      FakeTransport transport;
      FakeSleeper sleeper;
      transport.response_body = kZlibResponse;
      const Result<vuln::MatchOutcome> outcome =
          vuln::match_via_cpe(components, options_with_cache(tree), transport.as_function(),
                              fixed_clock(kNow), sleeper.as_function());
      std::vector<std::string> purls;
      for (const vuln::VulnerabilityHit& hit : outcome.value.hits)
      {
        purls.push_back(hit.purl);
      }
      return purls;
    };

    const std::vector<std::string> forward_order = matched_purl_order(forward);
    BOMWERK_TEST_CHECK(forward_order.size() == 3);
    BOMWERK_TEST_CHECK(forward_order == matched_purl_order(reversed));
  }

  // Given two outcomes from the two feeds, when they are merged, then hits sort
  // by purl with the stronger provenance first, and the checked list is unioned
  //: so which thread finished first can never reach the output (rule 3).
  {
    vuln::MatchOutcome purl_outcome;
    purl_outcome.components_without_osv_coverage = 3;
    purl_outcome.hits.push_back({"pkg:npm/zeta@1.0", {}, vuln::MatchProvenance::PurlExact});
    purl_outcome.hits.push_back({"pkg:npm/alpha@1.0", {}, vuln::MatchProvenance::PurlExact});

    vuln::MatchOutcome cpe_outcome;
    cpe_outcome.hits.push_back({"pkg:conan/mid@1.0", {}, vuln::MatchProvenance::CpeFallback});
    cpe_outcome.hits.push_back({"pkg:npm/alpha@1.0", {}, vuln::MatchProvenance::CpeFallback});
    cpe_outcome.cpe_checked_purls = {"pkg:conan/mid@1.0", "pkg:conan/mid@1.0"};

    const vuln::MatchOutcome merged =
        vuln::merge_outcomes(std::move(purl_outcome), std::move(cpe_outcome));

    BOMWERK_TEST_CHECK(merged.hits.size() == 4);
    BOMWERK_TEST_CHECK(merged.hits[0].purl == "pkg:conan/mid@1.0");
    BOMWERK_TEST_CHECK(merged.hits[1].purl == "pkg:npm/alpha@1.0");
    // Same purl from both feeds: the purl-exact evidence leads.
    BOMWERK_TEST_CHECK(merged.hits[1].provenance == vuln::MatchProvenance::PurlExact);
    BOMWERK_TEST_CHECK(merged.hits[2].purl == "pkg:npm/alpha@1.0");
    BOMWERK_TEST_CHECK(merged.hits[2].provenance == vuln::MatchProvenance::CpeFallback);
    BOMWERK_TEST_CHECK(merged.hits[3].purl == "pkg:npm/zeta@1.0");
    BOMWERK_TEST_CHECK(merged.components_without_osv_coverage == 3);
    // Deduplicated, so a count taken from size() cannot overstate coverage.
    BOMWERK_TEST_CHECK(merged.cpe_checked_purls.size() == 1);
  }

  // Given the label table, when a provenance is rendered, then it matches the
  // lower-case hyphenated shape every other enum in the codebase uses.
  {
    BOMWERK_TEST_CHECK(std::string(vuln::to_string(vuln::MatchProvenance::PurlExact)) ==
                       "purl-exact");
    BOMWERK_TEST_CHECK(std::string(vuln::to_string(vuln::MatchProvenance::CpeFallback)) ==
                       "cpe-fallback");
    BOMWERK_TEST_CHECK(vuln::is_high_confidence_provenance(vuln::MatchProvenance::PurlExact));
    BOMWERK_TEST_CHECK(!vuln::is_high_confidence_provenance(vuln::MatchProvenance::CpeFallback));
  }

  return 0;
}
