#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"
#include "vuln/http.hpp"
#include "vuln/osv.hpp"

using bomwerk::core::Component;
using bomwerk::core::Result;
using bomwerk::test::TempTree;
using nlohmann::json;
namespace vuln = bomwerk::vuln;
namespace core = bomwerk::core;

namespace
{

constexpr std::int64_t kNow = 1'750'000'000;
constexpr std::int64_t kOneDaySeconds = 24 * 60 * 60;

// A purl-query-path stand-in: not conan/vcpkg/generic, not a hex-shaped
// version, so it exercises the `package.purl` query path (the shape a
// future M2 lockfile ecosystem: npm, PyPI, …: would use). Not a claim
// that bomwerk parses npm today.
constexpr const char* kEcosystemPurl = "pkg:npm/example-lib@1.2.3";
constexpr const char* kEcosystemResponse =
    R"({"results":[{"vulns":[{"id":"CVE-2022-37434","modified":"2024-01-01T00:00:00Z"}]}]})";

// The commit-query path: a real, verified example. This exact commit
// predates HarfBuzz's fix for CVE-2023-25193 (and two others) and is OSV's
// own documented example commit for demonstrating commit-based querying :
// confirmed directly against the live API while building this test.
constexpr const char* kHarfbuzzCommitSha = "6879efc2c1596d11a6a6ad296f80063b558d5e0f";
constexpr const char* kHarfbuzzPurl =
    "pkg:github/harfbuzz/harfbuzz@6879efc2c1596d11a6a6ad296f80063b558d5e0f";
constexpr const char* kHarfbuzzResponse =
    R"({"results":[{"vulns":[{"id":"CVE-2023-25193"},{"id":"CVE-2026-22693"},)"
    R"({"id":"OSV-2020-484"}]}]})";

// Coverage regression fixture: the same commit sha, but on a `pkg:generic` purl :
// the shape a submodule with no resolvable origin URL, or vendored code with
// no upstream, actually emits. Before the gate-ordering fix this was
// counted as `components_without_osv_coverage` and never queried at all,
// despite OSV's commit index matching it exactly like the github form above.
constexpr const char* kGenericCommitPurl =
    "pkg:generic/vendored-lib@6879efc2c1596d11a6a6ad296f80063b558d5e0f";

Component component_with_purl(const std::string& purl)
{
  Component component;
  component.purl = purl;
  return component;
}

/// Canned transport: counts calls, records the last request, replies with a
/// fixed status and body. status_code == 0 simulates an unreachable host.
///
/// Two OSV endpoints are routed: `/v1/querybatch` (detection) is answered with
/// `response_body`; `/v1/query` (the severity-hydration call, made once per
/// vulnerable purl) is answered with `severity_body`, which defaults to "no
/// severity" so a test that does not care about scores is unaffected.
///
/// A querybatch request carrying `"page_token"` (a pagination follow-up)
/// is instead answered with `page_two_body` when non-empty: otherwise it
/// falls through to `response_body` like any other querybatch call, which is
/// what makes every pre-bulk-feed scenario below correct without modification (a
/// canned page-1 response that happens to carry its own `next_page_token`
/// just gets echoed back verbatim on a follow-up, since no test relies on the
/// follow-up's CONTENT unless it explicitly sets `page_two_body`).
/// `match_components` may now call `as_function()`'s returned lambda
/// concurrently from several worker threads (bounded hydration/detection
/// fan-out). Every counter/string below is guarded by `state_mutex` so those
/// calls stay race-free; `in_flight`/`peak_in_flight` are plain atomics
/// (incremented/decremented outside the lock) so a test can assert how many
/// calls genuinely overlapped, and `artificial_delay` widens the overlap
/// window enough for that to be observable instead of racy-in-theory-only.
struct FakeTransport
{
  long status_code = 200;
  std::string response_body;
  std::string page_two_body;   //: served only to a page_token request
  bool fail_page_two = false;  //: a page_token request fails, independent of `status_code`
  std::string severity_body = R"({"vulns":[]})";  // default: hydration finds no CVSS
  int call_count = 0;                             // total across both endpoints
  int detect_calls = 0;                           // /v1/querybatch only
  int query_calls = 0;                            // /v1/query (severity) only
  int page_two_calls = 0;                         //: page_token requests specifically
  std::string last_request_url;
  std::string last_request_body;
  std::string last_detect_body;  // last /v1/querybatch body (survives hydration calls)

  // Concurrency-observation knobs, unused by any earlier test.
  std::chrono::milliseconds artificial_delay{0};
  std::atomic<int> in_flight{0};
  std::atomic<int> peak_in_flight{0};

  std::mutex state_mutex;

  vuln::HttpPostFunction as_function()
  {
    return [this](const vuln::HttpRequest& request) -> Result<vuln::HttpResponse>
    {
      const int now_in_flight = ++in_flight;
      int previous_peak = peak_in_flight.load();
      while (now_in_flight > previous_peak &&
             !peak_in_flight.compare_exchange_weak(previous_peak, now_in_flight))
      {
      }
      if (artificial_delay.count() > 0)
      {
        std::this_thread::sleep_for(artificial_delay);
      }

      const std::lock_guard<std::mutex> lock(state_mutex);
      ++call_count;
      last_request_url = request.url;
      last_request_body = request.body;
      const bool is_detect = request.url == std::string(vuln::kOsvQueryBatchUrl);
      const bool is_page_two_request =
          is_detect && request.body.find("page_token") != std::string::npos;
      if (is_detect)
      {
        ++detect_calls;
        last_detect_body = request.body;
      }
      else
      {
        ++query_calls;
      }
      Result<vuln::HttpResponse> result;
      if (is_page_two_request)
      {
        ++page_two_calls;
        if (fail_page_two)
        {
          --in_flight;
          result.warn(core::WarningCode::kVulnHttpRequestFailed,
                      "transport unreachable (test, page two)");
          return result;
        }
      }
      if (status_code == 0)
      {
        --in_flight;
        result.warn(core::WarningCode::kVulnHttpRequestFailed, "transport unreachable (test)");
        return result;
      }
      result.value.status_code = status_code;
      result.value.body = !is_detect                                      ? severity_body
                          : is_page_two_request && !page_two_body.empty() ? page_two_body
                                                                          : response_body;
      --in_flight;
      return result;
    };
  }
};

/// The advisory ids of a hit, in the hit's own (worst-severity-first) order.
std::vector<std::string> ids_of(const vuln::VulnerabilityHit& hit)
{
  std::vector<std::string> ids;
  ids.reserve(hit.advisories.size());
  for (const bomwerk::core::ScoredAdvisory& advisory : hit.advisories)
  {
    ids.push_back(advisory.id);
  }
  return ids;
}

std::function<std::int64_t()> fixed_clock(std::int64_t now_epoch_seconds)
{
  return [now_epoch_seconds] { return now_epoch_seconds; };
}

vuln::MatchOptions options_with_cache(const TempTree& tree)
{
  vuln::MatchOptions options;
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

}  // namespace

int main()
{
  // Given assorted purls, when asked whether they are queryable, then only
  // purl-shaped strings carrying a resolved @version qualify: and qualifiers
  // or subpaths never masquerade as versions.
  {
    BOMWERK_TEST_CHECK(vuln::is_queryable_purl("pkg:conan/zlib@1.2.11"));
    BOMWERK_TEST_CHECK(vuln::is_queryable_purl("pkg:github/microsoft/vcpkg@0123abc"));
    BOMWERK_TEST_CHECK(vuln::is_queryable_purl("pkg:conan/zlib@1.2.11?os=linux"));
    BOMWERK_TEST_CHECK(!vuln::is_queryable_purl("pkg:vcpkg/zlib"));
    BOMWERK_TEST_CHECK(!vuln::is_queryable_purl("pkg:vcpkg/zlib@"));
    BOMWERK_TEST_CHECK(!vuln::is_queryable_purl("pkg:vcpkg/zlib?arch=x64#sub@dir"));
    BOMWERK_TEST_CHECK(!vuln::is_queryable_purl("zlib@1.2.11"));
    BOMWERK_TEST_CHECK(!vuln::is_queryable_purl(""));
  }

  // Given assorted purl types, when asked whether OSV has any ecosystem
  // coverage for them, then only Conan/vcpkg/generic are flagged as
  // structurally uncoverable: verified against OSV's own ecosystem list,
  // not inferred from a failed query: UNLESS the version is a resolved
  // commit id, in which case OSV's commit index covers it regardless
  // of type, same as a commit-pinned github purl.
  {
    BOMWERK_TEST_CHECK(vuln::has_no_known_osv_coverage("pkg:conan/zlib@1.2.11"));
    BOMWERK_TEST_CHECK(vuln::has_no_known_osv_coverage("pkg:vcpkg/zlib@1.3.1"));
    BOMWERK_TEST_CHECK(vuln::has_no_known_osv_coverage("pkg:generic/foo@1.0?checksum=abc"));
    BOMWERK_TEST_CHECK(!vuln::has_no_known_osv_coverage(kHarfbuzzPurl));
    BOMWERK_TEST_CHECK(!vuln::has_no_known_osv_coverage(kEcosystemPurl));
    BOMWERK_TEST_CHECK(!vuln::has_no_known_osv_coverage(""));
    BOMWERK_TEST_CHECK(!vuln::has_no_known_osv_coverage(kGenericCommitPurl));

    // Given an UNVERSIONED Conan/vcpkg/generic purl (a bare manifest
    // dependency), when asked, then this returns false: it classifies as
    // `UnversionedPurl`, not `UnmappedPurlType` (core::classify_match_coverage
    // checks version-presence before type). This is a narrower contract than
    // earlier (which was purely type-based); pinned here so a future caller
    // relying on the old, type-only meaning notices via a failing test rather
    // than a silent behavior change. `is_queryable_purl` is what answers "no
    // resolved version" for this same input.
    BOMWERK_TEST_CHECK(!vuln::has_no_known_osv_coverage("pkg:conan/openssl"));
    BOMWERK_TEST_CHECK(!vuln::has_no_known_osv_coverage("pkg:vcpkg/zlib"));
    BOMWERK_TEST_CHECK(!vuln::is_queryable_purl("pkg:conan/openssl"));
  }

  // Given the known-vulnerable, commit-pinned github purl and OSV answering
  // real HarfBuzz CVEs, when matched, then the hits surface exactly those
  // ids AND the request was a commit query, not a purl query: the acceptance
  // check in hermetic form (fake transport, throwaway cache), exercising
  // the only query shape that has real coverage for a git-pinned C/C++
  // dependency today.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = kHarfbuzzResponse;
    // Hydration answer: one of the three advisories carries a CVSS v3 vector
    // scoring 9.8 (Critical); the other two stay unscored (Unknown).
    transport.severity_body = R"({"vulns":[{"id":"CVE-2023-25193","severity":[{"type":"CVSS_V3",)"
                              R"("score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]})";
    const std::vector<Component> components{component_with_purl(kHarfbuzzPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.warnings.empty());
    // One detection (querybatch) call plus one severity (query) hydration call.
    BOMWERK_TEST_CHECK(transport.detect_calls == 1);
    BOMWERK_TEST_CHECK(transport.query_calls == 1);
    BOMWERK_TEST_CHECK(
        transport.last_detect_body.find("\"commit\":\"" + std::string(kHarfbuzzCommitSha) + "\"") !=
        std::string::npos);
    BOMWERK_TEST_CHECK(transport.last_detect_body.find("\"purl\"") == std::string::npos);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.hits[0].purl == kHarfbuzzPurl);
    // Advisories are worst-first: the scored 9.8 leads, the two unscored follow
    // in id order.
    BOMWERK_TEST_CHECK(
        ids_of(matches.value.hits[0]) ==
        (std::vector<std::string>{"CVE-2023-25193", "CVE-2026-22693", "OSV-2020-484"}));
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories[0].id == "CVE-2023-25193");
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories[0].severity.has_score);
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories[0].severity.score > 9.7 &&
                       matches.value.hits[0].advisories[0].severity.score < 9.9);
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories[0].severity.rating ==
                       bomwerk::core::SeverityRating::Critical);
    BOMWERK_TEST_CHECK(!matches.value.hits[0].advisories[1].severity.has_score);
    BOMWERK_TEST_CHECK(matches.value.components_without_osv_coverage == 0);
  }

  // Given a component whose purl has a resolved version but a package type
  // with no OSV ecosystem (Conan), when matched, then it is never queried at
  // all: no HTTP call, no warning (this is a structural fact, not a
  // problem): and is counted separately so "0 hits" cannot be read as
  // "checked, clean".
  {
    TempTree tree;
    FakeTransport transport;
    const std::vector<Component> components{component_with_purl("pkg:conan/zlib@1.2.11")};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.warnings.empty());
    BOMWERK_TEST_CHECK(transport.call_count == 0);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(matches.value.components_without_osv_coverage == 1);
  }

  // Given a component whose purl has an unmapped type (generic) BUT a
  // resolved 40-hex commit id for its version, when matched, then it IS
  // queried: by commit, not by purl: and is NOT counted as uncovered. This
  // is the coverage regression test: the query gate classifies by
  // `core::classify_match_coverage`, whose commit check runs before the
  // unmapped-type check, so a `pkg:generic@<sha>` submodule with no
  // resolvable origin URL gets the same commit-index coverage a
  // `pkg:github@<sha>` one does.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = kHarfbuzzResponse;
    const std::vector<Component> components{component_with_purl(kGenericCommitPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(transport.detect_calls == 1);
    BOMWERK_TEST_CHECK(
        transport.last_detect_body.find("\"commit\":\"" + std::string(kHarfbuzzCommitSha) + "\"") !=
        std::string::npos);
    BOMWERK_TEST_CHECK(transport.last_detect_body.find("\"purl\"") == std::string::npos);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.hits[0].purl == kGenericCommitPurl);
    BOMWERK_TEST_CHECK(matches.value.components_without_osv_coverage == 0);
  }

  // Given a mix of a commit-pinned github component, an ecosystem-purl
  // component, and a Conan component in the same scan, when matched, then
  // the batch queries only the first two (one by commit, one by purl) and
  // both come back correctly matched to their own purl by position, while
  // the Conan component is counted as uncovered rather than queried: the
  // real-world shape of a mixed-producer scan.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = R"({"results":[)" +
                              std::string(R"({"vulns":[{"id":"CVE-2023-25193"}]},)") +
                              R"({"vulns":[{"id":"CVE-2022-37434"}]})" + R"(]})";
    const std::vector<Component> components{component_with_purl(kHarfbuzzPurl),
                                            component_with_purl(kEcosystemPurl),
                                            component_with_purl("pkg:conan/zlib@1.2.11")};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    // One batched detection call; two components had hits, so two severity
    // hydration calls follow.
    BOMWERK_TEST_CHECK(transport.detect_calls == 1);
    BOMWERK_TEST_CHECK(transport.query_calls == 2);
    BOMWERK_TEST_CHECK(transport.last_detect_body.find(kHarfbuzzCommitSha) != std::string::npos);
    BOMWERK_TEST_CHECK(transport.last_detect_body.find(kEcosystemPurl) != std::string::npos);
    BOMWERK_TEST_CHECK(transport.last_detect_body.find("conan") == std::string::npos);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 2);
    BOMWERK_TEST_CHECK(matches.value.components_without_osv_coverage == 1);
  }

  // Given a fresh cache entry from a first match, when matching again within
  // the horizon, then zero HTTP calls and identical hits: the cache answers.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport first_transport;
    first_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree),
                                 first_transport.as_function(), fixed_clock(kNow));

    FakeTransport second_transport;  // would answer nothing useful: must not be called
    const auto matches =
        vuln::match_components(components, options_with_cache(tree), second_transport.as_function(),
                               fixed_clock(kNow + 3600));
    BOMWERK_TEST_CHECK(second_transport.call_count == 0);
    BOMWERK_TEST_CHECK(matches.warnings.empty());
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(matches.value.hits[0]) == std::vector<std::string>{"CVE-2022-37434"});
  }

  // Given an entry aged exactly the refresh horizon, when matched, then it
  // still answers from cache (entries refresh strictly OLDER than 24 h).
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport first_transport;
    first_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree),
                                 first_transport.as_function(), fixed_clock(kNow));

    FakeTransport second_transport;
    (void)vuln::match_components(components, options_with_cache(tree),
                                 second_transport.as_function(),
                                 fixed_clock(kNow + kOneDaySeconds));
    BOMWERK_TEST_CHECK(second_transport.call_count == 0);
  }

  // Given an entry one second past the horizon, when matched, then it is
  // re-fetched and the cache updated with the new answer.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport first_transport;
    first_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree),
                                 first_transport.as_function(), fixed_clock(kNow));

    FakeTransport refresh_transport;
    refresh_transport.response_body = R"({"results":[{}]})";  // now reported clean
    const auto refreshed = vuln::match_components(components, options_with_cache(tree),
                                                  refresh_transport.as_function(),
                                                  fixed_clock(kNow + kOneDaySeconds + 1));
    BOMWERK_TEST_CHECK(refresh_transport.call_count == 1);
    BOMWERK_TEST_CHECK(refreshed.value.hits.empty());

    FakeTransport third_transport;  // the refreshed "clean" answer must now be cached
    const auto cached_clean =
        vuln::match_components(components, options_with_cache(tree), third_transport.as_function(),
                               fixed_clock(kNow + kOneDaySeconds + 2));
    BOMWERK_TEST_CHECK(third_transport.call_count == 0);
    BOMWERK_TEST_CHECK(cached_clean.value.hits.empty());
  }

  // Given --offline and an empty cache, when matched, then no HTTP call, a
  // coverage warning, no hits: and the run stays complete (rule 1).
  {
    TempTree tree;
    FakeTransport transport;
    vuln::MatchOptions options = options_with_cache(tree);
    options.offline = true;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches =
        vuln::match_components(components, options, transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(transport.call_count == 0);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "--offline"));
  }

  // Given --offline and a stale cache entry, when matched, then the stale
  // data answers: offline, old knowledge beats none: with a warning.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport seed_transport;
    seed_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree), seed_transport.as_function(),
                                 fixed_clock(kNow));

    vuln::MatchOptions offline_options = options_with_cache(tree);
    offline_options.offline = true;
    FakeTransport offline_transport;
    const auto matches =
        vuln::match_components(components, offline_options, offline_transport.as_function(),
                               fixed_clock(kNow + 2 * kOneDaySeconds));
    BOMWERK_TEST_CHECK(offline_transport.call_count == 0);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(matches.value.hits[0]) == std::vector<std::string>{"CVE-2022-37434"});
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "--offline"));
  }

  // Given an HTTP 500, when matched, then a warning names the status, there
  // are no hits, and the run stays complete (rule 1: degrade, never crash).
  {
    TempTree tree;
    FakeTransport transport;
    transport.status_code = 500;
    transport.response_body = "internal error";
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "HTTP 500"));
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "coverage incomplete"));
  }

  // Given a transport that never reaches the host (status 0), when matched,
  // then the transport's own warning surfaces and the run stays complete.
  {
    TempTree tree;
    FakeTransport transport;
    transport.status_code = 0;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "transport unreachable"));
  }

  // Given a body that is not JSON, when matched, then the batch is discarded
  // with a warning: a hostile feed can degrade the run, never break it.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = "<html>totally not json</html>";
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "expected JSON shape"));
  }

  // Given pathologically deep response JSON, when matched, then the linear
  // depth pre-scan discards it before the recursive parser can see it :
  // never a stack overflow (rule 1).
  {
    TempTree tree;
    FakeTransport transport;
    std::string deep_body = R"({"results":)";
    deep_body.append(200, '[');
    deep_body.append(200, ']');
    deep_body += "}";
    transport.response_body = deep_body;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "expected JSON shape"));
  }

  // Given two queried purls but a results array answering only one, when
  // matched, then the answered purl still hits, the shortfall is warned
  // about, and the unanswered purl is reported as unresolved.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = R"({"results":[{"vulns":[{"id":"CVE-2000-0001"}]}]})";
    const std::vector<Component> components{component_with_purl("pkg:npm/aaa@1.0"),
                                            component_with_purl("pkg:npm/zzz@2.0")};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.hits[0].purl == "pkg:npm/aaa@1.0");
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "partial batch"));
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "coverage incomplete"));
  }

  // Given only version-less purls, when matched, then nothing is queried at
  // all: no HTTP call, no hits, no warnings (skipping is normal, not
  // degraded), and nothing is counted as "no OSV coverage" either (there is
  // no version to even classify).
  {
    TempTree tree;
    FakeTransport transport;
    const std::vector<Component> components{component_with_purl("pkg:vcpkg/zlib"),
                                            component_with_purl("")};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(matches.warnings.empty());
    BOMWERK_TEST_CHECK(transport.call_count == 0);
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(matches.value.components_without_osv_coverage == 0);
  }

  // Given a failed re-fetch but a stale cache entry, when matched, then the
  // stale entry answers (partial output beats none) with a warning saying so.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport seed_transport;
    seed_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree), seed_transport.as_function(),
                                 fixed_clock(kNow));

    FakeTransport failing_transport;
    failing_transport.status_code = 0;
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                failing_transport.as_function(),
                                                fixed_clock(kNow + 2 * kOneDaySeconds));
    // Detection fails and falls back to the stale detection cache (1 call); the
    // hit then triggers a severity hydration call, which also fails (1 call) and
    // falls back to the stale full-payload cache: 2 calls total.
    BOMWERK_TEST_CHECK(failing_transport.detect_calls == 1);
    BOMWERK_TEST_CHECK(failing_transport.query_calls == 1);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(matches.value.hits[0]) == std::vector<std::string>{"CVE-2022-37434"});
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "stale cache"));
  }

  // Given duplicate advisory ids and a pagination token in the answer, when
  // matched, then ids are deduplicated and sorted, and the truncation is
  // warned about exactly once.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body =
        R"({"results":[{"vulns":[{"id":"CVE-2022-37434"},{"id":"CVE-2018-25032"},)"
        R"({"id":"CVE-2022-37434"}],"next_page_token":"token"}]})";
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(matches.value.hits[0]) ==
                       (std::vector<std::string>{"CVE-2018-25032", "CVE-2022-37434"}));
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "paginated"));
  }

  // Given the same components in a different order across two runs, when
  // matched, then the hits are byte-identical (rule 3: deterministic output).
  {
    const char* two_purl_response =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0001"}]},{"vulns":[{"id":"CVE-2000-0002"}]}]})";

    TempTree first_tree;
    FakeTransport first_transport;
    first_transport.response_body = two_purl_response;
    const std::vector<Component> forward_order{component_with_purl("pkg:npm/aaa@1.0"),
                                               component_with_purl("pkg:npm/zzz@2.0")};
    const auto first_matches =
        vuln::match_components(forward_order, options_with_cache(first_tree),
                               first_transport.as_function(), fixed_clock(kNow));

    TempTree second_tree;
    FakeTransport second_transport;
    second_transport.response_body = two_purl_response;
    const std::vector<Component> reverse_order{component_with_purl("pkg:npm/zzz@2.0"),
                                               component_with_purl("pkg:npm/aaa@1.0")};
    const auto second_matches =
        vuln::match_components(reverse_order, options_with_cache(second_tree),
                               second_transport.as_function(), fixed_clock(kNow));

    BOMWERK_TEST_CHECK(first_matches.value.hits.size() == 2);
    BOMWERK_TEST_CHECK(second_matches.value.hits.size() == 2);
    for (std::size_t hit_index = 0; hit_index < first_matches.value.hits.size(); ++hit_index)
    {
      BOMWERK_TEST_CHECK(first_matches.value.hits[hit_index].purl ==
                         second_matches.value.hits[hit_index].purl);
      BOMWERK_TEST_CHECK(ids_of(first_matches.value.hits[hit_index]) ==
                         ids_of(second_matches.value.hits[hit_index]));
    }
    BOMWERK_TEST_CHECK(first_matches.value.hits[0].purl == "pkg:npm/aaa@1.0");
  }

  // CPE-fallback regression. Given the OSV path alone, when components are matched,
  // then every hit is PURL-EXACT and nothing is reported as CPE-checked: the
  // fallback is opt-in, and this pass must be unable to claim its coverage.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = kEcosystemResponse;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl),
                                            component_with_purl("pkg:conan/zlib@1.2.11")};

    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));

    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    for (const vuln::VulnerabilityHit& hit : matches.value.hits)
    {
      BOMWERK_TEST_CHECK(hit.provenance == vuln::MatchProvenance::PurlExact);
      BOMWERK_TEST_CHECK(vuln::is_high_confidence_provenance(hit.provenance));
    }
    // The conan component is still counted as structurally uncoverable...
    BOMWERK_TEST_CHECK(matches.value.components_without_osv_coverage == 1);
    // ...and this pass never marks anything as checked by the CPE fallback.
    BOMWERK_TEST_CHECK(matches.value.cpe_checked_purls.empty());
  }

  // Given a first run that discovers one advisory, when matched again
  // with an IDENTICAL feed answer, then the second run's deltas are empty :
  // `changed_purls` has nothing, `purls_unchanged` covers the purl, and
  // (critically) the severity/alias hydration call is skipped entirely. This
  // is the issue's Definition of Done ("feeds update idempotently") proven at
  // the OSV-client level: a stable purl costs one detection lookup and zero
  // hydration requests on every subsequent refresh.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport first_transport;
    first_transport.response_body = kEcosystemResponse;
    const auto first_matches = vuln::match_components(
        components, options_with_cache(tree), first_transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(first_transport.query_calls == 1);  // first sighting: hydrates once
    BOMWERK_TEST_CHECK(first_matches.value.deltas.changed_purls.size() == 1);
    BOMWERK_TEST_CHECK(first_matches.value.deltas.changed_purls[0].purl == kEcosystemPurl);
    BOMWERK_TEST_CHECK(first_matches.value.deltas.changed_purls[0].added_advisory_ids ==
                       std::vector<std::string>{"CVE-2022-37434"});

    // Past the horizon so detection re-fetches (never skips asking), but the
    // feed's answer is BYTE-IDENTICAL: same id, same `modified`.
    FakeTransport second_transport;
    second_transport.response_body = kEcosystemResponse;
    const auto second_matches =
        vuln::match_components(components, options_with_cache(tree), second_transport.as_function(),
                               fixed_clock(kNow + kOneDaySeconds + 1));
    BOMWERK_TEST_CHECK(second_transport.detect_calls == 1);
    BOMWERK_TEST_CHECK(second_transport.query_calls == 0);  // the idempotency win
    BOMWERK_TEST_CHECK(second_matches.value.deltas.changed_purls.empty());
    BOMWERK_TEST_CHECK(second_matches.value.deltas.purls_unchanged == 1);
    BOMWERK_TEST_CHECK(second_matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(second_matches.value.hits[0]) ==
                       std::vector<std::string>{"CVE-2022-37434"});
  }

  // Given a run that finds nothing, when matched again after the feed
  // gains a NEW advisory for the same purl, then the delta reports exactly
  // that id as added: never as modified, never conflated with the (absent)
  // previous state.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport clean_transport;
    clean_transport.response_body = R"({"results":[{}]})";
    (void)vuln::match_components(components, options_with_cache(tree),
                                 clean_transport.as_function(), fixed_clock(kNow));

    FakeTransport newly_vulnerable_transport;
    newly_vulnerable_transport.response_body = kEcosystemResponse;
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                newly_vulnerable_transport.as_function(),
                                                fixed_clock(kNow + kOneDaySeconds + 1));
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls[0].added_advisory_ids ==
                       std::vector<std::string>{"CVE-2022-37434"});
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls[0].removed_advisory_ids.empty());
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls[0].modified_advisory_ids.empty());
  }

  // Given a vulnerable purl, when the feed later reports it fixed (zero
  // advisories), then the delta reports the id as REMOVED and no hit is
  // produced: the "went clean" transition a finding-state machine needs.
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport first_transport;
    first_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree),
                                 first_transport.as_function(), fixed_clock(kNow));

    FakeTransport fixed_transport;
    fixed_transport.response_body = R"({"results":[{}]})";
    const auto matches =
        vuln::match_components(components, options_with_cache(tree), fixed_transport.as_function(),
                               fixed_clock(kNow + kOneDaySeconds + 1));
    BOMWERK_TEST_CHECK(matches.value.hits.empty());
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls[0].removed_advisory_ids ==
                       std::vector<std::string>{"CVE-2022-37434"});
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls[0].added_advisory_ids.empty());
  }

  // Given a stale (past-horizon) cache entry whose re-fetch FAILS, when
  // matched, then hydration still runs: a stale answer is never treated as
  // confirmation that nothing changed, no matter what its own `modified`
  // values say. (Same setup as the earlier "stale fallback" scenario above;
  // restated here as an explicit contract on `detection_confirmed_unchanged`
  // rather than an incidental byproduct of it.)
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    FakeTransport seed_transport;
    seed_transport.response_body = kEcosystemResponse;
    (void)vuln::match_components(components, options_with_cache(tree), seed_transport.as_function(),
                                 fixed_clock(kNow));

    FakeTransport failing_transport;
    failing_transport.status_code = 0;
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                failing_transport.as_function(),
                                                fixed_clock(kNow + 2 * kOneDaySeconds));
    BOMWERK_TEST_CHECK(failing_transport.query_calls == 1);
    BOMWERK_TEST_CHECK(matches.value.deltas.changed_purls.empty());  // the STORED snapshot is
                                                                     // unchanged (same stale ids) :
                                                                     // "stale" gates HYDRATION, not
                                                                     // detection's own delta math
  }

  // Given a hydration payload whose advisory carries `aliases` including
  // a CVE-shaped id, when matched, then the alias is captured on the
  // resulting `ScoredAdvisory`, sorted, and non-CVE-shaped aliases are
  // dropped: the join a CVE-keyed feed needs to match a GHSA-only OSV
  // finding, verified against real OSV data where every npm/PyPI/Go advisory
  // checked carries its CVE only in `aliases[]` (2026-08-23).
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = R"({"results":[{"vulns":[{"id":"GHSA-29mw-wpgm-hmr9"}]}]})";
    transport.severity_body =
        R"({"vulns":[{"id":"GHSA-29mw-wpgm-hmr9",)"
        R"("aliases":["CVE-2020-28500","GHSA-not-a-cve","CVE-2020-28500"]}]})";
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories.size() == 1);
    const std::vector<std::string> expected_aliases = {"CVE-2020-28500"};  // deduplicated, CVE-only
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories[0].cve_aliases == expected_aliases);
  }

  // Given an advisory with no `aliases` field at all, when matched, then
  // `cve_aliases` is empty: absence of a known alias, never fabricated.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body = kHarfbuzzResponse;
    transport.severity_body = R"({"vulns":[{"id":"CVE-2023-25193"}]})";
    const std::vector<Component> components{component_with_purl(kHarfbuzzPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(matches.value.hits[0].advisories[0].cve_aliases.empty());
  }

  // Given a querybatch answer whose result carries a `next_page_token`,
  // when matched with a transport that serves a genuinely DIFFERENT (and
  // complete, no further token) page 2, then a follow-up request is issued
  // carrying `page_token`, the merged advisory list includes ids from BOTH
  // pages, and no incompleteness warning fires: real, successful pagination,
  // not merely the token-detection this codebase had before the bulk feeds.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0001"}],"next_page_token":"page-2"}]})";
    transport.page_two_body = R"({"results":[{"vulns":[{"id":"CVE-2000-0002"}]}]})";
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(transport.page_two_calls == 1);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(matches.value.hits[0]) ==
                       (std::vector<std::string>{"CVE-2000-0001", "CVE-2000-0002"}));
    BOMWERK_TEST_CHECK(!warnings_mention(matches.warnings, "did not complete"));
  }

  // Given a server that echoes back the EXACT token it was just sent,
  // when matched, then pagination stops after ONE follow-up (a spin guard,
  // not the full round bound) and the incompleteness warning names it.
  {
    TempTree tree;
    FakeTransport transport;
    transport.response_body =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0001"}],"next_page_token":"stuck"}]})";
    // page_two_body left empty: EVERY querybatch call: page 1 and every
    // follow-up alike: answers with `response_body`, i.e. the SAME "stuck"
    // token forever, exactly the malfunctioning-server case under test.
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};
    const auto matches = vuln::match_components(components, options_with_cache(tree),
                                                transport.as_function(), fixed_clock(kNow));
    // One page-1 detect call plus exactly ONE follow-up before the repeated
    // token is caught: never kMaxOsvPaginationRounds worth of them.
    BOMWERK_TEST_CHECK(transport.detect_calls == 2);
    BOMWERK_TEST_CHECK(warnings_mention(matches.warnings, "did not complete"));
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(matches.value.hits[0]) == std::vector<std::string>{"CVE-2000-0001"});
  }

  // Bulk-feed regression. Given a purl with two KNOWN advisories, when a LATER
  // refresh's page 1 shows only one of them plus a next_page_token and the
  // follow-up request fails, then the missing advisory is NEVER reported as
  // "removed" (an incomplete answer must not be trusted as proof of removal :
  // rule 1) and hydration is NOT skipped for what page 1 did show. A third,
  // fully successful refresh then proves the "invisible" advisory truly
  // survived in the snapshot rather than having been silently deleted: it
  // reappears with its ORIGINAL `modified` value and is reported unchanged,
  // never as newly "added".
  {
    TempTree tree;
    const std::vector<Component> components{component_with_purl(kEcosystemPurl)};

    FakeTransport seed_transport;
    seed_transport.response_body =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0001","modified":"2026-01-01T00:00:00Z"},)"
        R"({"id":"CVE-2000-0002","modified":"2026-01-01T00:00:00Z"}]}]})";
    const auto seeded = vuln::match_components(components, options_with_cache(tree),
                                               seed_transport.as_function(), fixed_clock(kNow));
    BOMWERK_TEST_CHECK(seeded.value.deltas.changed_purls.size() == 1);

    FakeTransport truncated_transport;
    truncated_transport.response_body =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0001","modified":"2026-01-01T00:00:00Z"}],)"
        R"("next_page_token":"page-2"}]})";
    truncated_transport.fail_page_two = true;
    const auto truncated = vuln::match_components(components, options_with_cache(tree),
                                                  truncated_transport.as_function(),
                                                  fixed_clock(kNow + kOneDaySeconds + 1));
    BOMWERK_TEST_CHECK(warnings_mention(truncated.warnings, "did not complete"));
    // The bug this guards against: CVE-2000-0002 must not appear as removed
    // anywhere in this run's deltas: after clearing a truncated answer's
    // spurious removals, the only observed advisory (CVE-2000-0001) still
    // matches the stored snapshot exactly, so this purl is reclassified
    // "unchanged" rather than "CVE-2000-0002 removed".
    BOMWERK_TEST_CHECK(truncated.value.deltas.purls_unchanged == 1);
    for (const vuln::PurlAdvisoryDelta& delta : truncated.value.deltas.changed_purls)
    {
      BOMWERK_TEST_CHECK(delta.removed_advisory_ids.empty());
    }
    // Hydration for the purl must still have been attempted (not silently
    // skipped as "confirmed unchanged") despite CVE-2000-0001 alone matching
    // the stored snapshot exactly.
    BOMWERK_TEST_CHECK(truncated_transport.query_calls == 1);

    FakeTransport recovered_transport;
    recovered_transport.response_body =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0001","modified":"2026-01-01T00:00:00Z"}],)"
        R"("next_page_token":"page-2"}]})";
    recovered_transport.page_two_body =
        R"({"results":[{"vulns":[{"id":"CVE-2000-0002","modified":"2026-01-01T00:00:00Z"}]}]})";
    const auto recovered = vuln::match_components(components, options_with_cache(tree),
                                                  recovered_transport.as_function(),
                                                  fixed_clock(kNow + 2 * kOneDaySeconds + 2));
    BOMWERK_TEST_CHECK(recovered_transport.page_two_calls == 1);
    BOMWERK_TEST_CHECK(recovered.value.hits.size() == 1);
    BOMWERK_TEST_CHECK(ids_of(recovered.value.hits[0]) ==
                       (std::vector<std::string>{"CVE-2000-0001", "CVE-2000-0002"}));
    // CVE-2000-0002 comes back with its ORIGINAL `modified` value unchanged :
    // proof its snapshot row was preserved, not deleted-then-recreated: so
    // the WHOLE purl is reported unchanged this round, not "CVE-2000-0002
    // added" (which is exactly what would happen if round 2 had wrongly
    // deleted it).
    BOMWERK_TEST_CHECK(recovered.value.deltas.purls_unchanged == 1);
    for (const vuln::PurlAdvisoryDelta& delta : recovered.value.deltas.changed_purls)
    {
      BOMWERK_TEST_CHECK(delta.added_advisory_ids.empty());
      BOMWERK_TEST_CHECK(delta.removed_advisory_ids.empty());
    }
  }

  // Six distinct vulnerable ecosystem purls, one hit each. Given a
  // hydration fan-out bounded to 2 concurrent requests and an artificial
  // per-request delay (wide enough to force genuine overlap between worker
  // threads), when matched, then no more than 2 hydration/detection requests
  // are ever in flight at once, every purl is still hydrated exactly once
  // (no duplicate/dropped request), and the output is the same six hits in
  // purl-sorted order regardless of which worker thread happened to finish
  // first.
  {
    TempTree tree;
    std::vector<Component> components;
    json batch_results = json::array();
    for (int purl_index = 0; purl_index < 6; ++purl_index)
    {
      const std::string purl = "pkg:npm/concurrency-lib-" + std::to_string(purl_index) + "@1.0.0";
      components.push_back(component_with_purl(purl));
      json vuln_entry;
      vuln_entry["id"] = "CVE-2031-" + std::to_string(1000 + purl_index);
      json result_entry;
      result_entry["vulns"] = json::array({vuln_entry});
      batch_results.push_back(result_entry);
    }
    json response_document;
    response_document["results"] = batch_results;

    FakeTransport transport;
    transport.response_body = response_document.dump();
    transport.artificial_delay = std::chrono::milliseconds(20);
    vuln::MatchOptions options = options_with_cache(tree);
    options.max_osv_request_concurrency = 2;
    const auto matches =
        vuln::match_components(components, options, transport.as_function(), fixed_clock(kNow));

    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(transport.detect_calls == 1);  // 6 purls fit in one default-sized batch
    BOMWERK_TEST_CHECK(transport.query_calls == 6);   // one hydration request per vulnerable purl
    BOMWERK_TEST_CHECK(transport.peak_in_flight.load() <= 2);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 6);
    for (int purl_index = 0; purl_index < 6; ++purl_index)
    {
      BOMWERK_TEST_CHECK(matches.value.hits[static_cast<std::size_t>(purl_index)].purl ==
                         "pkg:npm/concurrency-lib-" + std::to_string(purl_index) + "@1.0.0");
    }
  }

  // The same six-purl scenario, but `max_osv_request_concurrency == 1`
  // (fully sequential, the earlier behavior) versus the default concurrency
  //: given identical inputs and cache state, when matched with each, then
  // the two runs produce byte-identical hits: concurrency changes wall-clock
  // behavior only, never the result (rule 3).
  {
    json batch_results = json::array();
    std::vector<Component> components;
    for (int purl_index = 0; purl_index < 4; ++purl_index)
    {
      const std::string purl = "pkg:npm/order-lib-" + std::to_string(purl_index) + "@2.0.0";
      components.push_back(component_with_purl(purl));
      json vuln_entry;
      vuln_entry["id"] = "CVE-2031-" + std::to_string(2000 + purl_index);
      json result_entry;
      result_entry["vulns"] = json::array({vuln_entry});
      batch_results.push_back(result_entry);
    }
    json response_document;
    response_document["results"] = batch_results;

    TempTree sequential_tree;
    FakeTransport sequential_transport;
    sequential_transport.response_body = response_document.dump();
    vuln::MatchOptions sequential_options = options_with_cache(sequential_tree);
    sequential_options.max_osv_request_concurrency = 1;
    const auto sequential_matches = vuln::match_components(
        components, sequential_options, sequential_transport.as_function(), fixed_clock(kNow));

    TempTree concurrent_tree;
    FakeTransport concurrent_transport;
    concurrent_transport.response_body = response_document.dump();
    vuln::MatchOptions concurrent_options = options_with_cache(concurrent_tree);
    concurrent_options.max_osv_request_concurrency = 8;
    const auto concurrent_matches = vuln::match_components(
        components, concurrent_options, concurrent_transport.as_function(), fixed_clock(kNow));

    BOMWERK_TEST_CHECK(sequential_transport.query_calls == 4);
    BOMWERK_TEST_CHECK(concurrent_transport.query_calls == 4);
    BOMWERK_TEST_CHECK(sequential_matches.value.hits.size() ==
                       concurrent_matches.value.hits.size());
    for (std::size_t hit_index = 0; hit_index < sequential_matches.value.hits.size(); ++hit_index)
    {
      BOMWERK_TEST_CHECK(sequential_matches.value.hits[hit_index].purl ==
                         concurrent_matches.value.hits[hit_index].purl);
      BOMWERK_TEST_CHECK(ids_of(sequential_matches.value.hits[hit_index]) ==
                         ids_of(concurrent_matches.value.hits[hit_index]));
    }
  }

  // Forcing multiple detection querybatch POSTs (one purl per batch)
  // exercises the DETECTION-side concurrent fan-out, not just hydration.
  // Given 4 purls with `max_queries_per_batch == 1` (four batches) and
  // `max_osv_request_concurrency == 2`, when matched, then all four batches
  // are still issued and merged correctly (four hits) and no more than 2
  // requests are ever in flight at once.
  {
    TempTree tree;
    std::vector<Component> components;
    for (int purl_index = 0; purl_index < 4; ++purl_index)
    {
      components.push_back(
          component_with_purl("pkg:npm/batch-lib-" + std::to_string(purl_index) + "@1.0.0"));
    }
    // One purl per querybatch request, so every batch's "results" is a
    // single-entry array; FakeTransport answers every querybatch call with
    // the SAME `response_body`, which is fine here since each batch expects
    // exactly one result back regardless of which purl it was for.
    FakeTransport transport;
    transport.response_body = R"({"results":[{"vulns":[{"id":"CVE-2031-3000"}]}]})";
    transport.artificial_delay = std::chrono::milliseconds(20);
    vuln::MatchOptions options = options_with_cache(tree);
    options.max_queries_per_batch = 1;
    options.max_osv_request_concurrency = 2;
    const auto matches =
        vuln::match_components(components, options, transport.as_function(), fixed_clock(kNow));

    BOMWERK_TEST_CHECK(matches.complete);
    BOMWERK_TEST_CHECK(transport.detect_calls == 4);
    BOMWERK_TEST_CHECK(transport.query_calls == 4);
    BOMWERK_TEST_CHECK(transport.peak_in_flight.load() <= 2);
    BOMWERK_TEST_CHECK(matches.value.hits.size() == 4);
  }

  return 0;
}
