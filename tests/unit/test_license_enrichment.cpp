#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <thread>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"
#include "vuln/endpoints.hpp"
#include "vuln/http.hpp"
#include "vuln/license_enrichment.hpp"

using bomwerk::core::Component;
using bomwerk::core::Result;
using bomwerk::test::TempTree;
using nlohmann::json;
namespace vuln = bomwerk::vuln;
namespace core = bomwerk::core;

namespace
{

constexpr std::int64_t kNow = 1'780'000'000;

Component component_with_purl(const std::string& purl, const std::string& license = {})
{
  Component component;
  component.purl = purl;
  component.license = license;
  return component;
}

struct FakeTransport
{
  std::map<std::string, std::string> response_by_url;
  std::string default_response = R"({"version":{"license":"MIT"}})";
  std::vector<std::string> requested_urls;
  std::chrono::milliseconds artificial_delay{0};
  std::atomic<int> in_flight{0};
  std::atomic<int> peak_in_flight{0};
  std::mutex state_mutex;

  /// Scripted per-URL response sequences, consumed front-first, for tests
  /// that need to model a 429-then-success (or 429-exhausted) sequence. A URL
  /// with no scripted responses left (or none at all) falls back to
  /// `response_by_url`/`default_response`, both always status 200.
  std::map<std::string, std::deque<vuln::HttpResponse>> scripted_responses_by_url;

  vuln::HttpGetFunction as_function()
  {
    return [this](const vuln::HttpGetRequest& request) -> Result<vuln::HttpResponse>
    {
      const int active_count = ++in_flight;
      int previous_peak = peak_in_flight.load();
      while (active_count > previous_peak &&
             !peak_in_flight.compare_exchange_weak(previous_peak, active_count))
      {
      }
      if (artificial_delay.count() > 0)
      {
        std::this_thread::sleep_for(artificial_delay);
      }

      Result<vuln::HttpResponse> result;
      {
        const std::lock_guard<std::mutex> lock(state_mutex);
        requested_urls.push_back(request.url);
        const auto scripted = scripted_responses_by_url.find(request.url);
        if (scripted != scripted_responses_by_url.end() && !scripted->second.empty())
        {
          result.value = scripted->second.front();
          scripted->second.pop_front();
        }
        else
        {
          result.value.status_code = 200;
          const auto response = response_by_url.find(request.url);
          result.value.body =
              response == response_by_url.end() ? default_response : response->second;
        }
      }
      --in_flight;
      return result;
    };
  }
};

/// Counting stand-in for the throttle, mirroring test_nvd.cpp's `FakeSleeper`
/// but mutex-guarded: unlike `match_via_cpe`'s single-threaded caller,
/// `enrich_component_licenses` may invoke `sleep_for` concurrently from the
/// crates.io pacing thread and from a PyPI/RubyGems worker's own 429 backoff.
struct FakeSleeper
{
  std::mutex state_mutex;
  int call_count = 0;
  std::vector<std::chrono::milliseconds> recorded_intervals;

  std::function<void(std::chrono::milliseconds)> as_function()
  {
    return [this](std::chrono::milliseconds interval)
    {
      const std::lock_guard<std::mutex> lock(state_mutex);
      ++call_count;
      recorded_intervals.push_back(interval);
    };
  }
};

std::function<void(std::chrono::milliseconds)> no_op_sleep()
{
  return [](std::chrono::milliseconds) {};
}

/// `fixed_clock` never advances, which is insufficient for exercising
/// a time budget's deadline check. Tracks milliseconds internally (rather
/// than losing sub-second remainders to integer-second sleeps like
/// `kCratesIoRequestInterval`'s 1100ms) so repeated `sleep_for` calls
/// deterministically simulate wall-clock passage without a real sleep.
struct AdvancingClock
{
  std::atomic<std::int64_t> epoch_milliseconds;

  explicit AdvancingClock(std::int64_t start_epoch_seconds)
      : epoch_milliseconds(start_epoch_seconds * 1000)
  {
  }

  std::function<std::int64_t()> now_function()
  {
    return [this] { return epoch_milliseconds.load() / 1000; };
  }

  std::function<void(std::chrono::milliseconds)> sleep_function()
  {
    return [this](std::chrono::milliseconds interval) { epoch_milliseconds += interval.count(); };
  }
};

vuln::LicenseEnrichmentOptions options_with_cache(const TempTree& tree)
{
  vuln::LicenseEnrichmentOptions options;
  options.cache_database_path = tree.root() / "vuln_cache.sqlite3";
  return options;
}

std::function<std::int64_t()> fixed_clock(std::int64_t now)
{
  return [now] { return now; };
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
  // Given one unlicensed component from each supported ecosystem, when the
  // registries answer, then exact-version metadata fills only empty licenses,
  // PyPI falls back from UNKNOWN to classifiers, and every URL is allowlisted.
  {
    TempTree tree;
    FakeTransport transport;
    const std::string cargo_url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "serde/1.0.219";
    const std::string pypi_url =
        std::string(vuln::kPyPiProjectVersionApiUrl) + "requests/2.32.3/json";
    const std::string gem_url =
        std::string(vuln::kRubyGemsVersionApiUrl) + "rails/versions/8.0.2.json";
    transport.response_by_url[cargo_url] = R"({"version":{"license":"MIT OR Apache-2.0"}})";
    transport.response_by_url[pypi_url] =
        R"({"info":{"license":"UNKNOWN","classifiers":["License :: OSI Approved :: MIT License","License :: OSI Approved :: Apache Software License"]}})";
    transport.response_by_url[gem_url] = R"({"licenses":["MIT","Apache-2.0","MIT"]})";

    std::vector<Component> components = {
        component_with_purl("pkg:cargo/Serde@1.0.219"),
        component_with_purl("pkg:pypi/requests@2.32.3"), component_with_purl("pkg:gem/rails@8.0.2"),
        component_with_purl("pkg:cargo/already-known@1.0.0", "BSD-3-Clause"),
        component_with_purl("pkg:npm/left-pad@1.3.0")};
    vuln::LicenseEnrichmentOptions options = options_with_cache(tree);
    options.max_request_concurrency = 1;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options, transport.as_function(), fixed_clock(kNow), no_op_sleep());

    BOMWERK_TEST_CHECK(enriched.complete);
    BOMWERK_TEST_CHECK(enriched.warnings.empty());
    BOMWERK_TEST_CHECK(enriched.value.candidate_components == 3);
    BOMWERK_TEST_CHECK(enriched.value.enriched_components == 3);
    BOMWERK_TEST_CHECK(enriched.value.fetched_answers == 3);
    BOMWERK_TEST_CHECK(components[0].license == "MIT OR Apache-2.0");
    BOMWERK_TEST_CHECK(components[1].license == "Apache Software License; MIT License");
    BOMWERK_TEST_CHECK(components[2].license == "Apache-2.0 OR MIT");
    BOMWERK_TEST_CHECK(components[3].license == "BSD-3-Clause");
    BOMWERK_TEST_CHECK(components[4].license.empty());
    BOMWERK_TEST_CHECK(transport.requested_urls.size() == 3);
    for (const std::string& url : transport.requested_urls)
    {
      BOMWERK_TEST_CHECK(vuln::is_allowlisted_feed_url(url));
    }
  }

  // Given a warm registry-license cache, when the same purl is enriched in
  // offline mode, then no transport call occurs and the cached license wins.
  {
    TempTree tree;
    FakeTransport online_transport;
    std::vector<Component> first_components = {component_with_purl("pkg:pypi/flask@3.1.0")};
    const std::string flask_url = std::string(vuln::kPyPiProjectVersionApiUrl) + "flask/3.1.0/json";
    online_transport.response_by_url[flask_url] =
        R"({"info":{"license_expression":"BSD-3-Clause"}})";
    const vuln::LicenseEnrichmentOptions online_options = options_with_cache(tree);
    const Result<vuln::LicenseEnrichmentSummary> first = vuln::enrich_component_licenses(
        first_components, online_options, online_transport.as_function(), fixed_clock(kNow),
        no_op_sleep());
    BOMWERK_TEST_CHECK(first.value.enriched_components == 1);

    FakeTransport offline_transport;
    std::vector<Component> second_components = {component_with_purl("pkg:pypi/flask@3.1.0")};
    vuln::LicenseEnrichmentOptions offline_options = options_with_cache(tree);
    offline_options.offline = true;
    const Result<vuln::LicenseEnrichmentSummary> second = vuln::enrich_component_licenses(
        second_components, offline_options, offline_transport.as_function(), fixed_clock(kNow),
        no_op_sleep());

    BOMWERK_TEST_CHECK(second.warnings.empty());
    BOMWERK_TEST_CHECK(second.value.fresh_cache_answers == 1);
    BOMWERK_TEST_CHECK(second.value.enriched_components == 1);
    BOMWERK_TEST_CHECK(second_components[0].license == "BSD-3-Clause");
    BOMWERK_TEST_CHECK(offline_transport.requested_urls.empty());
  }

  // Given a decoded coordinate containing a path separator and an unversioned
  // purl, when enrichment is requested, then both are counted and skipped
  // before the transport can see attacker-controlled structure.
  {
    TempTree tree;
    FakeTransport transport;
    std::vector<Component> components = {component_with_purl("pkg:pypi/good%2F..%2Fevil@1.0"),
                                         component_with_purl("pkg:cargo/no-version")};

    const Result<vuln::LicenseEnrichmentSummary> enriched =
        vuln::enrich_component_licenses(components, options_with_cache(tree),
                                        transport.as_function(), fixed_clock(kNow), no_op_sleep());

    BOMWERK_TEST_CHECK(enriched.value.candidate_components == 2);
    BOMWERK_TEST_CHECK(enriched.value.skipped_components == 2);
    BOMWERK_TEST_CHECK(transport.requested_urls.empty());
    BOMWERK_TEST_CHECK(warnings_mention(enriched.warnings, "unsafe registry name/version"));
  }

  // Given six independent PyPI cache misses and a concurrency limit of two,
  // when enriched, then requests genuinely overlap but never exceed the
  // bound and every component receives the deterministic answer. PyPI (not
  // crates.io) is used here specifically because crates.io no longer ever
  // overlaps with itself (see the dedicated crates.io tests below).
  {
    TempTree tree;
    FakeTransport transport;
    transport.default_response = R"({"info":{"license":"MIT"}})";
    transport.artificial_delay = std::chrono::milliseconds(20);
    std::vector<Component> components;
    for (int component_index = 0; component_index < 6; ++component_index)
    {
      components.push_back(component_with_purl("pkg:pypi/concurrency-" +
                                               std::to_string(component_index) + "@1.0.0"));
    }
    vuln::LicenseEnrichmentOptions options = options_with_cache(tree);
    options.max_request_concurrency = 2;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options, transport.as_function(), fixed_clock(kNow), no_op_sleep());

    BOMWERK_TEST_CHECK(enriched.value.enriched_components == 6);
    BOMWERK_TEST_CHECK(transport.requested_urls.size() == 6);
    BOMWERK_TEST_CHECK(transport.peak_in_flight.load() > 1);
    BOMWERK_TEST_CHECK(transport.peak_in_flight.load() <= 2);
    for (const Component& component : components)
    {
      BOMWERK_TEST_CHECK(component.license == "MIT");
    }
  }

  // Given four independent crates.io cache misses, when enriched, then
  // requests never overlap with each other (unlike PyPI/RubyGems above) and
  // the fake throttle records exactly one sleep of kCratesIoRequestInterval
  // between each pair of requests.
  {
    TempTree tree;
    FakeTransport transport;
    transport.artificial_delay = std::chrono::milliseconds(20);
    std::vector<Component> components;
    for (int component_index = 0; component_index < 4; ++component_index)
    {
      components.push_back(component_with_purl("pkg:cargo/sequential-" +
                                               std::to_string(component_index) + "@1.0.0"));
    }
    vuln::LicenseEnrichmentOptions options = options_with_cache(tree);
    FakeSleeper sleeper;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options, transport.as_function(), fixed_clock(kNow), sleeper.as_function());

    BOMWERK_TEST_CHECK(enriched.value.enriched_components == 4);
    BOMWERK_TEST_CHECK(transport.peak_in_flight.load() == 1);
    BOMWERK_TEST_CHECK(sleeper.call_count == 3);
    for (const std::chrono::milliseconds interval : sleeper.recorded_intervals)
    {
      BOMWERK_TEST_CHECK(interval == vuln::kCratesIoRequestInterval);
    }
  }

  // Given a crates.io lookup that answers 429 twice before succeeding, when
  // enriched, then the component is still enriched and the rate-limited
  // counter/warning stay untouched: only genuinely exhausted rate limiting
  // is reported.
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "flaky/1.0.0";
    vuln::HttpResponse too_many_requests;
    too_many_requests.status_code = 429;
    vuln::HttpResponse ok;
    ok.status_code = 200;
    ok.body = R"({"version":{"license":"MIT"}})";
    transport.scripted_responses_by_url[url] = {too_many_requests, too_many_requests, ok};
    std::vector<Component> components = {component_with_purl("pkg:cargo/flaky@1.0.0")};
    FakeSleeper sleeper;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options_with_cache(tree), transport.as_function(), fixed_clock(kNow),
        sleeper.as_function());

    BOMWERK_TEST_CHECK(enriched.value.fetched_answers == 1);
    BOMWERK_TEST_CHECK(enriched.value.rate_limited_components == 0);
    BOMWERK_TEST_CHECK(components[0].license == "MIT");
    BOMWERK_TEST_CHECK(!warnings_mention(enriched.warnings, "rate-limited by the registry"));
    BOMWERK_TEST_CHECK(sleeper.call_count == 2);
  }

  // Given a crates.io lookup that answers 429 on every attempt with no stale
  // cache entry, when enriched, then it is counted and warned about as
  // rate-limited, NOT as a genuine "no registry data" absence.
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "throttled/1.0.0";
    vuln::HttpResponse too_many_requests;
    too_many_requests.status_code = 429;
    transport.scripted_responses_by_url[url] = {too_many_requests, too_many_requests,
                                                too_many_requests};
    std::vector<Component> components = {component_with_purl("pkg:cargo/throttled@1.0.0")};
    FakeSleeper sleeper;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options_with_cache(tree), transport.as_function(), fixed_clock(kNow),
        sleeper.as_function());

    BOMWERK_TEST_CHECK(enriched.value.rate_limited_components == 1);
    BOMWERK_TEST_CHECK(enriched.value.unresolved_components == 0);
    BOMWERK_TEST_CHECK(components[0].license.empty());
    BOMWERK_TEST_CHECK(warnings_mention(enriched.warnings, "rate-limited by the registry"));
    BOMWERK_TEST_CHECK(!warnings_mention(enriched.warnings, "no registry data for"));
    BOMWERK_TEST_CHECK(sleeper.call_count == 2);
  }

  // Given a 429 response carrying a `Retry-After` value, when retried, then
  // the fake throttle is asked to sleep exactly that many seconds; absent, it
  // falls back to the default backoff; an excessive value is capped.
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "backoff/1.0.0";
    vuln::HttpResponse retry_after_five;
    retry_after_five.status_code = 429;
    retry_after_five.retry_after = "5";
    vuln::HttpResponse ok;
    ok.status_code = 200;
    ok.body = R"({"version":{"license":"MIT"}})";
    transport.scripted_responses_by_url[url] = {retry_after_five, ok};
    std::vector<Component> components = {component_with_purl("pkg:cargo/backoff@1.0.0")};
    FakeSleeper sleeper;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options_with_cache(tree), transport.as_function(), fixed_clock(kNow),
        sleeper.as_function());

    BOMWERK_TEST_CHECK(enriched.value.fetched_answers == 1);
    BOMWERK_TEST_CHECK(sleeper.call_count == 1);
    BOMWERK_TEST_CHECK(sleeper.recorded_intervals.at(0) == std::chrono::seconds(5));
  }
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url =
        std::string(vuln::kCratesIoCrateVersionApiUrl) + "backoff-default/1.0.0";
    vuln::HttpResponse retry_after_absent;
    retry_after_absent.status_code = 429;
    vuln::HttpResponse ok;
    ok.status_code = 200;
    ok.body = R"({"version":{"license":"MIT"}})";
    transport.scripted_responses_by_url[url] = {retry_after_absent, ok};
    std::vector<Component> components = {component_with_purl("pkg:cargo/backoff-default@1.0.0")};
    FakeSleeper sleeper;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options_with_cache(tree), transport.as_function(), fixed_clock(kNow),
        sleeper.as_function());

    BOMWERK_TEST_CHECK(enriched.value.fetched_answers == 1);
    BOMWERK_TEST_CHECK(sleeper.call_count == 1);
    BOMWERK_TEST_CHECK(sleeper.recorded_intervals.at(0) == std::chrono::milliseconds(2000));
  }
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "backoff-capped/1.0.0";
    vuln::HttpResponse retry_after_excessive;
    retry_after_excessive.status_code = 429;
    retry_after_excessive.retry_after = "9999";
    vuln::HttpResponse ok;
    ok.status_code = 200;
    ok.body = R"({"version":{"license":"MIT"}})";
    transport.scripted_responses_by_url[url] = {retry_after_excessive, ok};
    std::vector<Component> components = {component_with_purl("pkg:cargo/backoff-capped@1.0.0")};
    FakeSleeper sleeper;

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options_with_cache(tree), transport.as_function(), fixed_clock(kNow),
        sleeper.as_function());

    BOMWERK_TEST_CHECK(enriched.value.fetched_answers == 1);
    BOMWERK_TEST_CHECK(sleeper.call_count == 1);
    BOMWERK_TEST_CHECK(sleeper.recorded_intervals.at(0) == std::chrono::milliseconds(30000));
  }

  // Given a PyPI response whose `license` field exceeds the 1 KiB cap but
  // whose classifiers carry a usable `License ::` entry, when enriched, then
  // the oversized field no longer aborts extraction: the classifier
  // recovers a usable license.
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url =
        std::string(vuln::kPyPiProjectVersionApiUrl) + "oversized-ok/1.0.0/json";
    const std::string oversized_license_text(2000, 'x');
    json response_body;
    response_body["info"]["license"] = oversized_license_text;
    response_body["info"]["classifiers"] = json::array({"License :: OSI Approved :: MIT License"});
    transport.response_by_url[url] = response_body.dump();
    std::vector<Component> components = {component_with_purl("pkg:pypi/oversized-ok@1.0.0")};

    const Result<vuln::LicenseEnrichmentSummary> enriched =
        vuln::enrich_component_licenses(components, options_with_cache(tree),
                                        transport.as_function(), fixed_clock(kNow), no_op_sleep());

    BOMWERK_TEST_CHECK(enriched.value.enriched_components == 1);
    BOMWERK_TEST_CHECK(components[0].license == "MIT License");
    BOMWERK_TEST_CHECK(!warnings_mention(enriched.warnings, "malformed or oversized"));
  }

  // Given the same oversized `license` field but no usable classifiers, when
  // enriched, then nothing is recoverable and today's pre-fix outcome is
  // preserved: the component stays unenriched and is reported malformed.
  {
    TempTree tree;
    FakeTransport transport;
    const std::string url =
        std::string(vuln::kPyPiProjectVersionApiUrl) + "oversized-unrecoverable/1.0.0/json";
    const std::string oversized_license_text(2000, 'x');
    json response_body;
    response_body["info"]["license"] = oversized_license_text;
    transport.response_by_url[url] = response_body.dump();
    std::vector<Component> components = {
        component_with_purl("pkg:pypi/oversized-unrecoverable@1.0.0")};

    const Result<vuln::LicenseEnrichmentSummary> enriched =
        vuln::enrich_component_licenses(components, options_with_cache(tree),
                                        transport.as_function(), fixed_clock(kNow), no_op_sleep());

    BOMWERK_TEST_CHECK(components[0].license.empty());
    BOMWERK_TEST_CHECK(warnings_mention(enriched.warnings, "malformed or oversized"));
  }

  // given a cache entry fetched 25h ago and DEFAULT options (the new
  // 60-day TTL), when enriched again, then it still resolves as a fresh
  // cache answer and no second network call is made: the direct regression
  // test for the root cause: this same entry would have been
  // `expired_cache_lookups` under the old 24h TTL.
  {
    TempTree tree;
    FakeTransport seed_transport;
    const std::string url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "immutable-ttl/1.0.0";
    seed_transport.response_by_url[url] = R"({"version":{"license":"MIT"}})";
    std::vector<Component> seed_components = {component_with_purl("pkg:cargo/immutable-ttl@1.0.0")};
    const Result<vuln::LicenseEnrichmentSummary> seeded = vuln::enrich_component_licenses(
        seed_components, options_with_cache(tree), seed_transport.as_function(), fixed_clock(kNow),
        no_op_sleep());
    BOMWERK_TEST_CHECK(seeded.value.fetched_answers == 1);

    constexpr std::int64_t kTwentyFiveHoursLater = kNow + 25 * 3600;
    FakeTransport later_transport;
    std::vector<Component> later_components = {
        component_with_purl("pkg:cargo/immutable-ttl@1.0.0")};
    const Result<vuln::LicenseEnrichmentSummary> later = vuln::enrich_component_licenses(
        later_components, options_with_cache(tree), later_transport.as_function(),
        fixed_clock(kTwentyFiveHoursLater), no_op_sleep());

    BOMWERK_TEST_CHECK(later.value.fresh_cache_answers == 1);
    BOMWERK_TEST_CHECK(later.value.expired_cache_lookups == 0);
    BOMWERK_TEST_CHECK(later_transport.requested_urls.empty());
    BOMWERK_TEST_CHECK(later_components[0].license == "MIT");
  }

  // given the same aged entry but `cache_max_age` explicitly
  // overridden to 1h (--license-cache-max-age), when enriched, then it
  // falls into `expired_cache_lookups` and gets refetched: proving the
  // override still works even with the longer default in place.
  {
    TempTree tree;
    const std::string url = std::string(vuln::kCratesIoCrateVersionApiUrl) + "override-ttl/1.0.0";
    FakeTransport seed_transport;
    seed_transport.response_by_url[url] = R"({"version":{"license":"MIT"}})";
    std::vector<Component> seed_components = {component_with_purl("pkg:cargo/override-ttl@1.0.0")};
    const Result<vuln::LicenseEnrichmentSummary> seeded = vuln::enrich_component_licenses(
        seed_components, options_with_cache(tree), seed_transport.as_function(), fixed_clock(kNow),
        no_op_sleep());
    BOMWERK_TEST_CHECK(seeded.value.fetched_answers == 1);

    constexpr std::int64_t kTwoHoursLater = kNow + 2 * 3600;
    FakeTransport later_transport;
    later_transport.response_by_url[url] = R"({"version":{"license":"MIT"}})";
    std::vector<Component> later_components = {component_with_purl("pkg:cargo/override-ttl@1.0.0")};
    vuln::LicenseEnrichmentOptions later_options = options_with_cache(tree);
    later_options.cache_max_age = std::chrono::hours(1);

    const Result<vuln::LicenseEnrichmentSummary> later = vuln::enrich_component_licenses(
        later_components, later_options, later_transport.as_function(), fixed_clock(kTwoHoursLater),
        no_op_sleep());

    BOMWERK_TEST_CHECK(later.value.expired_cache_lookups == 1);
    BOMWERK_TEST_CHECK(later.value.fetched_answers == 1);
    BOMWERK_TEST_CHECK(!later_transport.requested_urls.empty());
  }

  // given one purl with no prior cache entry and one purl whose cache
  // entry aged past `cache_max_age`, when enriched together, then the two
  // causes are counted separately rather than conflated into one "not yet
  // cached" number.
  {
    TempTree tree;
    const std::string expiring_url =
        std::string(vuln::kCratesIoCrateVersionApiUrl) + "will-expire/1.0.0";
    FakeTransport seed_transport;
    seed_transport.response_by_url[expiring_url] = R"({"version":{"license":"MIT"}})";
    std::vector<Component> seed_components = {component_with_purl("pkg:cargo/will-expire@1.0.0")};
    const Result<vuln::LicenseEnrichmentSummary> seeded = vuln::enrich_component_licenses(
        seed_components, options_with_cache(tree), seed_transport.as_function(), fixed_clock(kNow),
        no_op_sleep());
    BOMWERK_TEST_CHECK(seeded.value.fetched_answers == 1);

    constexpr std::int64_t kTwoHoursLater = kNow + 2 * 3600;
    FakeTransport later_transport;
    later_transport.response_by_url[expiring_url] = R"({"version":{"license":"MIT"}})";
    const std::string never_fetched_url =
        std::string(vuln::kCratesIoCrateVersionApiUrl) + "never-fetched/1.0.0";
    later_transport.response_by_url[never_fetched_url] = R"({"version":{"license":"MIT"}})";
    std::vector<Component> later_components = {
        component_with_purl("pkg:cargo/will-expire@1.0.0"),
        component_with_purl("pkg:cargo/never-fetched@1.0.0")};
    vuln::LicenseEnrichmentOptions later_options = options_with_cache(tree);
    later_options.cache_max_age = std::chrono::hours(1);

    const Result<vuln::LicenseEnrichmentSummary> later = vuln::enrich_component_licenses(
        later_components, later_options, later_transport.as_function(), fixed_clock(kTwoHoursLater),
        no_op_sleep());

    BOMWERK_TEST_CHECK(later.value.expired_cache_lookups == 1);
    BOMWERK_TEST_CHECK(later.value.never_fetched_lookups == 1);
  }

  // given five independent crates.io cache misses and a time budget
  // short enough that only some complete (an AdvancingClock lets the
  // crates.io pacing sleeps themselves drive the clock past the deadline),
  // when enriched, then the rest are counted as timed out (also folded into
  // `unresolved_components`), the result stays `complete == true`: the
  // critical exit-code-safety invariant, since a shorter pass is a smaller
  // enrichment, never an incomplete scan: and a warning names the cause.
  {
    TempTree tree;
    FakeTransport transport;
    std::vector<Component> components;
    for (int component_index = 0; component_index < 5; ++component_index)
    {
      components.push_back(
          component_with_purl("pkg:cargo/budget-" + std::to_string(component_index) + "@1.0.0"));
    }
    vuln::LicenseEnrichmentOptions options = options_with_cache(tree);
    options.time_budget = std::chrono::seconds(2);
    AdvancingClock clock(kNow);

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options, transport.as_function(), clock.now_function(), clock.sleep_function());

    BOMWERK_TEST_CHECK(enriched.complete);
    BOMWERK_TEST_CHECK(enriched.value.timed_out_components > 0);
    BOMWERK_TEST_CHECK(enriched.value.timed_out_components < 5);
    BOMWERK_TEST_CHECK(enriched.value.unresolved_components >= enriched.value.timed_out_components);
    BOMWERK_TEST_CHECK(warnings_mention(enriched.warnings, "time budget"));
  }

  // given a fresh cache hit and an uncached lookup, `time_budget =
  // 0s`, when enriched, then the cached answer still resolves (a fresh
  // cache hit is decided before the fetch loop and never even sees the
  // deadline) but the uncached one times out before any request is issued.
  {
    TempTree tree;
    const std::string cached_url =
        std::string(vuln::kCratesIoCrateVersionApiUrl) + "cached-budget/1.0.0";
    FakeTransport seed_transport;
    seed_transport.response_by_url[cached_url] = R"({"version":{"license":"MIT"}})";
    std::vector<Component> seed_components = {component_with_purl("pkg:cargo/cached-budget@1.0.0")};
    const Result<vuln::LicenseEnrichmentSummary> seeded = vuln::enrich_component_licenses(
        seed_components, options_with_cache(tree), seed_transport.as_function(), fixed_clock(kNow),
        no_op_sleep());
    BOMWERK_TEST_CHECK(seeded.value.fetched_answers == 1);

    FakeTransport transport;
    std::vector<Component> components = {
        component_with_purl("pkg:cargo/cached-budget@1.0.0"),
        component_with_purl("pkg:cargo/never-cached-budget@1.0.0")};
    vuln::LicenseEnrichmentOptions options = options_with_cache(tree);
    options.time_budget = std::chrono::seconds(0);

    const Result<vuln::LicenseEnrichmentSummary> enriched = vuln::enrich_component_licenses(
        components, options, transport.as_function(), fixed_clock(kNow), no_op_sleep());

    BOMWERK_TEST_CHECK(enriched.complete);
    BOMWERK_TEST_CHECK(enriched.value.fresh_cache_answers == 1);
    BOMWERK_TEST_CHECK(enriched.value.timed_out_components == 1);
    BOMWERK_TEST_CHECK(components[0].license == "MIT");
    BOMWERK_TEST_CHECK(components[1].license.empty());
    BOMWERK_TEST_CHECK(transport.requested_urls.empty());
    BOMWERK_TEST_CHECK(warnings_mention(enriched.warnings, "time budget"));
  }

  return 0;
}
