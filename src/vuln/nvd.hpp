#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "vuln/endpoints.hpp"
#include "vuln/finding.hpp"
#include "vuln/http.hpp"
#include "vuln/osv.hpp"

namespace bomwerk::vuln
{

/// Name of the environment variable holding an NVD API key. Deliberately an
/// environment variable and NOT a `bomwerk.toml` key: the config file ships
/// inside the repo under audit (untrusted input), and a credential
/// has no business living there.
inline constexpr const char* kNvdApiKeyEnvironmentVariable = "BOMWERK_NVD_API_KEY";

/// Minimum spacing between NVD requests. Unauthenticated callers get 5
/// requests per rolling 30 s window and NIST's own guidance is to sleep six
/// seconds between requests; an API key raises the ceiling to 50 per 30 s,
/// which 700 ms honors with headroom.
inline constexpr std::chrono::milliseconds kNvdIntervalWithoutApiKey(6000);
inline constexpr std::chrono::milliseconds kNvdIntervalWithApiKey(700);

/// Advisories requested per query. 2000 is the API's documented maximum and
/// its default; a wildcard-vendor product query realistically never fills one
/// page, and `match_via_cpe` warns rather than silently truncating if it does.
inline constexpr std::size_t kNvdResultsPerPage = 2000;

/// Runtime-tunable knobs for `match_via_cpe`, mirroring `MatchOptions`.
struct NvdOptions
{
  /// SQLite cache file; empty means `default_cache_database_path()`. Shares
  /// the OSV cache file under namespaced keys: entries can never collide.
  std::filesystem::path cache_database_path;

  /// Answer from cache only, never the network (`--offline`).
  bool offline = false;

  /// Freshness horizon: cached entries at least this old are re-fetched.
  std::chrono::seconds cache_max_age = kCacheMaxAge;

  /// NVD API key; empty means unauthenticated (and eight times slower).
  /// NEVER logged, warned about, or written to any output.
  std::string api_key;
};

/// Match the components OSV structurally cannot check against **NVD's CVE API
/// 2.0**, using a CPE match string with a wildcard vendor.
///
/// Selection is exactly `core::MatchCoverage::UnmappedPurlType`: the same
/// single predicate the coverage reporting and `match_components` use, so
/// the set queried here and the set reported as uncovered elsewhere can never
/// disagree. Everything else is left alone: a component OSV can match is never
/// sent here, and neither is one whose purl cannot produce a safe CPE
/// (`vuln::cpe_match_string_for`), which is counted and warned about instead.
///
/// Why NVD and not OSV: OSV's API has no CPE query of any kind: `/v1/query`
/// accepts only `commit`, `version` and `package{name,ecosystem,purl}`. For a
/// Conan/vcpkg/generic purl with no resolved commit id, NVD is the only feed
/// that can answer at all.
///
/// Findings carry `MatchProvenance::CpeFallback` and are LOWER CONFIDENCE by
/// construction: a wildcard vendor also matches a different vendor's product
/// that happens to share the name. Callers must present them as such.
///
/// Requests are strictly SEQUENTIAL and throttled through `sleep_for` :
/// NVD's rate limit is per-key, not per-connection, so issuing them in
/// parallel would get the caller blocked rather than served. The CLI instead
/// runs this whole function on its own thread so the waiting overlaps the OSV
/// path (see cli/scan_command.cpp).
///
/// Counters: this fills `MatchOutcome::cpe_checked_purls` only and leaves
/// `components_without_osv_coverage` at 0: that number is the OSV pass's fact
/// to report, and `merge_outcomes` combines the two outcomes.
///
/// Injection points (so unit tests never touch network, wall clock or the
/// real clock's patience): `http_get`: production passes
/// `make_curl_http_get(...)`; `now_epoch_seconds`: production passes
/// `system_clock_epoch_seconds`; `sleep_for`: production passes a
/// `std::this_thread::sleep_for` adapter.
///
/// Never throws and never returns `complete == false` (rule 1): every failure
///: transport, HTTP status, malformed/oversized/over-deep response JSON,
/// unusable cache: degrades to a warning, falling back to a stale cache entry
/// when one exists. Found vulnerabilities are RESULTS, not warnings: a hit
/// alone never degrades the run's exit code.
///
/// Deterministic (rule 3): hits are sorted by purl, advisories sorted
/// worst-first and deduplicated; identical inputs and cache state yield
/// identical output regardless of timing.
[[nodiscard]] core::Result<MatchOutcome> match_via_cpe(
    const std::vector<core::Component>& components, const NvdOptions& options,
    const HttpGetFunction& http_get, const std::function<std::int64_t()>& now_epoch_seconds,
    const std::function<void(std::chrono::milliseconds)>& sleep_for);

}  // namespace bomwerk::vuln
