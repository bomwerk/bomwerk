#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "core/cvss.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "vuln/endpoints.hpp"
#include "vuln/finding.hpp"
#include "vuln/http.hpp"

namespace bomwerk::vuln
{

/// Cache entries older than this are re-fetched (refresh >24 h old).
inline constexpr std::chrono::hours kCacheMaxAge(24);

/// The OUTER bound on how long the "detection confirmed unchanged" fast
/// path (`try_cached_hydration_answer` in osv.cpp) may trust a cached
/// severity/alias payload without re-fetching, even when OSV's own advisory
/// ids and `modified` timestamps agree with the stored snapshot. OSV does not
/// always send `modified` (see kHarfbuzzResponse in tests/unit/test_osv.cpp), and an
/// absent `modified` compares as an empty string equal to itself: so "the id
/// set matches" alone could otherwise confirm "unchanged" forever for a purl
/// whose feed never carries that field, silently defeating `kCacheMaxAge`
/// (rule 1: never claim more accuracy than the data supports). Seven days
/// keeps the common-case efficiency win (skip a hydration request on every
/// nightly refresh once a purl's advisory set is stable) while guaranteeing
/// no purl's severity/alias data goes stale indefinitely.
inline constexpr std::chrono::seconds kConfirmedUnchangedMaxAge(7 * 24 * 60 * 60);

/// Default number of purls per querybatch request, and OSV's documented hard
/// limit (requests above it are rejected by the API).
inline constexpr std::size_t kDefaultQueriesPerBatch = 500;
inline constexpr std::size_t kOsvMaxQueriesPerBatch = 1000;

/// Pagination follow-up ROUNDS one refresh will issue. Every
/// still-paginating purl is batched into a single querybatch request per
/// round, so this bounds total follow-up REQUESTS, not per-purl work. OSV
/// pages at 1,000 advisories, so ten rounds covers a package with up to
/// 10,000 advisories (which does not exist), while stopping a hostile or
/// malfunctioning server from spinning bomwerk forever (rule 1).
inline constexpr std::size_t kMaxOsvPaginationRounds = 10;

/// Bounded worker count for concurrent OSV requests: hydration's per-purl
/// `/v1/query` calls (one per already-vulnerable purl) and detection's
/// `/v1/querybatch` calls when there is more than one batch to send. Both
/// call sites issue independent requests with no data dependency between
/// them, so a bounded thread fan-out cuts wall-clock time on a
/// vulnerability-heavy repo without unbounded load on osv.dev. Conservative
/// by design (the request asked for "an order of magnitude" and suggested 8-16x;
/// this defaults to the low end). Never both call sites at once: detection
/// always finishes before hydration starts, so one knob covers both.
inline constexpr std::size_t kDefaultOsvRequestConcurrency = 8;

/// Runtime-tunable knobs for `match_components`, mirroring the parsers'
/// `ParseOptions` pattern: sane defaults, every limit overridable.
struct MatchOptions
{
  /// SQLite cache file; empty means `default_cache_database_path()`.
  std::filesystem::path cache_database_path;

  /// Answer from cache only, never the network (`--offline`).
  /// Stale entries are used (with a warning): offline, old knowledge beats
  /// none; purls with no cached entry at all also warn.
  bool offline = false;

  /// Freshness horizon: cached entries at least this old are re-fetched.
  std::chrono::seconds cache_max_age = kCacheMaxAge;

  /// Purls per querybatch POST, clamped to [1, kOsvMaxQueriesPerBatch].
  std::size_t max_queries_per_batch = kDefaultQueriesPerBatch;

  /// Bounded worker count for concurrent OSV requests (hydration fetches and
  /// multi-batch detection fetches), clamped to >= 1. See
  /// `kDefaultOsvRequestConcurrency`.
  std::size_t max_osv_request_concurrency = kDefaultOsvRequestConcurrency;
};

/// True when `purl` is worth sending to OSV: non-empty, purl-shaped, and
/// carrying a resolved `@version`. A version-less purl (a bare vcpkg.json
/// dependency, say) would make OSV return every advisory the package ever
/// had (noise, not matches), so those components are counted and skipped.
[[nodiscard]] bool is_queryable_purl(std::string_view purl);

/// True when `purl` is VERSIONED and its package type has no OSV-supported
/// ecosystem at all: currently Conan and vcpkg (confirmed against OSV's own
/// ecosystem list: https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt
/// lists npm/PyPI/Maven/Debian/GIT/OSS-Fuzz/… but no Conan or vcpkg entry)
/// plus `pkg:generic` (no ecosystem mapping either): UNLESS the version is a
/// resolved 40/64-hex commit id, in which case OSV's commit index matches it
/// regardless of type: `core::classify_match_coverage`'s `Matched`
/// case). A purl in this bucket is never queried: see
/// `MatchOutcome::components_without_osv_coverage`. Defined in terms of
/// `core::classify_match_coverage` (`UnmappedPurlType`), the shared
/// classification the coverage reporting also uses, so this predicate and
/// the coverage numbers on the SBOM/report/coverage file can never disagree.
/// NOTE the "versioned" qualifier above is load-bearing: an UNVERSIONED
/// Conan/vcpkg/generic purl (e.g. a bare `vcpkg.json` dependency) classifies
/// as `UnversionedPurl`, not `UnmappedPurlType`, so this returns `false` for
/// it: `is_queryable_purl` above is what answers "has no resolved version"
/// separately. No production caller combines the two today (`match_components`
/// and `run_scan`'s uncovered-purl list both call `classify_match_coverage`
/// directly instead), but a future caller of this specific function must not
/// assume it is purely type-based, the way it was before.
[[nodiscard]] bool has_no_known_osv_coverage(std::string_view purl);

/// Wall-clock seconds since the Unix epoch (1970-01-01 UTC): a timestamp
/// format, not an operating-system requirement. The production freshness
/// clock; tests inject their own. Deliberately NOT `SOURCE_DATE_EPOCH`-aware:
/// cache freshness is an operational fact, not reproducible output (contrast
/// `core::current_timestamp_iso8601`).
[[nodiscard]] std::int64_t system_clock_epoch_seconds();

/// Match `components` against OSV, caching per-purl responses in SQLite (see
/// cache.hpp) and re-fetching entries older than `options.cache_max_age`.
///
/// Two query shapes are used depending on what the purl carries, since OSV's
/// `/v1/querybatch` accepts either per query object:
/// - a purl whose resolved version is a 40- or 64-hex object id (the shape
///   the submodules/CMake-FetchContent producers emit when a dependency is
///   pinned to a commit) is queried by **commit**: OSV maintains a global
///   commit -> advisory index that works regardless of purl type, which is
///   the only path with real coverage for vendored/pinned C/C++ code today.
///   This is ALSO the only path with real coverage for a commit-pinned
///   Conan/vcpkg/generic dependency: a `pkg:generic/x@<sha>` submodule
///   with no resolvable origin URL is queried exactly like a
///   `pkg:github/x/x@<sha>` one;
/// - everything else with a resolved, non-hex version is queried by
///   **purl** (`package.purl`): this is where a future OSV-native ecosystem
///   (npm, PyPI, …) would match once M2's lockfile parsers exist.
/// A purl in `has_no_known_osv_coverage`'s bucket (Conan, vcpkg, generic
/// WITHOUT a resolved commit id) is never queried at all; its component is
/// counted in `MatchOutcome::components_without_osv_coverage` instead.
///
/// Injection points (so unit tests never touch network or wall clock):
/// `http_post`: production passes `make_curl_http_post(...)`;
/// `now_epoch_seconds`: production passes `system_clock_epoch_seconds`.
/// `http_post` MAY be invoked concurrently from up to
/// `options.max_osv_request_concurrency` worker threads (bounded
/// concurrent hydration and multi-batch detection fetches): every request
/// is independent, and every cache write / warning is folded back on the
/// calling thread only after the workers issuing it have joined, so a test's
/// injected `http_post` needs its own synchronization only if it mutates
/// shared state (see `FakeTransport` in tests/unit/test_osv.cpp).
///
/// Never touches the network for `--offline` or an already-fresh/confirmed
/// cache entry (decision point #2): those paths never reach a worker
/// thread at all.
///
/// Never throws and never returns `complete == false` (rule 1): every
/// failure: transport, HTTP status, malformed/oversized/over-deep response
/// JSON, unusable cache: degrades to a warning, falling back to a stale
/// cache entry when one exists. Found vulnerabilities are RESULTS, not
/// warnings: a hit alone never degrades the run's exit code.
///
/// Deterministic (rule 3): hits are sorted by purl, ids within a hit sorted
/// and deduplicated; identical inputs (and cache state) yield identical
/// output.
[[nodiscard]] core::Result<MatchOutcome> match_components(
    const std::vector<core::Component>& components, const MatchOptions& options,
    const HttpPostFunction& http_post, const std::function<std::int64_t()>& now_epoch_seconds);

}  // namespace bomwerk::vuln
