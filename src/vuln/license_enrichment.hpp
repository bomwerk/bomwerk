#pragma once
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <vector>

#include "core/model.hpp"
#include "core/result.hpp"
#include "vuln/http.hpp"

namespace bomwerk::vuln
{

/// Exact-version registry license metadata is immutable by construction:
/// crates.io/PyPI/RubyGems do not allow mutating a published release, unlike
/// an OSV advisory, which can change. 24h (OSV's cadence, copied here without
/// re-deriving it) meant re-fetching answers that could never differ: a real
/// measurement found this costing ~10 minutes of wall time re-fetching next.js's cargo
/// licenses a day after they were first fetched. 60 days keeps a cold cache
/// from growing unbounded while making the common case answer from cache.
/// Safety against a future payload-format change is the cache-key-suffix
/// namespace (`kLicenseCacheKeySuffix`, license_enrichment.cpp) rather than
/// a short clock: bumping that literal invalidates every entry at once.
inline constexpr std::chrono::hours kRegistryLicenseCacheMaxAge(24 * 60);

/// Conservative bounded fan-out, matching OSV hydration's default. Governs
/// only PyPI and RubyGems lookups: neither rate-limits at comparable volume.
/// crates.io lookups ignore this: they are always strictly sequential (see
/// `kCratesIoRequestInterval` below), because crates.io does rate-limit.
inline constexpr std::size_t kDefaultLicenseRequestConcurrency = 8;

/// Minimum spacing between crates.io requests. crates.io's own guidance caps
/// sustained traffic at roughly one request per second; 1100 ms adds ~10%
/// margin over that floor, the same reasoning `kNvdIntervalWithApiKey`/
/// `kNvdIntervalWithoutApiKey` (nvd.hpp) apply to NVD's published ceilings.
inline constexpr std::chrono::milliseconds kCratesIoRequestInterval(1100);

struct LicenseEnrichmentOptions
{
  /// SQLite file shared with OSV/NVD under namespaced cache keys. Empty uses
  /// `default_cache_database_path()`.
  std::filesystem::path cache_database_path;

  /// Cache-only operation. Stale entries are used with a warning; a cache
  /// miss never reaches the network.
  bool offline = false;

  std::chrono::seconds cache_max_age = kRegistryLicenseCacheMaxAge;

  /// Bounds ONLY the PyPI/RubyGems fan-out. crates.io requests are always
  /// strictly sequential and ignore this value entirely.
  std::size_t max_request_concurrency = kDefaultLicenseRequestConcurrency;

  /// bounds total wall-clock time ONE call to `enrich_component_licenses`
  /// may spend fetching. `nullopt` (default) is unbounded, unchanged from
  /// before this option existed. Checked cooperatively at loop-iteration
  /// boundaries only (rule 1 forbids force-killing a thread mid-request), so
  /// actual overrun beyond the budget is bounded by one in-flight request's
  /// own transport timeout plus, for crates.io, one full 429-retry chain.
  /// On expiry, no NEW request is issued; already-resolved components are
  /// unaffected and the returned `Result::complete` stays `true` (enrichment
  /// is additive-only: a shorter pass is a smaller enrichment, not an
  /// incomplete scan).
  std::optional<std::chrono::seconds> time_budget;
};

/// Stable counters for the user-facing summary and unit-test assertions.
struct LicenseEnrichmentSummary
{
  std::size_t candidate_components = 0;
  std::size_t enriched_components = 0;
  std::size_t fresh_cache_answers = 0;
  std::size_t fetched_answers = 0;
  std::size_t stale_cache_answers = 0;
  std::size_t skipped_components = 0;
  std::size_t unresolved_components = 0;

  /// Components whose final registry answer was still 429 after every retry,
  /// with no stale cache fallback available. Reported separately from
  /// `unresolved_components`: the registry had (or may have had) the data
  /// and refused the request, so this is not a genuine absence.
  std::size_t rate_limited_components = 0;

  /// split of the lookups that needed a registry fetch (no fresh cache
  /// answer), by WHY they needed one: a purl fetched for the first time vs.
  /// one whose previous cache entry aged past `cache_max_age`. Both are
  /// counted once each in `lookup_indices_to_fetch`'s size; these two sum to
  /// it.
  std::size_t never_fetched_lookups = 0;
  std::size_t expired_cache_lookups = 0;

  /// components left unfetched because `time_budget` elapsed before
  /// their request was issued. Also counted in `unresolved_components`
  /// (they genuinely have no answer this run): reported separately so a
  /// caller can distinguish "timed out" from every other unresolved cause.
  std::size_t timed_out_components = 0;
};

/// Fill empty `Component::license` values for exact, versioned Cargo, PyPI and
/// RubyGems purls from those ecosystems' public registries.
///
/// Existing licenses always win. Package coordinates are percent-decoded and
/// then validated against `[a-z0-9._+-]` before they enter a URL; unsafe or
/// incomplete coordinates are counted and warned about, never escaped into a
/// request. Unsupported ecosystems are untouched.
///
/// PyPI and RubyGems lookups are fanned out through the injected GET transport
/// concurrently from at most `options.max_request_concurrency` workers, same
/// as before. crates.io lookups instead run strictly SEQUENTIALLY on their own
/// thread, paced through `sleep_for` between requests only (first one free,
/// the same shape `match_via_cpe` uses for NVD): crates.io's rate limit
/// cannot sustain the shared worker-pool concurrency PyPI/RubyGems tolerate.
/// That thread is joined before any cache access, warning folding or
/// component mutation, which (as before) happen only on the calling thread
/// once every worker has finished, preserving SQLite safety and deterministic
/// output regardless of wall-clock timing.
///
/// Any registry's occasional HTTP 429 is retried a bounded number of times,
/// honoring a `Retry-After` header when the registry sends one (capped) and
/// falling back to a fixed backoff otherwise; a component still rate-limited
/// after every retry, with no stale cache answer to fall back to, is counted
/// in `LicenseEnrichmentSummary::rate_limited_components` and warned about
/// separately from a genuine absence.
///
/// `sleep_for` and `now_epoch_seconds` may both be invoked CONCURRENTLY :
/// from the crates.io pacing thread and from a PyPI/RubyGems worker's own
/// 429 backoff or deadline check: unlike `match_via_cpe`, which only ever
/// calls its `sleep_for` from one thread. Implementations (production and
/// test doubles alike) must tolerate concurrent calls to both.
///
/// `options.time_budget`, when set, is checked cooperatively at the top of
/// each pending lookup on both sub-passes: past the deadline, no NEW
/// request is issued and the affected lookups are counted in
/// `LicenseEnrichmentSummary::timed_out_components` (also folded into
/// `unresolved_components`) and warned about. This never stops or discards
/// an in-flight request, and never touches already-resolved components.
///
/// Never returns `complete == false` (rule 1): registry, cache, malformed
/// metadata and time-budget failures all degrade to warnings and leave the
/// affected component unchanged: a time budget makes enrichment smaller,
/// never the scan incomplete. With `offline == true`, no transport call
/// occurs and `sleep_for` is never invoked.
[[nodiscard]] core::Result<LicenseEnrichmentSummary> enrich_component_licenses(
    std::vector<core::Component>& components, const LicenseEnrichmentOptions& options,
    const HttpGetFunction& http_get, const std::function<std::int64_t()>& now_epoch_seconds,
    const std::function<void(std::chrono::milliseconds)>& sleep_for);

}  // namespace bomwerk::vuln
