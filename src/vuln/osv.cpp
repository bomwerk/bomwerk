#include "vuln/osv.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <deque>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/cvss.hpp"
#include "core/joining_thread.hpp"
#include "core/json_utils.hpp"
#include "core/match_coverage.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "vuln/cache.hpp"
#include "vuln/delta.hpp"

namespace bomwerk::vuln
{
namespace
{

using nlohmann::json;

/// Run `task_count` independent jobs (identified by index 0..task_count)
/// in waves of at most `concurrency_limit` `core::JoiningThread`s at a time.
/// `run_one(task_index)` must touch only state reachable through its own
/// index (e.g. `outcomes[task_index]`): concurrent jobs in the same wave
/// share no synchronization, so anything they share must stay read-only
/// (`http_post` itself is safe this way: see osv.hpp's doc comment) or be
/// disjoint per-index storage. Every job has joined before this returns, so
/// the caller may freely touch shared state (the cache, `result.warn`, ...)
/// afterward. `std::deque` (not `std::vector`) holds the wave's threads
/// because `core::JoiningThread` is neither copyable nor movable, and
/// `deque::emplace_back` never needs to relocate existing elements.
template <typename RunOne>
void run_bounded_concurrent(std::size_t task_count, std::size_t concurrency_limit, RunOne&& run_one)
{
  const std::size_t wave_size = std::max<std::size_t>(concurrency_limit, 1);
  for (std::size_t wave_begin = 0; wave_begin < task_count; wave_begin += wave_size)
  {
    const std::size_t wave_end = std::min(wave_begin + wave_size, task_count);
    std::deque<core::JoiningThread> wave_threads;
    for (std::size_t task_index = wave_begin; task_index < wave_end; ++task_index)
    {
      wave_threads.emplace_back([&run_one, task_index] { run_one(task_index); });
    }
    // wave_threads destructs here: every worker in this wave joins before the
    // next wave (or the caller) proceeds.
  }
}

/// Strip purl qualifiers (`?arch=…`) and subpath (`#dir`): OSV matches on the
/// bare type/namespace/name@version, and a qualifier would only cause a
/// silent no-match. Thin wrapper over the shared `core::purl_identity_part`
/// so this module and `core::match_coverage` can never disagree on where a
/// purl's identity ends.
std::string query_purl_for(std::string_view canonical_purl)
{
  return std::string(core::purl_identity_part(canonical_purl));
}

/// When `purl`'s resolved version is a 40- or 64-hex object id (a commit a
/// producer actually resolved, not a tag/branch name), the sha to send OSV's
/// global commit index: OSV matches this regardless of purl type or even
/// which repo the commit lives in.
std::optional<std::string> commit_sha_if_applicable(std::string_view query_purl)
{
  const std::string_view version = core::purl_version_of(query_purl);
  if (!core::is_hex_object_id(version))
  {
    return std::nullopt;
  }
  return std::string(version);
}

/// The OSV query object for one purl: `{"commit": sha}` when the version is
/// a resolved commit id, else `{"package": {"purl": ...}}`.
json build_query_object(const std::string& query_purl)
{
  json query_object;
  if (const std::optional<std::string> commit_sha = commit_sha_if_applicable(query_purl);
      commit_sha.has_value())
  {
    query_object["commit"] = *commit_sha;
  }
  else
  {
    query_object["package"]["purl"] = query_purl;
  }
  return query_object;
}

/// Parse semi-trusted feed JSON under rule-1 bounds: the linear depth
/// pre-scan runs first (nlohmann's parser is recursive-descent), then a
/// non-throwing parse. Any problem yields a discarded value.
json parse_bounded_json(const std::string& text)
{
  if (core::json_utils::exceeds_json_nesting_depth(text, core::json_utils::kMaxJsonNestingDepth))
  {
    return json(json::value_t::discarded);
  }
  return json::parse(text, nullptr, false);
}

/// What one purl's cached/fetched DETECTION payload (the per-query response
/// object, `{"vulns":[{"id":…,"modified":…},…]}`, `{}` for "no known
/// vulnerabilities", or carrying a `next_page_token` when OSV has more than
/// one page) contains.
struct ExtractedPayload
{
  std::vector<AdvisoryRevision> advisory_revisions;
  bool truncated = false;  ///< a next_page_token was present: ids may be incomplete
  bool malformed = false;  ///< payload was not the expected JSON shape
};

ExtractedPayload extract_advisory_revisions(const std::string& payload)
{
  ExtractedPayload extracted;
  const json document = parse_bounded_json(payload);
  if (document.is_discarded() || !document.is_object())
  {
    extracted.malformed = true;
    return extracted;
  }
  if (document.contains("next_page_token"))
  {
    extracted.truncated = true;
  }
  const auto vulns_field = document.find("vulns");
  if (vulns_field == document.end())
  {
    return extracted;  // {} is OSV's way of saying "no known vulnerabilities"
  }
  if (!vulns_field->is_array())
  {
    extracted.malformed = true;
    return extracted;
  }
  for (const json& advisory : *vulns_field)
  {
    if (!advisory.is_object())
    {
      continue;
    }
    const auto id_field = advisory.find("id");
    if (id_field == advisory.end() || !id_field->is_string())
    {
      continue;
    }
    AdvisoryRevision revision;
    revision.advisory_id = id_field->get<std::string>();
    if (const auto modified_field = advisory.find("modified");
        modified_field != advisory.end() && modified_field->is_string())
    {
      revision.modified = modified_field->get<std::string>();
    }
    extracted.advisory_revisions.push_back(std::move(revision));
  }
  return extracted;
}

/// Sort by advisory id (stable, so ties from a hostile duplicate keep the
/// server's own first-listed entry) and drop ids beyond the first :
/// `diff_advisory_revisions` requires both its inputs sorted and
/// deduplicated this way.
void sort_and_deduplicate_revisions(std::vector<AdvisoryRevision>& revisions)
{
  std::stable_sort(revisions.begin(), revisions.end(),
                   [](const AdvisoryRevision& left, const AdvisoryRevision& right)
                   { return left.advisory_id < right.advisory_id; });
  revisions.erase(std::unique(revisions.begin(), revisions.end(),
                              [](const AdvisoryRevision& left, const AdvisoryRevision& right)
                              { return left.advisory_id == right.advisory_id; }),
                  revisions.end());
}

/// A US (unit-separator) byte never appears in a purl, so suffixing it lets
/// the full-advisory payload share the purl-keyed cache table without a schema
/// change and without ever colliding with a detection (querybatch) entry.
constexpr std::string_view kFullPayloadKeySuffix =
    "\x1f"
    "full";

/// The best CVSS severity in one OSV `severity` array (entries
/// `{"type","score"}`, where `score` is a CVSS vector string). "Best" is the
/// highest-scoring vector; an unscored entry never displaces a scored one, and
/// an absent/empty array yields an unscored (Unknown) result: never a
/// misleading 0.
core::CvssScore best_severity(const json& severity_array)
{
  core::CvssScore best;  // has_score == false => Unknown
  if (!severity_array.is_array())
  {
    return best;
  }
  for (const json& entry : severity_array)
  {
    if (!entry.is_object())
    {
      continue;
    }
    const auto score_field = entry.find("score");
    if (score_field == entry.end() || !score_field->is_string())
    {
      continue;
    }
    const core::CvssScore candidate = core::score_cvss_vector(score_field->get<std::string>());
    if (candidate.has_score && (!best.has_score || candidate.score > best.score))
    {
      best = candidate;
    }
  }
  return best;
}

/// One advisory as its FULL OSV `/v1/query` record states it: the severity we
/// already resolve, plus the CVE-shaped ids OSV's `aliases[]` array says name
/// the SAME vulnerability. Aliases are what let a GHSA-only OSV finding join a
/// CVE-keyed bulk feed: verified live: EVERY advisory OSV
/// returns for `pkg:npm/lodash@4.17.15` is GHSA-keyed with its CVE only in
/// `aliases[]` (2026-08-23).
struct AdvisoryRecord
{
  core::CvssScore severity;
  std::vector<std::string> cve_aliases;  ///< sorted, deduplicated (rule 3)
};

/// Map every advisory id in a FULL `/v1/query` payload (potentially several :
/// one purl can be named by several advisories) to its severity and CVE
/// aliases.
std::map<std::string, AdvisoryRecord> extract_full_records(const std::string& payload)
{
  std::map<std::string, AdvisoryRecord> record_by_id;
  const json document = parse_bounded_json(payload);
  if (document.is_discarded() || !document.is_object())
  {
    return record_by_id;
  }
  const auto vulns_field = document.find("vulns");
  if (vulns_field == document.end() || !vulns_field->is_array())
  {
    return record_by_id;
  }
  for (const json& advisory : *vulns_field)
  {
    if (!advisory.is_object())
    {
      continue;
    }
    const auto id_field = advisory.find("id");
    if (id_field == advisory.end() || !id_field->is_string())
    {
      continue;
    }
    AdvisoryRecord record;
    if (const auto severity_field = advisory.find("severity"); severity_field != advisory.end())
    {
      record.severity = best_severity(*severity_field);
    }
    if (const auto aliases_field = advisory.find("aliases");
        aliases_field != advisory.end() && aliases_field->is_array())
    {
      for (const json& alias_entry : *aliases_field)
      {
        if (!alias_entry.is_string())
        {
          continue;
        }
        if (std::string alias_id = alias_entry.get<std::string>(); is_cve_shaped_id(alias_id))
        {
          record.cve_aliases.push_back(std::move(alias_id));
        }
      }
      std::sort(record.cve_aliases.begin(), record.cve_aliases.end());
      record.cve_aliases.erase(std::unique(record.cve_aliases.begin(), record.cve_aliases.end()),
                               record.cve_aliases.end());
    }
    record_by_id.insert_or_assign(id_field->get<std::string>(), std::move(record));
  }
  return record_by_id;
}

/// Resolve id->(severity, aliases) for one already-known-vulnerable purl by
/// hydrating its FULL advisory records (querybatch gives only ids). Reuses the
/// cache under a namespaced key and honors `--offline` (cached full payloads
/// only). A missing record is a nicety being unavailable, not a match
/// failure, so it never warns or degrades the run; a live network/HTTP
/// problem warns like the detection path (network trouble => exit 1). Falls
/// back to a stale full payload after a failed fetch (partial beats none).
///
/// Split into `try_cached_hydration_answer` (the non-network fast path
/// below) and `finish_hydration_fetch` (the post-fetch tail further below) so
/// the caller can run the actual `http_post` calls for every purl that needs
/// one CONCURRENTLY, bounded by `options.max_osv_request_concurrency`, rather
/// than one blocking request per vulnerable purl in sequence: this doc
/// comment's contract is unchanged, only how the caller reaches it.
///
/// `detection_confirmed_unchanged` is the efficiency win: when the
/// DETECTION pass (not this function) already proved: via OSV's own
/// `modified` timestamps, never a stale fallback, never a truncated/incomplete
/// answer: that this purl's advisory set has not moved since the last
/// refresh, a previously hydrated record for that SAME set is still correct
/// past the normal freshness horizon, so the network is skipped. This is what
/// lets "feeds update idempotently" cost one detection lookup and zero
/// hydration requests for a stable purl on most refreshes. It is bounded by
/// `kConfirmedUnchangedMaxAge`, not unconditional: OSV does not always send
/// `modified`, so "the id set matches" alone must not be trusted to confirm
/// freshness forever (rule 1): this only widens the horizon, it does not
/// remove it.
/// The non-network fast path split out of `resolve_purl_records`: a
/// fresh cache hit, a confirmed-unchanged hit, or (`--offline`) whatever is
/// cached. Returns `nullopt` exactly when the original function would have
/// gone on to call `http_post`; the caller then queues `query_purl` for the
/// concurrent fetch pass instead of blocking on it here. Single-threaded only
/// (touches `cache`).
std::optional<std::map<std::string, AdvisoryRecord>> try_cached_hydration_answer(
    const std::string& query_purl, VulnCache& cache, const MatchOptions& options, std::int64_t now,
    std::int64_t oldest_fresh_epoch_seconds, bool detection_confirmed_unchanged)
{
  const std::string cache_key = query_purl + std::string(kFullPayloadKeySuffix);
  const std::optional<VulnCacheEntry> cached = cache.lookup(cache_key);

  const std::int64_t oldest_confirmed_unchanged_epoch_seconds =
      now - kConfirmedUnchangedMaxAge.count();
  if (detection_confirmed_unchanged && cached.has_value() &&
      cached->fetched_at_epoch_seconds >= oldest_confirmed_unchanged_epoch_seconds)
  {
    return extract_full_records(cached->payload);
  }
  if (cached.has_value() && cached->fetched_at_epoch_seconds >= oldest_fresh_epoch_seconds)
  {
    return extract_full_records(cached->payload);
  }
  if (options.offline)
  {
    return cached.has_value() ? extract_full_records(cached->payload)
                              : std::map<std::string, AdvisoryRecord>{};
  }
  return std::nullopt;
}

/// The post-fetch tail split out of `resolve_purl_records`: folds one
/// already-completed hydration `http_post` outcome into the cache and
/// `result`'s warnings, falling back to a stale cached payload on failure
/// (partial beats none). Called only after every worker thread for this
/// refresh's concurrent fetch pass has joined (touches `cache` and `result`,
/// neither thread-safe).
std::map<std::string, AdvisoryRecord> finish_hydration_fetch(const std::string& query_purl,
                                                             VulnCache& cache, std::int64_t now,
                                                             core::Result<HttpResponse>& response,
                                                             core::Result<MatchOutcome>& result)
{
  const std::string cache_key = query_purl + std::string(kFullPayloadKeySuffix);
  for (core::Warning& transport_warning : response.warnings)
  {
    result.warn(std::move(transport_warning));
  }
  if (response.value.status_code == 200)
  {
    const json parsed = parse_bounded_json(response.value.body);
    if (!parsed.is_discarded() && parsed.is_object())
    {
      const std::string payload = parsed.dump();  // canonical (sorted keys), rule 3
      cache.store(cache_key, now, payload);
      return extract_full_records(payload);
    }
    result.warn(core::WarningCode::kVulnResponseMalformed,
                "OSV severity payload for " + query_purl + " is malformed, severity omitted");
  }
  else if (response.value.status_code != 0)
  {
    result.warn(core::WarningCode::kVulnHttpUnexpectedStatus,
                "OSV query (severity) returned HTTP " + std::to_string(response.value.status_code) +
                    " for " + query_purl);
  }
  const std::optional<VulnCacheEntry> cached = cache.lookup(cache_key);
  return cached.has_value() ? extract_full_records(cached->payload)
                            : std::map<std::string, AdvisoryRecord>{};
}

}  // namespace

bool is_queryable_purl(std::string_view purl)
{
  const std::string_view identity_part = core::purl_identity_part(purl);
  if (!identity_part.starts_with("pkg:"))
  {
    return false;
  }
  return !core::purl_version_of(identity_part).empty();
}

bool has_no_known_osv_coverage(std::string_view purl)
{
  return core::classify_match_coverage(purl) == core::MatchCoverage::UnmappedPurlType;
}

std::int64_t system_clock_epoch_seconds()
{
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

core::Result<MatchOutcome> match_components(const std::vector<core::Component>& components,
                                            const MatchOptions& options,
                                            const HttpPostFunction& http_post,
                                            const std::function<std::int64_t()>& now_epoch_seconds)
{
  core::Result<MatchOutcome> result;

  // Queryable purls, deduplicated and sorted (rule 3). merge_all upstream
  // already deduplicates by identity, but qualifier-stripping could
  // re-collide two purls, so a set keeps this locally airtight. Every
  // component is classified once through the SAME predicate the coverage
  // reporting uses (`core::classify_match_coverage`), so this gate and the
  // numbers a scan reports elsewhere can never disagree. A purl with no OSV
  // ecosystem at all (Conan/vcpkg/generic) is counted separately and never
  // queried UNLESS its version is a resolved commit id: OSV's commit index
  // matches by sha regardless of purl type: see
  // MatchOutcome::components_without_osv_coverage.
  std::set<std::string> query_purls;
  std::size_t skipped_component_count = 0;
  for (const core::Component& component : components)
  {
    switch (core::classify_match_coverage(component.purl))
    {
      case core::MatchCoverage::NoIdentifier:
      case core::MatchCoverage::UnversionedPurl:
        ++skipped_component_count;
        break;
      case core::MatchCoverage::UnmappedPurlType:
        ++result.value.components_without_osv_coverage;
        break;
      case core::MatchCoverage::Matched:
        query_purls.insert(query_purl_for(component.purl));
        break;
    }
  }
  if (skipped_component_count > 0)
  {
    // Progress information, not degradation: bare (version-less) manifest
    // dependencies are a normal state, so this must not touch the exit code.
    spdlog::info("vuln: skipped {} component(s) without a resolved version (nothing to match)",
                 skipped_component_count);
  }
  if (result.value.components_without_osv_coverage > 0)
  {
    // "by OSV" is load-bearing since: the CPE fallback may query exactly
    // these components against NVD, so a bare "not queried" would read as
    // "not checked at all" on a run where they were.
    spdlog::info(
        "vuln: {} component(s) have no OSV ecosystem coverage (Conan/vcpkg/generic), "
        "not queried by OSV",
        result.value.components_without_osv_coverage);
  }
  if (query_purls.empty())
  {
    return result;
  }

  // The cache is an optimization, never a requirement (rule 1): any open
  // failure was already turned into a warning, and a closed cache behaves as
  // permanent miss / no-op store.
  const std::filesystem::path cache_database_path = options.cache_database_path.empty()
                                                        ? default_cache_database_path()
                                                        : options.cache_database_path;
  core::Result<VulnCache> cache_open = VulnCache::open(cache_database_path);
  for (core::Warning& open_warning : cache_open.warnings)
  {
    result.warn(std::move(open_warning));
  }
  VulnCache cache = std::move(cache_open.value);

  const std::int64_t now = now_epoch_seconds();
  const std::int64_t oldest_fresh_epoch_seconds = now - options.cache_max_age.count();

  // Partition: fresh cache entries answer immediately; stale entries are
  // remembered as a fallback (offline mode, or a fetch that later fails).
  // `stale_answer_purls` tracks every purl whose FINAL answer below came from
  // a stale source (offline stale-use, or a post-fetch stale fallback), and
  // the delta path never treats a stale answer as confirmation that nothing changed, however
  // much OSV's own `modified` timestamps might agree with the last snapshot.
  std::map<std::string, std::string> payload_by_purl;
  std::map<std::string, std::string> stale_payload_by_purl;
  std::vector<std::string> purls_to_fetch;
  std::set<std::string> stale_answer_purls;
  for (const std::string& purl : query_purls)
  {
    std::optional<VulnCacheEntry> cached_entry = cache.lookup(purl);
    // Fresh means "not older than the horizon" (refresh >24 h old),
    // so an entry aged exactly cache_max_age still answers.
    if (cached_entry.has_value() &&
        cached_entry->fetched_at_epoch_seconds >= oldest_fresh_epoch_seconds)
    {
      payload_by_purl.insert_or_assign(purl, std::move(cached_entry->payload));
      continue;
    }
    if (cached_entry.has_value())
    {
      stale_payload_by_purl.insert_or_assign(purl, std::move(cached_entry->payload));
    }
    purls_to_fetch.push_back(purl);
  }
  const std::size_t fresh_cache_count = payload_by_purl.size();
  std::size_t fetched_purl_count = 0;
  std::set<std::string> freshly_fetched_purls;

  if (options.offline)
  {
    // Cache only, no network (`--offline`). Offline, stale knowledge beats
    // none: but both stale answers and holes are stated plainly.
    std::size_t stale_used_count = 0;
    std::size_t missing_count = 0;
    for (const std::string& purl : purls_to_fetch)
    {
      if (const auto stale_position = stale_payload_by_purl.find(purl);
          stale_position != stale_payload_by_purl.end())
      {
        payload_by_purl.insert(*stale_position);
        stale_answer_purls.insert(purl);
        ++stale_used_count;
      }
      else
      {
        ++missing_count;
      }
    }
    if (stale_used_count > 0)
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "--offline: " + std::to_string(stale_used_count) +
                      " purl(s) answered from cache entries older than the refresh horizon");
    }
    if (missing_count > 0)
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "--offline: no cached OSV data for " + std::to_string(missing_count) +
                      " purl(s), vulnerability coverage incomplete");
    }
  }
  else
  {
    const std::size_t batch_size_limit =
        std::clamp<std::size_t>(options.max_queries_per_batch, 1, kOsvMaxQueriesPerBatch);
    const std::size_t request_concurrency_limit =
        std::max<std::size_t>(options.max_osv_request_concurrency, 1);

    // Every querybatch POST below is an independent request (no batch
    // depends on another's result), so when there is more than one, fetch
    // them concurrently first: bounded by `request_concurrency_limit`: and
    // then process the responses sequentially, in batch order, exactly like
    // the earlier loop body did. `batch_responses` is indexed by batch
    // number, one disjoint slot per worker, so no mutex is needed and the
    // processing loop below never depends on which worker finished first
    // (rule 3).
    const std::size_t batch_count =
        (purls_to_fetch.size() + batch_size_limit - 1) / std::max<std::size_t>(batch_size_limit, 1);
    std::vector<core::Result<HttpResponse>> batch_responses(batch_count);
    run_bounded_concurrent(
        batch_count, request_concurrency_limit,
        [&](std::size_t batch_index)
        {
          const std::size_t batch_begin = batch_index * batch_size_limit;
          const std::size_t batch_end =
              std::min(batch_begin + batch_size_limit, purls_to_fetch.size());

          json request_body;
          request_body["queries"] = json::array();
          for (std::size_t purl_index = batch_begin; purl_index < batch_end; ++purl_index)
          {
            request_body["queries"].push_back(build_query_object(purls_to_fetch[purl_index]));
          }
          batch_responses[batch_index] =
              http_post(HttpRequest{std::string(kOsvQueryBatchUrl), request_body.dump()});
        });

    for (std::size_t batch_begin = 0; batch_begin < purls_to_fetch.size();
         batch_begin += batch_size_limit)
    {
      const std::size_t batch_end = std::min(batch_begin + batch_size_limit, purls_to_fetch.size());
      const std::size_t batch_index = batch_begin / batch_size_limit;

      core::Result<HttpResponse>& response = batch_responses[batch_index];
      for (core::Warning& transport_warning : response.warnings)
      {
        result.warn(std::move(transport_warning));
      }
      if (response.value.status_code != 0 && response.value.status_code != 200)
      {
        result.warn(core::WarningCode::kVulnHttpUnexpectedStatus,
                    "OSV querybatch returned HTTP " + std::to_string(response.value.status_code));
      }
      bool batch_usable = response.value.status_code == 200;

      json response_document;
      if (batch_usable)
      {
        response_document = parse_bounded_json(response.value.body);
        if (response_document.is_discarded() || !response_document.is_object() ||
            !response_document.contains("results") || !response_document["results"].is_array())
        {
          result.warn(core::WarningCode::kVulnResponseMalformed,
                      "OSV querybatch response is not the expected JSON shape, batch discarded");
          batch_usable = false;
        }
      }

      if (batch_usable)
      {
        const json& batch_results = response_document["results"];
        const std::size_t expected_result_count = batch_end - batch_begin;
        if (batch_results.size() != expected_result_count)
        {
          result.warn(core::WarningCode::kVulnCoverageIncomplete,
                      "OSV querybatch answered " + std::to_string(batch_results.size()) + " of " +
                          std::to_string(expected_result_count) + " queries, partial batch");
        }
        const std::size_t usable_result_count =
            std::min<std::size_t>(batch_results.size(), expected_result_count);
        for (std::size_t result_index = 0; result_index < usable_result_count; ++result_index)
        {
          const std::string& queried_purl = purls_to_fetch[batch_begin + result_index];
          const json& result_entry = batch_results[result_index];
          if (!result_entry.is_object())
          {
            result.warn(core::WarningCode::kVulnResponseMalformed,
                        "OSV entry for " + queried_purl + " is malformed, skipped");
            continue;
          }
          // dump() of a (map-based) nlohmann::json emits sorted keys, so the
          // cached payload bytes are canonical (rule 3). Stored verbatim here
          // even when a next_page_token is present: the pagination pass
          // below overwrites it with a merged payload ONLY for a purl that
          // actually needed one, so the common (single-page) case is
          // byte-identical to earlier cache contents.
          std::string payload = result_entry.dump();
          cache.store(queried_purl, now, payload);
          payload_by_purl.insert_or_assign(queried_purl, std::move(payload));
          freshly_fetched_purls.insert(queried_purl);
          ++fetched_purl_count;
        }
      }
    }

    // Whatever a failed batch left unanswered falls back to a stale cache
    // entry when one exists (partial output beats none): stated plainly.
    std::size_t stale_fallback_count = 0;
    std::size_t unresolved_count = 0;
    for (const std::string& purl : purls_to_fetch)
    {
      if (payload_by_purl.contains(purl))
      {
        continue;
      }
      if (const auto stale_position = stale_payload_by_purl.find(purl);
          stale_position != stale_payload_by_purl.end())
      {
        payload_by_purl.insert(*stale_position);
        stale_answer_purls.insert(purl);
        ++stale_fallback_count;
      }
      else
      {
        ++unresolved_count;
      }
    }
    if (stale_fallback_count > 0)
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  std::to_string(stale_fallback_count) +
                      " purl(s) answered from stale cache after a failed OSV fetch");
    }
    if (unresolved_count > 0)
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "OSV coverage incomplete: " + std::to_string(unresolved_count) +
                      " purl(s) unresolved this run");
    }

    // pagination: OSV's querybatch pages at 1,000 advisories per query.
    // Only purls FRESHLY FETCHED this round can carry a real, followable
    // token: a fresh-cache or stale-fallback payload is last refresh's
    // already-resolved (or already-abandoned) state, and gets its own chance
    // to paginate the next time IT is fetched fresh. Every still-paginating
    // purl is folded into ONE combined querybatch request per round, so this
    // costs one extra round trip per ROUND, never one per purl.
    std::map<std::string, std::string> next_page_token_by_purl;
    for (const std::string& purl : freshly_fetched_purls)
    {
      const json first_page = parse_bounded_json(payload_by_purl.at(purl));
      if (first_page.is_discarded() || !first_page.is_object())
      {
        continue;
      }
      if (const auto token_field = first_page.find("next_page_token");
          token_field != first_page.end() && token_field->is_string())
      {
        next_page_token_by_purl.emplace(purl, token_field->get<std::string>());
      }
    }

    std::map<std::string, std::vector<json>> extra_vulns_by_purl;
    std::set<std::string> incomplete_pagination_purls;
    for (std::size_t page_round = 0;
         page_round < kMaxOsvPaginationRounds && !next_page_token_by_purl.empty(); ++page_round)
    {
      json follow_up_body;
      follow_up_body["queries"] = json::array();
      std::vector<std::string> ordered_purls;  // same order as the queries below
      ordered_purls.reserve(next_page_token_by_purl.size());
      for (const auto& [purl, token] : next_page_token_by_purl)  // std::map => purl-sorted (rule 3)
      {
        json query_object = build_query_object(purl);
        query_object["page_token"] = token;
        follow_up_body["queries"].push_back(std::move(query_object));
        ordered_purls.push_back(purl);
      }

      core::Result<HttpResponse> follow_up_response =
          http_post(HttpRequest{std::string(kOsvQueryBatchUrl), follow_up_body.dump()});
      for (core::Warning& transport_warning : follow_up_response.warnings)
      {
        result.warn(std::move(transport_warning));
      }

      const json follow_up_document = follow_up_response.value.status_code == 200
                                          ? parse_bounded_json(follow_up_response.value.body)
                                          : json(json::value_t::discarded);
      const bool follow_up_usable =
          follow_up_response.value.status_code == 200 && !follow_up_document.is_discarded() &&
          follow_up_document.is_object() && follow_up_document.contains("results") &&
          follow_up_document["results"].is_array() &&
          follow_up_document["results"].size() == ordered_purls.size();
      if (!follow_up_usable)
      {
        // Every purl still waiting this round stops here: its last
        // successful page (page 1, or an earlier follow-up) still carries a
        // real, unresolved `next_page_token`, which the merge step below
        // deliberately leaves in place so extraction downstream reports it
        // truncated rather than silently presenting a partial list as
        // complete (rule 1).
        for (const auto& [purl, token] : next_page_token_by_purl)
        {
          incomplete_pagination_purls.insert(purl);
        }
        break;
      }

      const json& follow_up_results = follow_up_document["results"];
      std::map<std::string, std::string> next_round_tokens;
      for (std::size_t index = 0; index < ordered_purls.size(); ++index)
      {
        const std::string& purl = ordered_purls[index];
        const json& page_result = follow_up_results[index];
        if (!page_result.is_object())
        {
          incomplete_pagination_purls.insert(purl);
          continue;
        }
        if (const auto vulns_field = page_result.find("vulns");
            vulns_field != page_result.end() && vulns_field->is_array())
        {
          std::vector<json>& accumulated = extra_vulns_by_purl[purl];
          for (const json& advisory : *vulns_field)
          {
            accumulated.push_back(advisory);
          }
        }
        if (const auto token_field = page_result.find("next_page_token");
            token_field != page_result.end() && token_field->is_string())
        {
          // A server echoing back the EXACT token it was just sent cannot be
          // making progress: an immediate spin guard, never worth waiting
          // out the round bound for (rule 1: a hostile or malfunctioning
          // server cannot spin this loop).
          if (std::string new_token = token_field->get<std::string>();
              new_token != next_page_token_by_purl.at(purl))
          {
            next_round_tokens.emplace(purl, std::move(new_token));
          }
          else
          {
            incomplete_pagination_purls.insert(purl);
          }
        }
        // No token in this page's result => genuinely done: absent from
        // `next_round_tokens`, never marked incomplete.
      }
      next_page_token_by_purl = std::move(next_round_tokens);
    }
    for (const auto& [purl, token] : next_page_token_by_purl)
    {
      incomplete_pagination_purls.insert(purl);  // the round bound was exhausted
    }
    if (!incomplete_pagination_purls.empty())
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "OSV pagination did not complete within " +
                      std::to_string(kMaxOsvPaginationRounds) + " round(s) for " +
                      std::to_string(incomplete_pagination_purls.size()) +
                      " purl(s), advisory lists may be incomplete");
    }

    // Fold every accumulated follow-up page back into ONE merged payload per
    // purl that needed pagination at all: a purl needing no follow-up never
    // reaches this loop, so its cache bytes are exactly what OSV returned on
    // page 1, unchanged from earlier behavior.
    for (auto& [purl, extra_advisories] : extra_vulns_by_purl)
    {
      const auto payload_position = payload_by_purl.find(purl);
      if (payload_position == payload_by_purl.end())
      {
        continue;
      }
      json merged_document = parse_bounded_json(payload_position->second);
      if (merged_document.is_discarded() || !merged_document.is_object())
      {
        continue;  // page 1 itself was unusable; flagged malformed downstream
      }
      json vulns_array = (merged_document.contains("vulns") && merged_document["vulns"].is_array())
                             ? merged_document["vulns"]
                             : json::array();
      for (json& advisory : extra_advisories)
      {
        vulns_array.push_back(std::move(advisory));
      }
      merged_document["vulns"] = std::move(vulns_array);
      // A purl that fully paginated has no token left to report; one still
      // incomplete keeps whatever token is already on `merged_document`
      // (page 1's own) so it is truthfully reported truncated below.
      if (!incomplete_pagination_purls.contains(purl))
      {
        merged_document.erase("next_page_token");
      }
      std::string merged_payload = merged_document.dump();
      cache.store(purl, now, merged_payload);
      payload_position->second = std::move(merged_payload);
    }
  }

  spdlog::info("vuln: {} purl(s) answered from fresh cache, {} fetched from OSV", fresh_cache_count,
               fetched_purl_count);

  // phase 1 (single-threaded): everything the earlier loop below did
  // EXCEPT the network hydration call: malformed/truncated handling, delta
  // computation and snapshot persistence, and (new) the non-network hydration
  // fast path. `purl_work` ends up in the same purl order `payload_by_purl`
  // (a std::map) iterates in, which is what keeps phase 3 byte-identical to
  // the old single-pass loop's output (rule 3).
  struct PurlWork
  {
    std::string purl;
    ExtractedPayload extracted;
    std::optional<std::map<std::string, AdvisoryRecord>> cached_hydration_answer;
  };
  std::vector<PurlWork> purl_work;
  purl_work.reserve(payload_by_purl.size());
  bool pagination_warned = false;
  for (const auto& [purl, payload] : payload_by_purl)
  {
    ExtractedPayload extracted = extract_advisory_revisions(payload);
    if (extracted.malformed)
    {
      result.warn(core::WarningCode::kVulnResponseMalformed,
                  "OSV data for " + purl + " is malformed, ignored");
      continue;
    }
    if (extracted.truncated && !pagination_warned)
    {
      // Distinct from the "did not complete within N rounds" warning above:
      // this fires even for a purl whose pagination we never attempted at all
      // (a fresh-cache or stale-fallback answer inherited from a run that
      // itself gave up): the same honesty rule either way, ids may be
      // incomplete.
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "OSV paginated at least one purl's advisory list and it is not fully resolved, "
                  "ids may be incomplete");
      pagination_warned = true;
    }
    sort_and_deduplicate_revisions(extracted.advisory_revisions);

    // delta: diff this refresh's advisory set against what was stored
    // last time, then persist the new snapshot (preserving first_seen_at for
    // any surviving id). This runs for EVERY resolved purl, including one
    // with zero advisories now and zero before: the common case for a clean
    // repository, and exactly why "feeds update idempotently" must hold
    // across the whole set, not only the vulnerable subset.
    const std::vector<AdvisoryRevision> previous_revisions = cache.lookup_advisory_snapshot(purl);
    PurlAdvisoryDelta delta =
        diff_advisory_revisions(purl, previous_revisions, extracted.advisory_revisions);
    if (extracted.truncated)
    {
      // An INCOMPLETE advisory list must never be trusted as proof an id was
      // REMOVED (rule 1: never claim more accuracy than the data supports) :
      // a previously-known id missing here may simply live on a page
      // pagination never reached. Added/modified ids are kept: those are
      // genuine observations regardless of what else is still missing. The
      // snapshot write below then leaves the un-reached id's row untouched
      // (neither deleted nor refreshed) rather than deleting a still-open
      // vulnerability out from under an incomplete refresh.
      delta.removed_advisory_ids.clear();
    }
    ++result.value.deltas.purls_examined;
    if (delta.is_unchanged())
    {
      ++result.value.deltas.purls_unchanged;
    }
    cache.store_advisory_snapshot(purl, extracted.advisory_revisions, delta.removed_advisory_ids,
                                  now);
    // A truncated answer is never "confirmed" unchanged, however well its
    // observed subset matches the stored snapshot: the whole point of this
    // flag is trusting OSV's own modified timestamps as proof nothing on the
    // FULL list changed, and an incomplete list cannot make that claim: a
    // genuinely new advisory could be sitting on the page pagination never
    // reached, and skipping hydration here would hide it indefinitely.
    const bool detection_confirmed_unchanged =
        delta.is_unchanged() && !stale_answer_purls.count(purl) && !extracted.truncated;
    if (!delta.is_unchanged())
    {
      result.value.deltas.changed_purls.push_back(std::move(delta));
    }

    if (extracted.advisory_revisions.empty())
    {
      continue;
    }

    PurlWork work;
    work.purl = purl;
    work.cached_hydration_answer = try_cached_hydration_answer(
        purl, cache, options, now, oldest_fresh_epoch_seconds, detection_confirmed_unchanged);
    work.extracted = std::move(extracted);
    purl_work.push_back(std::move(work));
  }

  // phase 2: fan the purls `try_cached_hydration_answer` could NOT
  // answer (a real fetch is needed) out across up to
  // `options.max_osv_request_concurrency` concurrent `http_post` calls: the
  // only network dependency between them is none: each hydrates a different
  // purl. `hydration_responses` is indexed by position in `hydration_fetch_indices`,
  // one disjoint slot per worker, so no mutex is needed.
  std::vector<std::size_t> hydration_fetch_indices;
  for (std::size_t work_index = 0; work_index < purl_work.size(); ++work_index)
  {
    if (!purl_work[work_index].cached_hydration_answer.has_value())
    {
      hydration_fetch_indices.push_back(work_index);
    }
  }
  std::vector<core::Result<HttpResponse>> hydration_responses(hydration_fetch_indices.size());
  run_bounded_concurrent(
      hydration_fetch_indices.size(), std::max<std::size_t>(options.max_osv_request_concurrency, 1),
      [&](std::size_t fetch_slot)
      {
        const std::string& query_purl = purl_work[hydration_fetch_indices[fetch_slot]].purl;
        hydration_responses[fetch_slot] = http_post(
            HttpRequest{std::string(kOsvQueryUrl), build_query_object(query_purl).dump()});
      });

  // phase 3 (single-threaded, `purl_work` order == earlier loop order):
  // fold each purl's hydration answer (already known, or just fetched above)
  // into the cache/result and assemble its hit: identical body to the
  // earlier single loop's tail.
  std::size_t fetch_slot = 0;
  for (PurlWork& work : purl_work)
  {
    std::map<std::string, AdvisoryRecord> record_by_id;
    if (work.cached_hydration_answer.has_value())
    {
      record_by_id = std::move(*work.cached_hydration_answer);
    }
    else
    {
      record_by_id =
          finish_hydration_fetch(work.purl, cache, now, hydration_responses[fetch_slot], result);
      ++fetch_slot;
    }

    VulnerabilityHit hit;
    hit.purl = work.purl;
    hit.advisories.reserve(work.extracted.advisory_revisions.size());
    for (const AdvisoryRevision& revision : work.extracted.advisory_revisions)
    {
      core::ScoredAdvisory advisory;
      advisory.id = revision.advisory_id;
      if (const auto record_position = record_by_id.find(revision.advisory_id);
          record_position != record_by_id.end())
      {
        advisory.severity = record_position->second.severity;
        advisory.cve_aliases = record_position->second.cve_aliases;
      }
      hit.advisories.push_back(std::move(advisory));
    }
    // Worst severity first; a total order (ties on id) keeps output byte-stable.
    std::sort(hit.advisories.begin(), hit.advisories.end(), core::more_severe);
    result.value.hits.push_back(std::move(hit));
  }
  // `changed_purls` is already purl-sorted here: phase 1 walks
  // `payload_by_purl` (a std::map, purl-ordered) and appends in that same
  // order, so no further sort is needed (rule 3 is satisfied by
  // construction, not by an extra pass).

  for (const core::Warning& cache_warning : cache.warnings())
  {
    result.warn(cache_warning);
  }

  return result;
}

}  // namespace bomwerk::vuln
