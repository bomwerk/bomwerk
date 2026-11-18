#include "vuln/nvd.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/cvss.hpp"
#include "core/json_utils.hpp"
#include "core/match_coverage.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "vuln/cache.hpp"
#include "vuln/cpe.hpp"

namespace bomwerk::vuln
{
namespace
{

using nlohmann::json;

/// A US (unit-separator) byte never appears in a CPE match string, so
/// suffixing it lets NVD payloads share the purl-keyed cache table with OSV's
/// entries without a schema change and without ever colliding with one. Same
/// trick `osv.cpp` uses for its full-advisory payloads.
constexpr std::string_view kNvdCacheKeySuffix =
    "\x1f"
    "nvd";

/// Appended to the "remain unchecked" warnings. A reviewed operating system
/// is asked under two CPEs, so when only one of them answered, its findings
/// are still shown for a component this warning calls unchecked.
constexpr std::string_view kPartialAnswerNote =
    " (a finding shown for one of them comes from another of its CPEs that did answer, and may "
    "be incomplete)";

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

/// The full request URL for one CPE match string. The match string is already
/// validated to a strict allowlist by `cpe_match_string_for`; percent-encoding
/// on top is belt-and-braces so this can never become a query-injection point.
std::string request_url_for(const std::string& cpe_match_string)
{
  std::string url(kNvdCveApiUrl);
  url += "?virtualMatchString=";
  url += percent_encode_query_value(cpe_match_string);
  url += "&resultsPerPage=";
  url += std::to_string(kNvdResultsPerPage);
  return url;
}

/// The best CVSS v3.1 severity in one CVE's `metrics` object. NVD may record
/// several scorings per CVE; the `type: "Primary"` entry is NIST's own and
/// wins outright, otherwise the highest-scoring secondary is used. An absent
/// or unparseable vector yields an unscored (Unknown) result: never a
/// misleading 0, since a CRA tool must not present an unscored advisory as
/// harmless.
core::CvssScore best_severity(const json& metrics_object)
{
  core::CvssScore best;  // has_score == false => Unknown
  if (!metrics_object.is_object())
  {
    return best;
  }
  const auto v31_field = metrics_object.find("cvssMetricV31");
  if (v31_field == metrics_object.end() || !v31_field->is_array())
  {
    return best;
  }
  for (const json& metric : *v31_field)
  {
    if (!metric.is_object())
    {
      continue;
    }
    const auto cvss_data_field = metric.find("cvssData");
    if (cvss_data_field == metric.end() || !cvss_data_field->is_object())
    {
      continue;
    }
    const auto vector_field = cvss_data_field->find("vectorString");
    if (vector_field == cvss_data_field->end() || !vector_field->is_string())
    {
      continue;
    }
    const core::CvssScore candidate = core::score_cvss_vector(vector_field->get<std::string>());
    if (!candidate.has_score)
    {
      continue;
    }
    const auto type_field = metric.find("type");
    const bool is_primary = type_field != metric.end() && type_field->is_string() &&
                            type_field->get<std::string>() == "Primary";
    if (is_primary)
    {
      return candidate;  // NIST's own scoring settles it
    }
    if (!best.has_score || candidate.score > best.score)
    {
      best = candidate;
    }
  }
  return best;
}

/// What one CPE's cached/fetched payload (a whole CVE API 2.0 response object)
/// contains.
using ExtractedPayload = NvdCvePayload;

ExtractedPayload extract_advisories(const std::string& payload)
{
  ExtractedPayload extracted;
  const json document = parse_bounded_json(payload);
  if (document.is_discarded() || !document.is_object())
  {
    extracted.malformed = true;
    return extracted;
  }
  const auto vulnerabilities_field = document.find("vulnerabilities");
  if (vulnerabilities_field == document.end())
  {
    // A well-formed "nothing known" answer still carries the array; a response
    // without it is not a shape we recognize.
    extracted.malformed = true;
    return extracted;
  }
  if (!vulnerabilities_field->is_array())
  {
    extracted.malformed = true;
    return extracted;
  }

  for (const json& entry : *vulnerabilities_field)
  {
    if (!entry.is_object())
    {
      continue;
    }
    const auto cve_field = entry.find("cve");
    if (cve_field == entry.end() || !cve_field->is_object())
    {
      continue;
    }
    const auto id_field = cve_field->find("id");
    if (id_field == cve_field->end() || !id_field->is_string())
    {
      continue;
    }
    core::ScoredAdvisory advisory;
    advisory.id = id_field->get<std::string>();
    if (const auto metrics_field = cve_field->find("metrics"); metrics_field != cve_field->end())
    {
      advisory.severity = best_severity(*metrics_field);
    }
    extracted.advisories.push_back(std::move(advisory));
  }

  if (const auto total_field = document.find("totalResults");
      total_field != document.end() && total_field->is_number_unsigned() &&
      total_field->get<std::size_t>() > extracted.advisories.size())
  {
    extracted.truncated = true;
  }
  return extracted;
}

/// Drop duplicate ids, then sort worst-severity-first, so a hit's advisory
/// list is byte-stable regardless of the order NVD returned them (rule 3).
/// Duplicates are grouped by id first, worst copy leading, so a CVE named by
/// both the part `a` and the part `o` answer survives once, at its worst
/// severity, even if the two answers ever scored it differently.
void finalize_advisories(std::vector<core::ScoredAdvisory>& advisories)
{
  std::sort(advisories.begin(), advisories.end(),
            [](const core::ScoredAdvisory& left, const core::ScoredAdvisory& right)
            {
              if (left.id != right.id)
              {
                return left.id < right.id;
              }
              return core::more_severe(left, right);
            });
  const auto duplicate_begin =
      std::unique(advisories.begin(), advisories.end(),
                  [](const core::ScoredAdvisory& left, const core::ScoredAdvisory& right)
                  { return left.id == right.id; });
  advisories.erase(duplicate_begin, advisories.end());
  std::sort(advisories.begin(), advisories.end(), core::more_severe);
}

/// True when the caller supplied a stop predicate and it says stop now.
bool stop_requested(const NvdOptions& options)
{
  return options.should_stop && options.should_stop();
}

}  // namespace

std::chrono::milliseconds nvd_request_interval(const NvdOptions& options)
{
  return options.api_key.empty() ? kNvdIntervalWithoutApiKey : kNvdIntervalWithApiKey;
}

bool wait_for_nvd_interval(std::chrono::milliseconds interval,
                           const std::function<bool()>& should_stop,
                           const std::function<void(std::chrono::milliseconds)>& sleep_for)
{
  if (!should_stop)
  {
    sleep_for(interval);
    return true;
  }
  std::chrono::milliseconds remaining = interval;
  while (remaining.count() > 0)
  {
    if (should_stop())
    {
      return false;
    }
    const std::chrono::milliseconds slice = std::min(remaining, kNvdStopCheckInterval);
    sleep_for(slice);
    remaining -= slice;
  }
  return !should_stop();
}

NvdCvePayload parse_nvd_cve_payload(const std::string& payload)
{
  return extract_advisories(payload);
}

core::Result<MatchOutcome> match_via_cpe(
    const std::vector<core::Component>& components, const NvdOptions& options,
    const HttpGetFunction& http_get, const std::function<std::int64_t()>& now_epoch_seconds,
    const std::function<void(std::chrono::milliseconds)>& sleep_for)
{
  core::Result<MatchOutcome> result;

  // One query per distinct CPE, but a CPE may stand for several components
  // (`pkg:conan/zlib@1.2.11` and `pkg:vcpkg/zlib@1.2.11` produce the same
  // match string), so the answer fans back out to every purl behind it. A
  // component may also stand behind several CPEs (a reviewed operating system
  // is asked as part `a` and part `o`). The map is ordered, which is where
  // this function's determinism starts.
  std::map<std::string, std::set<std::string>> purls_by_cpe;
  std::size_t unconvertible_component_count = 0;
  for (const core::Component& component : components)
  {
    if (core::classify_match_coverage(component) != core::MatchCoverage::UnmappedPurlType)
    {
      continue;  // OSV can match it; sending it here would only add false positives
    }
    const std::vector<std::string> cpe_match_strings = cpe_match_strings_for(component.purl);
    if (cpe_match_strings.empty())
    {
      ++unconvertible_component_count;
      continue;
    }
    // The component's purl VERBATIM, qualifiers included. `cpe_match_strings_for`
    // already strips them for the query itself, but every consumer of the
    // result: the report's per-row badge lookup, the CLI's uncovered list :
    // joins on `Component::purl` as stored, so a stripped key here would
    // silently fail to match a component carrying `?os=linux`.
    for (const std::string& cpe_match_string : cpe_match_strings)
    {
      purls_by_cpe[cpe_match_string].insert(component.purl);
    }
  }

  if (unconvertible_component_count > 0)
  {
    // Degraded coverage, not a parse failure: say so plainly rather than
    // letting these components look checked (rule: never claim more accuracy
    // than the data supports).
    result.warn(core::WarningCode::kVulnCoverageIncomplete,
                "CPE fallback: " + std::to_string(unconvertible_component_count) +
                    " component(s) have a name or version that cannot form a safe CPE, not "
                    "checked");
  }
  if (purls_by_cpe.empty())
  {
    return result;
  }

  // The cache is an optimization, never a requirement (rule 1): any open
  // failure was already turned into a warning, and a closed cache behaves as
  // permanent miss / no-op store. This is a SECOND connection to the same
  // file the OSV pass uses: safe by design, see cache.hpp.
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
  const std::chrono::milliseconds request_interval = nvd_request_interval(options);

  std::vector<std::string> request_headers;
  if (!options.api_key.empty())
  {
    // NVD reads the key from this header. It is built here and never logged.
    request_headers.push_back("apiKey: " + options.api_key);
  }

  std::map<std::string, std::string> payload_by_cpe;
  std::size_t fresh_cache_count = 0;
  std::size_t fetched_count = 0;
  std::size_t stale_fallback_count = 0;
  std::size_t unresolved_count = 0;
  std::size_t not_queried_count = 0;
  bool truncation_warned = false;
  bool has_issued_request = false;
  bool stopped = false;

  // Keyed iteration rather than a structured binding: the purls behind each CPE
  // are irrelevant until the assembly loop below, and one query answers all of
  // them.
  for (const auto& cpe_entry : purls_by_cpe)
  {
    const std::string& cpe_match_string = cpe_entry.first;
    const std::string cache_key = cpe_match_string + std::string(kNvdCacheKeySuffix);
    std::optional<VulnCacheEntry> cached_entry = cache.lookup(cache_key);
    // Fresh means "not older than the horizon", so an entry aged exactly
    // cache_max_age still answers.
    if (cached_entry.has_value() &&
        cached_entry->fetched_at_epoch_seconds >= oldest_fresh_epoch_seconds)
    {
      payload_by_cpe.insert_or_assign(cpe_match_string, std::move(cached_entry->payload));
      ++fresh_cache_count;
      continue;
    }

    if (options.offline)
    {
      // Offline, stale knowledge beats none: but both stale answers and
      // holes are stated plainly rather than passed off as a clean check.
      if (cached_entry.has_value())
      {
        payload_by_cpe.insert_or_assign(cpe_match_string, std::move(cached_entry->payload));
        ++stale_fallback_count;
      }
      else
      {
        ++unresolved_count;
      }
      continue;
    }

    // Throttle BETWEEN requests only: the first costs nothing, and a run
    // answered entirely from cache never sleeps at all. A stop seen before or
    // during the wait abandons this request and every later one; nothing is
    // ever sent sooner than the interval allows.
    stopped = stopped || stop_requested(options) ||
              (has_issued_request &&
               !wait_for_nvd_interval(request_interval, options.should_stop, sleep_for));
    if (stopped)
    {
      if (cached_entry.has_value())
      {
        payload_by_cpe.insert_or_assign(cpe_match_string, std::move(cached_entry->payload));
        ++stale_fallback_count;
      }
      else
      {
        ++not_queried_count;
      }
      continue;
    }
    has_issued_request = true;

    core::Result<HttpResponse> response =
        http_get(HttpGetRequest{request_url_for(cpe_match_string), request_headers});
    for (core::Warning& transport_warning : response.warnings)
    {
      result.warn(std::move(transport_warning));
    }

    bool stored = false;
    if (response.value.status_code == 200)
    {
      const json parsed = parse_bounded_json(response.value.body);
      if (!parsed.is_discarded() && parsed.is_object())
      {
        // dump() of a (map-based) nlohmann::json emits sorted keys, so the
        // cached payload bytes are canonical (rule 3).
        std::string payload = parsed.dump();
        cache.store(cache_key, now, payload);
        payload_by_cpe.insert_or_assign(cpe_match_string, std::move(payload));
        ++fetched_count;
        stored = true;
      }
      else
      {
        result.warn(core::WarningCode::kVulnResponseMalformed,
                    "NVD response for " + cpe_match_string + " is malformed, ignored");
      }
    }
    else if (response.value.status_code != 0)
    {
      result.warn(core::WarningCode::kVulnHttpUnexpectedStatus,
                  "NVD query returned HTTP " + std::to_string(response.value.status_code) +
                      " for " + cpe_match_string);
    }

    if (stored)
    {
      continue;
    }
    if (cached_entry.has_value())
    {
      payload_by_cpe.insert_or_assign(cpe_match_string, std::move(cached_entry->payload));
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
                "CPE fallback: " + std::to_string(stale_fallback_count) +
                    " CPE(s) answered from cache entries older than the refresh horizon");
  }
  if (unresolved_count > 0)
  {
    result.warn(core::WarningCode::kVulnCoverageIncomplete,
                "CPE fallback: no NVD data for " + std::to_string(unresolved_count) +
                    " CPE(s), those components remain unchecked" + std::string(kPartialAnswerNote));
  }
  if (not_queried_count > 0)
  {
    result.warn(core::WarningCode::kVulnCoverageIncomplete,
                "CPE fallback: stopped before querying " + std::to_string(not_queried_count) +
                    " CPE(s), those components remain unchecked" + std::string(kPartialAnswerNote));
  }

  // Assemble per purl. Map iteration is CPE-ordered and the purls behind each
  // CPE are a sorted set, so the walk is deterministic, and the per-purl maps
  // below are ordered by purl, which is the order every consumer expects and
  // the one the OSV pass uses (rule 3).
  std::map<std::string, std::vector<core::ScoredAdvisory>> advisories_by_purl;
  // Purls with at least one CPE that did not answer usably.
  std::set<std::string> partly_unanswered_purls;
  for (const auto& [cpe_match_string, purls] : purls_by_cpe)
  {
    const auto payload_position = payload_by_cpe.find(cpe_match_string);
    if (payload_position == payload_by_cpe.end())
    {
      // Unresolved: already counted and warned about above.
      partly_unanswered_purls.insert(purls.begin(), purls.end());
      continue;
    }

    ExtractedPayload extracted = extract_advisories(payload_position->second);
    if (extracted.malformed)
    {
      result.warn(core::WarningCode::kVulnResponseMalformed,
                  "NVD data for " + cpe_match_string + " is malformed, ignored");
      partly_unanswered_purls.insert(purls.begin(), purls.end());
      continue;
    }
    if (extracted.truncated && !truncation_warned)
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "NVD returned more advisories than one page holds for at least one component. "
                  "The advisory list may be incomplete");
      truncation_warned = true;
    }
    for (const std::string& purl : purls)
    {
      std::vector<core::ScoredAdvisory>& merged = advisories_by_purl[purl];
      merged.insert(merged.end(), extracted.advisories.begin(), extracted.advisories.end());
    }
  }

  for (auto& [purl, advisories] : advisories_by_purl)
  {
    // A purl was genuinely checked, even when the answer was "nothing known",
    // only when EVERY CPE behind it answered: an operating system whose part
    // `o` query failed was not checked where NVD files most of its CVEs, so it
    // must not be listed as checked. What did answer is still reported below,
    // and the unresolved CPE was already warned about.
    if (!partly_unanswered_purls.contains(purl))
    {
      result.value.cpe_checked_purls.push_back(purl);
    }
    if (advisories.empty())
    {
      continue;
    }
    // The part `a` and part `o` answers can name the same CVE; finalizing
    // keeps it once.
    finalize_advisories(advisories);
    VulnerabilityHit hit;
    hit.purl = purl;
    hit.advisories = std::move(advisories);
    hit.provenance = MatchProvenance::CpeFallback;
    result.value.hits.push_back(std::move(hit));
  }

  spdlog::info("vuln: CPE fallback: {} CPE(s) from fresh cache, {} fetched from NVD",
               fresh_cache_count, fetched_count);

  for (const core::Warning& cache_warning : cache.warnings())
  {
    result.warn(cache_warning);
  }

  return result;
}

}  // namespace bomwerk::vuln
