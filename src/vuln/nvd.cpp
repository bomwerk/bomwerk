#include "vuln/nvd.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
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
struct ExtractedPayload
{
  std::vector<core::ScoredAdvisory> advisories;
  bool truncated = false;  ///< totalResults exceeded what one page returned
  bool malformed = false;  ///< payload was not the expected JSON shape
};

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

/// Sort worst-severity-first and drop duplicate ids, so a hit's advisory list
/// is byte-stable regardless of the order NVD returned them (rule 3).
void finalize_advisories(std::vector<core::ScoredAdvisory>& advisories)
{
  std::sort(advisories.begin(), advisories.end(), core::more_severe);
  const auto duplicate_begin =
      std::unique(advisories.begin(), advisories.end(),
                  [](const core::ScoredAdvisory& left, const core::ScoredAdvisory& right)
                  { return left.id == right.id; });
  advisories.erase(duplicate_begin, advisories.end());
}

}  // namespace

core::Result<MatchOutcome> match_via_cpe(
    const std::vector<core::Component>& components, const NvdOptions& options,
    const HttpGetFunction& http_get, const std::function<std::int64_t()>& now_epoch_seconds,
    const std::function<void(std::chrono::milliseconds)>& sleep_for)
{
  core::Result<MatchOutcome> result;

  // One query per distinct CPE, but a CPE may stand for several components
  // (`pkg:conan/zlib@1.2.11` and `pkg:vcpkg/zlib@1.2.11` produce the same
  // match string), so the answer fans back out to every purl behind it. The
  // maps are ordered, which is where this function's determinism starts.
  std::map<std::string, std::set<std::string>> purls_by_cpe;
  std::size_t unconvertible_component_count = 0;
  for (const core::Component& component : components)
  {
    if (core::classify_match_coverage(component) != core::MatchCoverage::UnmappedPurlType)
    {
      continue;  // OSV can match it; sending it here would only add false positives
    }
    const std::optional<std::string> cpe_match_string = cpe_match_string_for(component.purl);
    if (!cpe_match_string.has_value())
    {
      ++unconvertible_component_count;
      continue;
    }
    // The component's purl VERBATIM, qualifiers included. `cpe_match_string_for`
    // already strips them for the query itself, but every consumer of the
    // result: the report's per-row badge lookup, the CLI's uncovered list :
    // joins on `Component::purl` as stored, so a stripped key here would
    // silently fail to match a component carrying `?os=linux`.
    purls_by_cpe[*cpe_match_string].insert(component.purl);
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
  const std::chrono::milliseconds request_interval =
      options.api_key.empty() ? kNvdIntervalWithoutApiKey : kNvdIntervalWithApiKey;

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
  bool truncation_warned = false;
  bool has_issued_request = false;

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
    // answered entirely from cache never sleeps at all.
    if (has_issued_request)
    {
      sleep_for(request_interval);
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
                    " CPE(s), those components remain unchecked");
  }

  // Assemble hits. Map iteration is CPE-ordered and the purls behind each CPE
  // are a sorted set, so the walk is deterministic before the final sort
  // (rule 3).
  for (const auto& [cpe_match_string, purls] : purls_by_cpe)
  {
    const auto payload_position = payload_by_cpe.find(cpe_match_string);
    if (payload_position == payload_by_cpe.end())
    {
      continue;  // unresolved: already counted and warned about above
    }

    ExtractedPayload extracted = extract_advisories(payload_position->second);
    if (extracted.malformed)
    {
      result.warn(core::WarningCode::kVulnResponseMalformed,
                  "NVD data for " + cpe_match_string + " is malformed, ignored");
      continue;
    }
    // Every purl behind this CPE was genuinely checked, even when the answer
    // was "nothing known": that is the distinction this list exists for. A
    // CPE with no resolved payload never reaches here, so an unchecked
    // component can never appear as checked.
    for (const std::string& purl : purls)
    {
      result.value.cpe_checked_purls.push_back(purl);
    }

    if (extracted.truncated && !truncation_warned)
    {
      result.warn(core::WarningCode::kVulnCoverageIncomplete,
                  "NVD returned more advisories than one page holds for at least one component. "
                  "The advisory list may be incomplete");
      truncation_warned = true;
    }
    if (extracted.advisories.empty())
    {
      continue;
    }
    finalize_advisories(extracted.advisories);

    for (const std::string& purl : purls)
    {
      VulnerabilityHit hit;
      hit.purl = purl;
      hit.advisories = extracted.advisories;
      hit.provenance = MatchProvenance::CpeFallback;
      result.value.hits.push_back(std::move(hit));
    }
  }

  // Two CPEs can contribute hits for different purls, so the accumulated order
  // is CPE-major; sorting by purl restores the identity order every consumer
  // expects and makes this agree with the OSV pass (rule 3). The checked-purl
  // list is sorted for the same reason.
  std::sort(result.value.hits.begin(), result.value.hits.end(),
            [](const VulnerabilityHit& left, const VulnerabilityHit& right)
            { return left.purl < right.purl; });
  std::sort(result.value.cpe_checked_purls.begin(), result.value.cpe_checked_purls.end());

  spdlog::info("vuln: CPE fallback: {} CPE(s) from fresh cache, {} fetched from NVD",
               fresh_cache_count, fetched_count);

  for (const core::Warning& cache_warning : cache.warnings())
  {
    result.warn(cache_warning);
  }

  return result;
}

}  // namespace bomwerk::vuln
