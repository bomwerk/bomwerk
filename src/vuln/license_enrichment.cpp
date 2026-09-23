#include "vuln/license_enrichment.hpp"

#include <spdlog/spdlog.h>

#include <algorithm>
#include <atomic>
#include <charconv>
#include <cstdint>
#include <deque>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "core/joining_thread.hpp"
#include "core/json_utils.hpp"
#include "core/percent.hpp"
#include "core/progress_ticker.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "vuln/cache.hpp"
#include "vuln/endpoints.hpp"

namespace bomwerk::vuln
{
namespace
{

using nlohmann::json;

constexpr std::string_view kLicenseCacheKeySuffix =
    "\x1f"
    "registry-license";
constexpr std::size_t kMaxLicenseTextBytes = 1024;
constexpr std::size_t kMaxLicenseValues = 64;

/// One initial attempt plus two retries: bounds the worst-case latency one
/// stuck lookup can add.
constexpr std::size_t kMaxRegistryGetAttempts = 3;

/// Backoff used between 429 retry attempts when the registry sent no usable
/// `Retry-After` value.
constexpr std::chrono::milliseconds kDefaultRateLimitBackoff(2000);

/// Upper bound on a parsed `Retry-After` value, so a misbehaving or hostile
/// registry cannot stall a lookup indefinitely: the same bounded-by-
/// construction posture as `kMaxHeaderValueBytes`/`kMaxResponseBytes` in
/// http_curl.cpp.
constexpr std::chrono::milliseconds kMaxRateLimitBackoff(30000);

/// How often, in wall-clock seconds, a running fetch pass logs progress.
/// A large, cold cargo corpus (e.g. ~1,650
/// candidates on next.js) legitimately takes tens of minutes with zero
/// intermediate output otherwise, which reads as a hang rather than a slow,
/// working pass. Time-based rather than request-counted: a request-counted
/// heartbeat freezes during a 429 backoff, exactly
/// when a pass looks most stuck.
constexpr std::chrono::seconds kLicenseFallbackHeartbeatInterval(30);

enum class RegistryKind
{
  CratesIo,
  PyPi,
  RubyGems
};

struct Lookup
{
  std::size_t component_index = 0;
  RegistryKind registry = RegistryKind::CratesIo;
  std::string purl;
  std::string url;
  std::string cache_key;
  std::optional<VulnCacheEntry> stale_entry;
  std::string payload;
  bool resolved = false;
};

struct ExtractedLicense
{
  std::string text;
  bool usable_shape = false;
};

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
  }
}

/// Delay-seconds form only: an HTTP-date `Retry-After` cannot be
/// parsed here and is treated the same as an absent header. Trims first, then
/// requires the ENTIRE trimmed string to be a non-negative integer: a
/// partial or garbage parse falls back to `kDefaultRateLimitBackoff` rather
/// than trusting a misread prefix.
std::chrono::milliseconds retry_backoff_for(const std::string& retry_after_header)
{
  const std::string trimmed = core::trimmed(retry_after_header);
  if (!trimmed.empty())
  {
    std::uint64_t seconds_value = 0;
    const char* parse_begin = trimmed.data();
    const char* parse_end = trimmed.data() + trimmed.size();
    const std::from_chars_result parse_result =
        std::from_chars(parse_begin, parse_end, seconds_value);
    if (parse_result.ec == std::errc() && parse_result.ptr == parse_end)
    {
      return std::min(std::chrono::duration_cast<std::chrono::milliseconds>(
                          std::chrono::seconds(seconds_value)),
                      kMaxRateLimitBackoff);
    }
  }
  return kDefaultRateLimitBackoff;
}

/// One registry GET, retried ONLY on HTTP 429: a transport failure
/// (`status_code == 0`) and every other non-200 status (404, 500, ...) both
/// return immediately, unchanged from before this retry helper existed.
/// Called uniformly for crates.io and PyPI/RubyGems lookups alike, so any
/// registry's occasional 429 gets the same treatment even though only
/// crates.io additionally paces requests apart from one another.
core::Result<HttpResponse> get_with_rate_limit_retry(
    const HttpGetFunction& http_get, const std::string& url,
    const std::function<void(std::chrono::milliseconds)>& sleep_for)
{
  core::Result<HttpResponse> response;
  for (std::size_t attempt = 1; attempt <= kMaxRegistryGetAttempts; ++attempt)
  {
    response = http_get(HttpGetRequest{url, {}});
    if (response.value.status_code != 429 || attempt == kMaxRegistryGetAttempts)
    {
      return response;
    }
    const std::chrono::milliseconds backoff = retry_backoff_for(response.value.retry_after);
    spdlog::info("license fallback: {} rate-limited (attempt {}/{}), retrying in {}ms", url,
                 attempt, kMaxRegistryGetAttempts, backoff.count());
    sleep_for(backoff);
  }
  return response;
}

json parse_bounded_json(const std::string& text)
{
  if (core::json_utils::exceeds_json_nesting_depth(text, core::json_utils::kMaxJsonNestingDepth))
  {
    return json(json::value_t::discarded);
  }
  return json::parse(text, nullptr, false);
}

bool is_safe_coordinate(std::string_view coordinate)
{
  if (coordinate.empty() || coordinate == "." || coordinate == "..")
  {
    return false;
  }
  return std::all_of(coordinate.begin(), coordinate.end(),
                     [](char character)
                     {
                       return (character >= 'a' && character <= 'z') ||
                              (character >= '0' && character <= '9') || character == '.' ||
                              character == '_' || character == '+' || character == '-';
                     });
}

std::optional<RegistryKind> registry_for(std::string_view purl_type)
{
  if (purl_type == "cargo")
  {
    return RegistryKind::CratesIo;
  }
  if (purl_type == "pypi")
  {
    return RegistryKind::PyPi;
  }
  if (purl_type == "gem")
  {
    return RegistryKind::RubyGems;
  }
  return std::nullopt;
}

std::string request_url_for(RegistryKind registry, std::string_view name, std::string_view version)
{
  switch (registry)
  {
    case RegistryKind::CratesIo:
      return std::string(kCratesIoCrateVersionApiUrl) + std::string(name) + "/" +
             std::string(version);
    case RegistryKind::PyPi:
      return std::string(kPyPiProjectVersionApiUrl) + std::string(name) + "/" +
             std::string(version) + "/json";
    case RegistryKind::RubyGems:
      return std::string(kRubyGemsVersionApiUrl) + std::string(name) + "/versions/" +
             std::string(version) + ".json";
  }
  return {};
}

std::optional<std::string> bounded_string(const json& value)
{
  if (!value.is_string())
  {
    return std::nullopt;
  }
  std::string text = core::trimmed(value.get<std::string>());
  if (text.size() > kMaxLicenseTextBytes)
  {
    return std::nullopt;
  }
  return text;
}

std::optional<std::string> join_license_values(const json& values)
{
  if (!values.is_array() || values.size() > kMaxLicenseValues)
  {
    return std::nullopt;
  }
  std::vector<std::string> licenses;
  for (const json& value : values)
  {
    const std::optional<std::string> license = bounded_string(value);
    if (!license.has_value())
    {
      return std::nullopt;
    }
    if (!license->empty())
    {
      licenses.push_back(*license);
    }
  }
  std::sort(licenses.begin(), licenses.end());
  licenses.erase(std::unique(licenses.begin(), licenses.end()), licenses.end());

  std::string joined;
  for (const std::string& license : licenses)
  {
    if (!joined.empty())
    {
      joined += " OR ";
    }
    joined += license;
    if (joined.size() > kMaxLicenseTextBytes)
    {
      return std::nullopt;
    }
  }
  return joined;
}

ExtractedLicense extract_crates_io_license(const json& document)
{
  ExtractedLicense extracted;
  if (!document.is_object())
  {
    return extracted;
  }
  const auto version = document.find("version");
  if (version == document.end() || !version->is_object())
  {
    return extracted;
  }
  extracted.usable_shape = true;
  const auto license = version->find("license");
  if (license == version->end() || license->is_null())
  {
    return extracted;
  }
  const std::optional<std::string> text = bounded_string(*license);
  if (!text.has_value())
  {
    extracted.usable_shape = false;
    return extracted;
  }
  extracted.text = *text;
  return extracted;
}

ExtractedLicense extract_pypi_license(const json& document)
{
  ExtractedLicense extracted;
  if (!document.is_object())
  {
    return extracted;
  }
  const auto info = document.find("info");
  if (info == document.end() || !info->is_object())
  {
    return extracted;
  }
  extracted.usable_shape = true;

  // An oversized or wrong-shape field no longer aborts extraction outright:
  // it falls through to the classifier check below instead, since a
  // response with a full-text `license` field often still carries usable
  // `License ::` classifiers. `usable_shape` is only re-asserted false, at
  // the end of this function, if nothing usable ultimately comes out of it.
  bool any_field_oversized_or_malformed = false;
  for (const char* field_name : {"license_expression", "license"})
  {
    const auto field = info->find(field_name);
    if (field == info->end() || field->is_null())
    {
      continue;
    }
    const std::optional<std::string> text = bounded_string(*field);
    if (!text.has_value())
    {
      any_field_oversized_or_malformed = true;
      continue;
    }
    if (!text->empty() && !core::equals_ascii_ignore_case(*text, "unknown"))
    {
      extracted.text = *text;
      return extracted;
    }
  }

  const auto classifiers = info->find("classifiers");
  if (classifiers == info->end() || classifiers->is_null())
  {
    if (any_field_oversized_or_malformed)
    {
      extracted.usable_shape = false;
    }
    return extracted;
  }
  if (!classifiers->is_array() || classifiers->size() > kMaxLicenseValues)
  {
    extracted.usable_shape = false;
    return extracted;
  }

  constexpr std::string_view kLicenseClassifierPrefix = "License :: ";
  std::vector<std::string> license_classifiers;
  for (const json& classifier_value : *classifiers)
  {
    const std::optional<std::string> classifier = bounded_string(classifier_value);
    if (!classifier.has_value())
    {
      extracted.usable_shape = false;
      return extracted;
    }
    if (!classifier->starts_with(kLicenseClassifierPrefix))
    {
      continue;
    }
    const std::size_t leaf_separator = classifier->rfind(" :: ");
    if (leaf_separator == std::string::npos)
    {
      continue;
    }
    std::string leaf = classifier->substr(leaf_separator + 4);
    if (leaf != "OSI Approved")
    {
      license_classifiers.push_back(std::move(leaf));
    }
  }
  std::sort(license_classifiers.begin(), license_classifiers.end());
  license_classifiers.erase(std::unique(license_classifiers.begin(), license_classifiers.end()),
                            license_classifiers.end());
  for (const std::string& classifier : license_classifiers)
  {
    if (!extracted.text.empty())
    {
      extracted.text += "; ";
    }
    extracted.text += classifier;
    if (extracted.text.size() > kMaxLicenseTextBytes)
    {
      extracted.text.clear();
      extracted.usable_shape = false;
      return extracted;
    }
  }
  if (extracted.text.empty() && any_field_oversized_or_malformed)
  {
    extracted.usable_shape = false;
  }
  return extracted;
}

ExtractedLicense extract_rubygems_license(const json& document)
{
  ExtractedLicense extracted;
  if (!document.is_object())
  {
    return extracted;
  }
  extracted.usable_shape = true;
  const auto licenses = document.find("licenses");
  if (licenses == document.end() || licenses->is_null())
  {
    return extracted;
  }
  const std::optional<std::string> text = join_license_values(*licenses);
  if (!text.has_value())
  {
    extracted.usable_shape = false;
    return extracted;
  }
  extracted.text = *text;
  return extracted;
}

ExtractedLicense extract_license(RegistryKind registry, const std::string& payload)
{
  const json document = parse_bounded_json(payload);
  if (document.is_discarded())
  {
    return {};
  }
  switch (registry)
  {
    case RegistryKind::CratesIo:
      return extract_crates_io_license(document);
    case RegistryKind::PyPi:
      return extract_pypi_license(document);
    case RegistryKind::RubyGems:
      return extract_rubygems_license(document);
  }
  return {};
}

std::string cache_payload_for(std::string_view license)
{
  json payload;
  payload["license"] = license;
  return payload.dump();
}

ExtractedLicense extract_cached_license(const std::string& payload)
{
  ExtractedLicense extracted;
  const json document = parse_bounded_json(payload);
  if (document.is_discarded() || !document.is_object())
  {
    return extracted;
  }
  const auto license = document.find("license");
  if (license == document.end())
  {
    return extracted;
  }
  const std::optional<std::string> text = bounded_string(*license);
  if (!text.has_value())
  {
    return extracted;
  }
  extracted.usable_shape = true;
  extracted.text = *text;
  return extracted;
}

}  // namespace

core::Result<LicenseEnrichmentSummary> enrich_component_licenses(
    std::vector<core::Component>& components, const LicenseEnrichmentOptions& options,
    const HttpGetFunction& http_get, const std::function<std::int64_t()>& now_epoch_seconds,
    const std::function<void(std::chrono::milliseconds)>& sleep_for)
{
  core::Result<LicenseEnrichmentSummary> result;
  std::vector<Lookup> lookups;

  for (std::size_t component_index = 0; component_index < components.size(); ++component_index)
  {
    const core::Component& component = components[component_index];
    if (!component.license.empty())
    {
      continue;
    }
    const std::string_view identity_purl = core::purl_identity_part(component.purl);
    const std::optional<RegistryKind> registry = registry_for(core::purl_type_of(identity_purl));
    if (!registry.has_value())
    {
      continue;
    }
    ++result.value.candidate_components;

    std::string name = core::percent_decode(core::purl_name_of(identity_purl));
    if (*registry == RegistryKind::CratesIo)
    {
      std::transform(name.begin(), name.end(), name.begin(),
                     [](char character) { return core::to_lower_ascii(character); });
    }
    const std::string version = core::percent_decode(core::purl_version_of(identity_purl));
    if (!is_safe_coordinate(name) || !is_safe_coordinate(version))
    {
      ++result.value.skipped_components;
      continue;
    }

    Lookup lookup;
    lookup.component_index = component_index;
    lookup.registry = *registry;
    lookup.purl = component.purl;
    lookup.url = request_url_for(*registry, name, version);
    lookup.cache_key = std::string(identity_purl) + std::string(kLicenseCacheKeySuffix);
    lookups.push_back(std::move(lookup));
  }

  if (result.value.skipped_components > 0)
  {
    result.warn(core::WarningCode::kLicenseFallbackIncomplete,
                "license fallback: " + std::to_string(result.value.skipped_components) +
                    " component(s) have a missing or unsafe registry name/version, skipped");
  }
  if (lookups.empty())
  {
    return result;
  }

  const std::filesystem::path cache_database_path = options.cache_database_path.empty()
                                                        ? default_cache_database_path()
                                                        : options.cache_database_path;
  core::Result<VulnCache> cache_open = VulnCache::open(cache_database_path);
  for (core::Warning& warning : cache_open.warnings)
  {
    result.warn(std::move(warning));
  }
  VulnCache cache = std::move(cache_open.value);

  const std::int64_t now = now_epoch_seconds();
  const std::int64_t oldest_fresh_epoch_seconds = now - options.cache_max_age.count();
  std::vector<std::size_t> lookup_indices_to_fetch;
  for (std::size_t lookup_index = 0; lookup_index < lookups.size(); ++lookup_index)
  {
    Lookup& lookup = lookups[lookup_index];
    std::optional<VulnCacheEntry> cached_entry = cache.lookup(lookup.cache_key);
    if (cached_entry.has_value() &&
        cached_entry->fetched_at_epoch_seconds >= oldest_fresh_epoch_seconds)
    {
      lookup.payload = std::move(cached_entry->payload);
      lookup.resolved = true;
      ++result.value.fresh_cache_answers;
      continue;
    }
    lookup.stale_entry = std::move(cached_entry);
    if (lookup.stale_entry.has_value())
    {
      ++result.value.expired_cache_lookups;
    }
    else
    {
      ++result.value.never_fetched_lookups;
    }
    lookup_indices_to_fetch.push_back(lookup_index);
  }

  std::size_t unusable_payload_count = 0;
  if (options.offline)
  {
    for (const std::size_t lookup_index : lookup_indices_to_fetch)
    {
      Lookup& lookup = lookups[lookup_index];
      if (lookup.stale_entry.has_value())
      {
        lookup.payload = std::move(lookup.stale_entry->payload);
        lookup.resolved = true;
        ++result.value.stale_cache_answers;
      }
      else
      {
        ++result.value.unresolved_components;
      }
    }
  }
  else
  {
    std::vector<core::Result<HttpResponse>> responses(lookup_indices_to_fetch.size());

    // a shared, wall-clock-gated heartbeat (see core/progress_ticker.hpp)
    // covers BOTH sub-passes below, unlike the old crates.io-only,
    // request-counted heartbeat that froze during a 429 backoff. `deadline_epoch_seconds`
    // is `time_budget`'s cutoff, or unreachable when no budget was given :
    // either way both sub-passes just compare against one shared value.
    const std::int64_t deadline_epoch_seconds = options.time_budget.has_value()
                                                    ? now + options.time_budget->count()
                                                    : std::numeric_limits<std::int64_t>::max();
    std::vector<std::uint8_t> timed_out_positions(lookup_indices_to_fetch.size(), 0);
    core::ProgressTicker heartbeat_ticker(now_epoch_seconds, kLicenseFallbackHeartbeatInterval);
    std::atomic<std::size_t> completed_fetch_count{0};

    if (!lookup_indices_to_fetch.empty())
    {
      spdlog::info(
          "license fallback: {} lookup(s) need a registry fetch ({} never cached, {} cache "
          "entries expired)",
          lookup_indices_to_fetch.size(), result.value.never_fetched_lookups,
          result.value.expired_cache_lookups);
    }

    // Split by registry: crates.io rate-limits aggressively and must run
    // strictly sequentially, paced apart; PyPI/RubyGems do not and keep the
    // existing bounded-concurrent fan-out. Order within each list mirrors
    // `lookup_indices_to_fetch`'s order, so which sub-pass fetched a given
    // response never affects the fixed-order bucketing loop below it (rule 3:
    // deterministic regardless of wall-clock timing).
    std::vector<std::size_t> crates_io_request_positions;
    std::vector<std::size_t> other_request_positions;
    for (std::size_t request_index = 0; request_index < lookup_indices_to_fetch.size();
         ++request_index)
    {
      if (lookups[lookup_indices_to_fetch[request_index]].registry == RegistryKind::CratesIo)
      {
        crates_io_request_positions.push_back(request_index);
      }
      else
      {
        other_request_positions.push_back(request_index);
      }
    }

    // Run crates.io's throttled, sequential pass on its own thread so its
    // pacing latency overlaps the PyPI/RubyGems pass below rather than
    // stacking on top of it: the same "threading buys latency, never
    // concurrency against the feed" reasoning `match_via_cpe` applies to NVD.
    // Neither pass touches `cache` or mutates `components`/`lookups`; each
    // only writes its own disjoint `responses`/`timed_out_positions` positions,
    // so the join below is the only synchronization this needs.
    std::optional<core::JoiningThread> crates_io_thread;
    std::int64_t crates_io_estimated_seconds = 0;
    if (!crates_io_request_positions.empty())
    {
      // Set expectations before the wait starts, not after: with no cache hit
      // for any of these, this pass alone takes roughly this long, by design
      // (crates.io rate-limits aggressively; PyPI/RubyGems do not need this).
      crates_io_estimated_seconds = static_cast<std::int64_t>(crates_io_request_positions.size()) *
                                    kCratesIoRequestInterval.count() / 1000;
      spdlog::info(
          "license fallback: {} crates.io lookup(s) not yet cached, paced at {}ms apart -- "
          "expect roughly {}s for this pass alone",
          crates_io_request_positions.size(), kCratesIoRequestInterval.count(),
          crates_io_estimated_seconds);

      crates_io_thread.emplace(
          [&crates_io_request_positions, &responses, &lookups, &lookup_indices_to_fetch, &http_get,
           &sleep_for, &now_epoch_seconds, deadline_epoch_seconds, &timed_out_positions,
           &heartbeat_ticker, &completed_fetch_count]
          {
            bool has_issued_crates_io_request = false;
            for (const std::size_t request_index : crates_io_request_positions)
            {
              if (now_epoch_seconds() >= deadline_epoch_seconds)
              {
                timed_out_positions[request_index] = 1;
                continue;
              }
              if (has_issued_crates_io_request)
              {
                sleep_for(kCratesIoRequestInterval);
              }
              has_issued_crates_io_request = true;
              const Lookup& lookup = lookups[lookup_indices_to_fetch[request_index]];
              responses[request_index] = get_with_rate_limit_retry(http_get, lookup.url, sleep_for);
              const std::size_t completed = ++completed_fetch_count;
              if (heartbeat_ticker.should_tick())
              {
                spdlog::info("license fallback: {}/{} lookup(s) done", completed,
                             lookup_indices_to_fetch.size());
              }
            }
          });
    }

    run_bounded_concurrent(
        other_request_positions.size(), options.max_request_concurrency,
        [&](std::size_t position_index)
        {
          const std::size_t request_index = other_request_positions[position_index];
          if (now_epoch_seconds() >= deadline_epoch_seconds)
          {
            timed_out_positions[request_index] = 1;
            return;
          }
          const Lookup& lookup = lookups[lookup_indices_to_fetch[request_index]];
          responses[request_index] = get_with_rate_limit_retry(http_get, lookup.url, sleep_for);
          const std::size_t completed = ++completed_fetch_count;
          if (heartbeat_ticker.should_tick())
          {
            spdlog::info("license fallback: {}/{} lookup(s) done", completed,
                         lookup_indices_to_fetch.size());
          }
        });

    if (crates_io_thread.has_value())
    {
      crates_io_thread->join();
    }

    for (std::size_t request_index = 0; request_index < responses.size(); ++request_index)
    {
      Lookup& lookup = lookups[lookup_indices_to_fetch[request_index]];
      core::Result<HttpResponse>& response = responses[request_index];
      for (core::Warning& warning : response.warnings)
      {
        result.warn(std::move(warning));
      }

      bool fetched = false;
      if (response.value.status_code == 200)
      {
        const ExtractedLicense extracted = extract_license(lookup.registry, response.value.body);
        if (extracted.usable_shape)
        {
          lookup.payload = cache_payload_for(extracted.text);
          lookup.resolved = true;
          cache.store(lookup.cache_key, now, lookup.payload);
          ++result.value.fetched_answers;
          fetched = true;
        }
        else
        {
          ++unusable_payload_count;
        }
      }

      if (fetched)
      {
        continue;
      }
      if (lookup.stale_entry.has_value())
      {
        lookup.payload = std::move(lookup.stale_entry->payload);
        lookup.resolved = true;
        ++result.value.stale_cache_answers;
      }
      else if (response.value.status_code == 429)
      {
        ++result.value.rate_limited_components;
      }
      else
      {
        ++result.value.unresolved_components;
        if (timed_out_positions[request_index] != 0)
        {
          ++result.value.timed_out_components;
        }
      }
    }

    if (!lookup_indices_to_fetch.empty())
    {
      const std::int64_t elapsed_seconds = now_epoch_seconds() - now;
      spdlog::info(
          "license fallback: fetch pass finished in {}s (estimated {}s for crates.io alone) -- "
          "{} from fresh cache, {} fetched from network, {} from stale cache",
          elapsed_seconds, crates_io_estimated_seconds, result.value.fresh_cache_answers,
          result.value.fetched_answers, result.value.stale_cache_answers);
    }
  }

  std::size_t unusable_cache_count = 0;
  for (Lookup& lookup : lookups)
  {
    if (!lookup.resolved)
    {
      continue;
    }
    const ExtractedLicense extracted = extract_cached_license(lookup.payload);
    if (!extracted.usable_shape)
    {
      ++unusable_cache_count;
      ++result.value.unresolved_components;
      continue;
    }
    if (!extracted.text.empty())
    {
      components[lookup.component_index].license = extracted.text;
      ++result.value.enriched_components;
    }
  }

  if (result.value.stale_cache_answers > 0)
  {
    result.warn(core::WarningCode::kVulnCoverageIncomplete,
                "license fallback: " + std::to_string(result.value.stale_cache_answers) +
                    " component(s) answered from stale cache entries");
  }
  if (result.value.unresolved_components > 0)
  {
    result.warn(core::WarningCode::kVulnCoverageIncomplete,
                "license fallback: no registry data for " +
                    std::to_string(result.value.unresolved_components) + " component(s)");
  }
  if (result.value.rate_limited_components > 0)
  {
    result.warn(core::WarningCode::kVulnCoverageIncomplete,
                "license fallback: rate-limited by the registry, " +
                    std::to_string(result.value.rate_limited_components) +
                    " component(s) left unenriched: rerun to complete");
  }
  if (result.value.timed_out_components > 0)
  {
    result.warn(core::WarningCode::kLicenseFallbackIncomplete,
                "license fallback: time budget of " + std::to_string(options.time_budget->count()) +
                    "s reached, " + std::to_string(result.value.timed_out_components) +
                    " component(s) left unenriched: the SBOM is complete, only enrichment "
                    "was cut short, rerun without --license-fallback-timeout to finish");
  }
  if (unusable_payload_count > 0)
  {
    result.warn(core::WarningCode::kLicenseFallbackIncomplete,
                "license fallback: " + std::to_string(unusable_payload_count) +
                    " registry response(s) had malformed or oversized license metadata");
  }
  if (unusable_cache_count > 0)
  {
    result.warn(core::WarningCode::kLicenseFallbackIncomplete,
                "license fallback: " + std::to_string(unusable_cache_count) +
                    " cached response(s) had malformed license metadata");
  }
  for (const core::Warning& cache_warning : cache.warnings())
  {
    result.warn(cache_warning);
  }
  return result;
}

}  // namespace bomwerk::vuln
