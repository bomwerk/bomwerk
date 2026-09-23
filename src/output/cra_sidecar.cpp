#include "output/cra_sidecar.hpp"

#include <array>
#include <nlohmann/json.hpp>
#include <string_view>

namespace bomwerk::output
{
namespace
{

/// Suffixes `cra_sidecar_path_for` strips in addition to the file extension
/// itself: the same list the consumer's own auto-discovery tries, so
/// writing the short form stays a strict subset of what it will find.
constexpr std::array<std::string_view, 4> kKnownFormatSuffixes = {".cdx", ".cyclonedx", ".spdx",
                                                                  ".spdx3"};

/// Length of a bare `YYYY-MM-DD` date (10 characters): the shape
/// `ReleaseMeta::support_until` is documented to hold today.
constexpr std::size_t kIsoDateLength = 10;

/// Widen a bare ISO-8601 date to a full RFC-3339 UTC datetime for
/// `supportEndDate`: see the header doc comment for why this matters.
std::string widened_to_rfc3339(const std::string& date_or_datetime)
{
  const bool already_a_datetime = date_or_datetime.find('T') != std::string::npos;
  const bool looks_like_bare_date = date_or_datetime.size() == kIsoDateLength;
  if (!already_a_datetime && looks_like_bare_date)
  {
    return date_or_datetime + "T00:00:00Z";
  }
  return date_or_datetime;
}

}  // namespace

bool has_cra_sidecar_content(const core::ReleaseMeta& release_meta,
                             const core::CraMetadata& cra_metadata)
{
  return !release_meta.product_id.empty() || !release_meta.support_until.empty() ||
         !cra_metadata.manufacturer_name.empty() || !cra_metadata.manufacturer_email.empty() ||
         !cra_metadata.security_contact.empty() ||
         !cra_metadata.vulnerability_disclosure_url.empty();
}

std::string write_cra_sidecar(const core::ReleaseMeta& release_meta,
                              const core::CraMetadata& cra_metadata)
{
  // Explicitly an object, not default-constructed null: when every field
  // below is empty, no `operator[]` assignment ever runs to establish that
  // implicitly, and a bare `null` is not what an empty sidecar should dump
  // as (`has_cra_sidecar_content` should have kept the caller from writing
  // one at all, but this function's own output must be valid JSON regardless
  // of who calls it or with what).
  nlohmann::json sidecar = nlohmann::json::object();
  if (!release_meta.product_id.empty())
  {
    sidecar["productName"] = release_meta.product_id;
    if (!release_meta.version.empty())
    {
      sidecar["productVersion"] = release_meta.version;
    }
  }
  if (!release_meta.support_until.empty())
  {
    sidecar["supportEndDate"] = widened_to_rfc3339(release_meta.support_until);
  }
  if (!cra_metadata.manufacturer_name.empty())
  {
    sidecar["manufacturerName"] = cra_metadata.manufacturer_name;
  }
  if (!cra_metadata.manufacturer_email.empty())
  {
    sidecar["manufacturerEmail"] = cra_metadata.manufacturer_email;
  }
  if (!cra_metadata.security_contact.empty())
  {
    sidecar["securityContact"] = cra_metadata.security_contact;
  }
  if (!cra_metadata.vulnerability_disclosure_url.empty())
  {
    sidecar["vulnerabilityDisclosureUrl"] = cra_metadata.vulnerability_disclosure_url;
  }
  return sidecar.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

std::filesystem::path cra_sidecar_path_for(const std::filesystem::path& sbom_output_path)
{
  std::string stem = sbom_output_path.stem().string();
  for (const std::string_view known_suffix : kKnownFormatSuffixes)
  {
    if (stem.size() > known_suffix.size() && stem.ends_with(known_suffix))
    {
      stem.erase(stem.size() - known_suffix.size());
      break;
    }
  }
  return sbom_output_path.parent_path() / (stem + ".cra.json");
}

}  // namespace bomwerk::output
