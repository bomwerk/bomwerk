#include "vuln/cpe.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/match_coverage.hpp"
#include "core/model.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"

namespace bomwerk::vuln
{
namespace
{

/// CPE 2.3 formatted-string prefix through the `part` component, for an
/// application or library: what nearly everything bomwerk reports is.
constexpr std::string_view kCpeApplicationPrefix = "cpe:2.3:a:";

/// The same prefix for an operating system. NVD files OS, RTOS kernel and
/// firmware releases here, so an RTOS asked only as an application is missed:
/// on 2026-11-17 `cpe:2.3:a:*:zephyr:3.5.0` matched 0 CVEs and
/// `cpe:2.3:o:*:zephyr:3.5.0` matched 74.
constexpr std::string_view kCpeOperatingSystemPrefix = "cpe:2.3:o:";

/// One reviewed operating-system product name and the NVD CPE dictionary
/// entry it was checked against.
struct OperatingSystemProduct
{
  std::string_view name;             ///< the CPE product, compared after lowercasing
  std::string_view checked_against;  ///< an NVD dictionary entry filed under part `o`
};

/// Products asked as an operating system (part `o`) as well as an
/// application (part `a`). Exact names only, never a pattern: each extra name
/// doubles that component's NVD requests and widens the wildcard-vendor match,
/// so an entry joins only after NVD's CPE dictionary confirms it files the
/// product under part `o` (`/rest/json/cpes/2.0?cpeMatchString=cpe:2.3:o:*:<name>`,
/// checked 2026-11-17). Sorted by name.
///
/// Deliberately absent: `nuttx` and `threadx`. NVD has no part `o` entry for
/// either (0 results on the same date); it files them as applications
/// (`cpe:2.3:a:nuttx:nuttx:...`, `cpe:2.3:a:eclipse:threadx:...`), which the
/// part `a` query already asks.
constexpr OperatingSystemProduct kOperatingSystemProducts[] = {
    {"contiki-ng", "cpe:2.3:o:contiki-ng:contiki-ng:4.9:*:*:*:*:*:*:*"},
    {"freertos", "cpe:2.3:o:amazon:freertos:10.0.1:*:*:*:*:*:*:*"},
    {"linux_kernel", "cpe:2.3:o:linux:linux_kernel:1.2.0:*:*:*:*:*:*:*"},
    {"mbed_os", "cpe:2.3:o:arm:mbed_os:6.17.0:*:*:*:*:*:*:*"},
    {"riot", "cpe:2.3:o:riot-os:riot:2023.10:-:*:*:*:*:*:*"},
    {"zephyr", "cpe:2.3:o:zephyrproject:zephyr:3.5.0:-:*:*:*:*:*:*"},
};

/// True when `product` (already lowercased) is a reviewed operating system.
bool is_operating_system_product(std::string_view product)
{
  for (const OperatingSystemProduct& listed : kOperatingSystemProducts)
  {
    if (listed.name == product)
    {
      return true;
    }
  }
  return false;
}

/// The vendor component. NVD's `virtualMatchString` allows a wildcard here :
/// see cpe.hpp for why that is the whole point of this path.
constexpr std::string_view kAnyVendor = "*";

/// CPE 2.3 attributes after version: update, edition, language, sw_edition,
/// target_sw, target_hw and other. NVD accepts the shorter prefix as a virtual
/// match string; SBOM fields carry the complete formatted identifier.
constexpr std::string_view kRemainingWildcardAttributes = ":*:*:*:*:*:*:*";

/// RFC 3986 unreserved characters, the only bytes left un-escaped by
/// `percent_encode_query_value`.
constexpr std::string_view kUnreservedUrlCharacters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

constexpr std::string_view kHexDigits = "0123456789ABCDEF";

/// The characters a validated CPE segment may contain, checked AFTER
/// lowercasing. Deliberately a strict allowlist: see cpe.hpp's SECURITY note
/// for what each excluded class would otherwise let a hostile manifest do.
bool is_safe_cpe_character(char character)
{
  const bool is_lowercase_letter = character >= 'a' && character <= 'z';
  const bool is_digit = character >= '0' && character <= '9';
  const bool is_permitted_punctuation =
      character == '.' || character == '_' || character == '+' || character == '-';
  return is_lowercase_letter || is_digit || is_permitted_punctuation;
}

/// Lowercase `segment` and return it only when every byte survives validation.
/// CPE dictionary entries are canonically lower-case (NVD files OpenSSL's
/// `1.0.2K` as `1.0.2k`), so lowercasing is a match requirement, not cosmetics.
std::optional<std::string> validated_segment(std::string_view segment)
{
  if (segment.empty() || segment.size() > kMaxCpeSegmentBytes)
  {
    return std::nullopt;
  }
  std::string lowercased = core::to_lower_ascii(segment);
  for (const char character : lowercased)
  {
    if (!is_safe_cpe_character(character))
    {
      return std::nullopt;
    }
  }
  return lowercased;
}

/// `version` without one leading `v` or `V`, but only when a digit follows it.
/// Releases are often tagged `v1.2.3` (Go modules always are, FreeRTOS writes
/// `V11.1.0`), while NVD files the bare number, so `v11.1.0` would never match.
/// The digit check keeps a version that merely starts with the letter, such as
/// `vendor-1` or a lone `v`, untouched.
std::string_view without_leading_v(std::string_view version)
{
  constexpr std::size_t kShortestStrippableVersion = 2;  // the `v` plus one digit
  if (version.size() < kShortestStrippableVersion)
  {
    return version;
  }
  const bool starts_with_v = core::to_lower_ascii(version[0]) == 'v';
  const bool digit_follows = version[1] >= '0' && version[1] <= '9';
  if (starts_with_v && digit_follows)
  {
    return version.substr(1);
  }
  return version;
}

/// The validated product and version segments of a purl.
struct ProductAndVersion
{
  std::string product;
  std::string version;
};

/// Read and validate `purl`'s product and version, or nothing when either
/// cannot form a safe CPE segment.
std::optional<ProductAndVersion> product_and_version_of(std::string_view purl)
{
  // Qualifiers and subpath are stripped through the SAME shared accessor the
  // OSV client and the coverage classifier use, so all three agree on where a
  // purl's identity ends.
  const std::string_view identity_part = core::purl_identity_part(purl);
  if (!identity_part.starts_with("pkg:"))
  {
    return std::nullopt;
  }

  std::optional<std::string> product = validated_segment(core::purl_name_of(identity_part));
  if (!product.has_value())
  {
    return std::nullopt;
  }
  std::optional<std::string> version =
      validated_segment(without_leading_v(core::purl_version_of(identity_part)));
  if (!version.has_value())
  {
    return std::nullopt;  // an unversioned purl would match every advisory ever filed
  }
  return ProductAndVersion{std::move(*product), std::move(*version)};
}

/// `<part_prefix>*:<product>:<version>`.
std::string match_string_with_part(std::string_view part_prefix, const ProductAndVersion& segments)
{
  std::string match_string;
  match_string.reserve(part_prefix.size() + kAnyVendor.size() + segments.product.size() +
                       segments.version.size() + 2);
  match_string.append(part_prefix);
  match_string.append(kAnyVendor);
  match_string.push_back(':');
  match_string.append(segments.product);
  match_string.push_back(':');
  match_string.append(segments.version);
  return match_string;
}

}  // namespace

std::optional<std::string> cpe_match_string_for(std::string_view purl)
{
  const std::optional<ProductAndVersion> segments = product_and_version_of(purl);
  if (!segments.has_value())
  {
    return std::nullopt;
  }
  return match_string_with_part(kCpeApplicationPrefix, *segments);
}

std::vector<std::string> cpe_match_strings_for(std::string_view purl)
{
  std::vector<std::string> match_strings;
  const std::optional<ProductAndVersion> segments = product_and_version_of(purl);
  if (!segments.has_value())
  {
    return match_strings;
  }
  match_strings.push_back(match_string_with_part(kCpeApplicationPrefix, *segments));
  if (is_operating_system_product(segments->product))
  {
    match_strings.push_back(match_string_with_part(kCpeOperatingSystemPrefix, *segments));
  }
  return match_strings;
}

std::optional<std::string> cpe_identifier_for(std::string_view purl)
{
  const std::optional<ProductAndVersion> segments = product_and_version_of(purl);
  if (!segments.has_value())
  {
    return std::nullopt;
  }
  // An SBOM carries one identifier, so a listed operating system publishes
  // the part NVD files its releases under rather than one it never matches.
  const std::string_view part_prefix = is_operating_system_product(segments->product)
                                           ? kCpeOperatingSystemPrefix
                                           : kCpeApplicationPrefix;
  std::string identifier = match_string_with_part(part_prefix, *segments);
  identifier.append(kRemainingWildcardAttributes);
  return identifier;
}

void populate_cpe_identifiers(std::vector<core::Component>& components, CpePopulationScope scope)
{
  for (core::Component& component : components)
  {
    if (!component.cpe.empty())
    {
      continue;  // existing identifier (and whatever provenance it carries) is preserved verbatim
    }
    // UnmappedOnly keeps the long-standing gate: only purls OSV cannot match
    // (no OSV ecosystem, or a tag-pinned forge repository). AllVersioned drops the gate entirely
    // and lets cpe_identifier_for's own product/version validation be the only filter
    //: that is what newly admits npm, Go, every other OSV-native ecosystem,
    // and commit-pinned purls of any type.
    if (scope == CpePopulationScope::UnmappedOnly &&
        core::classify_match_coverage(component) != core::MatchCoverage::UnmappedPurlType)
    {
      continue;
    }
    const std::optional<std::string> identifier = cpe_identifier_for(component.purl);
    if (!identifier.has_value())
    {
      continue;
    }
    component.cpe = *identifier;
    if (scope == CpePopulationScope::AllVersioned)
    {
      component.cpe_provenance = core::CpeProvenance::SynthesizedWildcardVendor;
    }
  }
}

std::string percent_encode_query_value(std::string_view value)
{
  std::string encoded;
  encoded.reserve(value.size());
  for (const char character : value)
  {
    if (kUnreservedUrlCharacters.find(character) != std::string_view::npos)
    {
      encoded.push_back(character);
      continue;
    }
    const auto byte = static_cast<unsigned char>(character);
    constexpr unsigned int kBitsPerHexDigit = 4;
    constexpr unsigned int kHexDigitMask = 0x0F;
    encoded.push_back('%');
    encoded.push_back(kHexDigits[(byte >> kBitsPerHexDigit) & kHexDigitMask]);
    encoded.push_back(kHexDigits[byte & kHexDigitMask]);
  }
  return encoded;
}

}  // namespace bomwerk::vuln
