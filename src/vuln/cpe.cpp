#include "vuln/cpe.hpp"

#include <optional>
#include <string>
#include <string_view>

#include "core/match_coverage.hpp"
#include "core/model.hpp"
#include "core/purl.hpp"
#include "core/text.hpp"

namespace bomwerk::vuln
{
namespace
{

/// CPE 2.3 formatted-string prefix through the `part` component. Everything
/// bomwerk reports from a manifest is an application or library, never an OS
/// or hardware entry, so `a` is fixed rather than guessed.
constexpr std::string_view kCpeApplicationPrefix = "cpe:2.3:a:";

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

}  // namespace

std::optional<std::string> cpe_match_string_for(std::string_view purl)
{
  // Qualifiers and subpath are stripped through the SAME shared accessor the
  // OSV client and the coverage classifier use, so all three agree on where a
  // purl's identity ends.
  const std::string_view identity_part = core::purl_identity_part(purl);
  if (!identity_part.starts_with("pkg:"))
  {
    return std::nullopt;
  }

  const std::optional<std::string> product = validated_segment(core::purl_name_of(identity_part));
  if (!product.has_value())
  {
    return std::nullopt;
  }
  const std::optional<std::string> version =
      validated_segment(core::purl_version_of(identity_part));
  if (!version.has_value())
  {
    return std::nullopt;  // an unversioned purl would match every advisory ever filed
  }

  std::string match_string;
  match_string.reserve(kCpeApplicationPrefix.size() + kAnyVendor.size() + product->size() +
                       version->size() + 2);
  match_string.append(kCpeApplicationPrefix);
  match_string.append(kAnyVendor);
  match_string.push_back(':');
  match_string.append(*product);
  match_string.push_back(':');
  match_string.append(*version);
  return match_string;
}

std::optional<std::string> cpe_identifier_for(std::string_view purl)
{
  std::optional<std::string> identifier = cpe_match_string_for(purl);
  if (!identifier.has_value())
  {
    return std::nullopt;
  }
  identifier->append(kRemainingWildcardAttributes);
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
    // UnmappedOnly keeps the long-standing gate: only types with no OSV
    // ecosystem at all. AllVersioned drops the gate entirely and lets
    // cpe_identifier_for's own product/version validation be the only filter
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
