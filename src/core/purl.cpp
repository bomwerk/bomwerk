#include "core/purl.hpp"

#include <string>
#include <string_view>
#include <utility>

#include "core/text.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::core
{
namespace
{

constexpr std::string_view kPurlScheme = "pkg";
constexpr std::string_view kCanonicalPurlScheme = "pkg:";

bool is_ascii_whitespace(char character)
{
  return character == ' ' || character == '\t' || character == '\n' || character == '\r' ||
         character == '\f' || character == '\v';
}

void append_lowercase_ascii(std::string& destination, std::string_view value)
{
  for (char character : value)
  {
    destination.push_back(to_lower_ascii(character));
  }
}

std::string quoted(std::string_view value)
{
  std::string result;
  result.reserve(value.size() + 2);
  result.push_back('\'');
  result.append(value.data(), value.size());
  result.push_back('\'');
  return result;
}

struct PurlSeparators
{
  std::size_t scheme_separator = std::string_view::npos;
  std::size_t type_separator = std::string_view::npos;
  bool has_whitespace = false;
};

PurlSeparators find_separators(std::string_view raw_purl)
{
  PurlSeparators separators;
  for (std::size_t character_index = 0; character_index < raw_purl.size(); ++character_index)
  {
    const char character = raw_purl[character_index];
    if (is_ascii_whitespace(character))
    {
      separators.has_whitespace = true;
      return separators;
    }
    if (character == ':' && separators.scheme_separator == std::string_view::npos)
    {
      separators.scheme_separator = character_index;
      continue;
    }
    if (character == '/' && separators.scheme_separator != std::string_view::npos &&
        separators.type_separator == std::string_view::npos)
    {
      separators.type_separator = character_index;
    }
  }
  return separators;
}

}  // namespace

Purl::Purl(std::string canonical_purl) : canonical_purl_(std::move(canonical_purl)) {}

Result<Purl> Purl::parse(std::string_view raw_purl)
{
  Result<Purl> result;

  if (raw_purl.empty())
  {
    result.complete = false;
    result.warn(WarningCode::kPurlMalformed, "purl is empty");
    return result;
  }

  const PurlSeparators separators = find_separators(raw_purl);
  if (separators.has_whitespace)
  {
    result.complete = false;
    result.warn(WarningCode::kPurlMalformed, "purl contains whitespace: " + quoted(raw_purl));
    return result;
  }
  if (separators.scheme_separator == std::string_view::npos)
  {
    result.complete = false;
    result.warn(WarningCode::kPurlMalformed,
                "purl is missing scheme separator: " + quoted(raw_purl));
    return result;
  }

  const std::string_view scheme = raw_purl.substr(0, separators.scheme_separator);
  if (!equals_ascii_ignore_case(scheme, kPurlScheme))
  {
    result.complete = false;
    result.warn(WarningCode::kPurlMalformed, "purl scheme is not pkg: " + quoted(raw_purl));
    return result;
  }

  const std::size_t type_start = separators.scheme_separator + 1;
  if (separators.type_separator == std::string_view::npos ||
      separators.type_separator == type_start)
  {
    result.complete = false;
    result.warn(WarningCode::kPurlMalformed, "purl is missing package type: " + quoted(raw_purl));
    return result;
  }
  if (separators.type_separator + 1 == raw_purl.size())
  {
    result.complete = false;
    result.warn(WarningCode::kPurlMalformed, "purl is missing package name: " + quoted(raw_purl));
    return result;
  }

  std::string canonical_purl;
  canonical_purl.reserve(raw_purl.size());
  canonical_purl.append(kCanonicalPurlScheme.data(), kCanonicalPurlScheme.size());
  append_lowercase_ascii(canonical_purl,
                         raw_purl.substr(type_start, separators.type_separator - type_start));
  canonical_purl.append(raw_purl.data() + separators.type_separator,
                        raw_purl.size() - separators.type_separator);
  result.value = Purl(std::move(canonical_purl));
  return result;
}

std::string_view purl_identity_part(std::string_view purl)
{
  const std::size_t extras_begin = purl.find_first_of("?#");
  return extras_begin == std::string_view::npos ? purl : purl.substr(0, extras_begin);
}

std::string_view purl_type_of(std::string_view purl)
{
  if (!purl.starts_with("pkg:"))
  {
    return {};
  }
  constexpr std::size_t kSchemePrefixLength = 4;  // "pkg:"
  const std::string_view after_scheme = purl.substr(kSchemePrefixLength);
  const std::size_t type_end = after_scheme.find('/');
  return type_end == std::string_view::npos ? after_scheme : after_scheme.substr(0, type_end);
}

std::string_view purl_version_of(std::string_view purl_without_extras)
{
  const std::size_t version_marker = purl_without_extras.rfind('@');
  if (version_marker == std::string_view::npos)
  {
    return {};
  }
  return purl_without_extras.substr(version_marker + 1);
}

void canonicalize_purl(std::string& purl, std::string_view producer_name,
                       std::vector<Warning>& warnings)
{
  const Result<Purl> parsed_purl = Purl::parse(purl);
  if (!parsed_purl.complete)
  {
    warnings.push_back(
        Warning{WarningCode::kPurlValidationFailed,
                std::string(producer_name) + ": produced purl failed validation: " + purl,
                std::string(producer_name),
                {}});
    return;
  }
  purl = parsed_purl.value.canonical();
}

std::string_view purl_name_of(std::string_view purl_without_extras)
{
  if (!purl_without_extras.starts_with(kCanonicalPurlScheme))
  {
    return {};
  }
  const std::string_view after_scheme = purl_without_extras.substr(kCanonicalPurlScheme.size());
  const std::size_t type_end = after_scheme.find('/');
  if (type_end == std::string_view::npos)
  {
    return {};  // "pkg:conan": a type with no name at all
  }

  // Strip the version with the same rfind('@') rule purl_version_of uses, so
  // the two accessors can never disagree about where a version begins.
  std::string_view name_and_namespace = after_scheme.substr(type_end + 1);
  const std::size_t version_marker = name_and_namespace.rfind('@');
  if (version_marker != std::string_view::npos)
  {
    name_and_namespace = name_and_namespace.substr(0, version_marker);
  }

  // Whatever precedes the last '/' is namespace; the final segment is the name.
  const std::size_t last_separator = name_and_namespace.rfind('/');
  if (last_separator == std::string_view::npos)
  {
    return name_and_namespace;
  }
  return name_and_namespace.substr(last_separator + 1);
}

}  // namespace bomwerk::core
