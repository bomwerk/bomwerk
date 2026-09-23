#pragma once
#include <string>
#include <string_view>
#include <vector>

#include "core/result.hpp"
#include "core/warning.hpp"

namespace bomwerk::core
{

/// Package URL identity value.
///
/// The canonical form lowercases the PURL scheme and type. Package names,
/// namespaces, versions, qualifiers, and subpaths stay exact until an
/// ecosystem-specific normalizer owns those rules.
class Purl
{
 public:
  Purl() = default;

  static Result<Purl> parse(std::string_view raw_purl);

  const std::string& canonical() const { return canonical_purl_; }
  bool empty() const { return canonical_purl_.empty(); }

 private:
  explicit Purl(std::string canonical_purl);

  std::string canonical_purl_;
};

/// The purl with any qualifiers (`?...`) and subpath (`#...`) stripped, or
/// `purl` unchanged when it carries neither. Shared by every consumer that
/// matches on the bare type/namespace/name@version: OSV querying
/// (`vuln::osv`) and match-coverage classification (`core::match_coverage`)
///: so a qualifier can never make one see a match the other doesn't.
/// Example: `purl_identity_part("pkg:generic/zlib@1.3.1?checksum=sha256:ab")`
/// -> `"pkg:generic/zlib@1.3.1"`.
[[nodiscard]] std::string_view purl_identity_part(std::string_view purl);

/// The `<type>` segment of `pkg:<type>/...`, or empty when `purl` is not
/// purl-shaped. A cheap structural read, not a canonicalization: case stays
/// whatever the caller passed in (that is `Purl::parse`'s job).
/// Example: `purl_type_of("pkg:conan/openssl@3.2.0")` -> `"conan"`.
[[nodiscard]] std::string_view purl_type_of(std::string_view purl);

/// The resolved version of a purl already passed through
/// `purl_identity_part` (no qualifiers/subpath left to confuse the search
/// for '@'), or empty when there is none.
/// Example: `purl_version_of("pkg:npm/left-pad@1.3.0")` -> `"1.3.0"`.
[[nodiscard]] std::string_view purl_version_of(std::string_view purl_without_extras);

/// The bare `<name>` segment of a purl already passed through
/// `purl_identity_part`: type, namespace and version all removed. Empty when
/// `purl` is not purl-shaped or carries no name. Like its siblings this is a
/// cheap structural read, not a canonicalization: case stays whatever the
/// caller passed in.
///
/// The namespace is deliberately dropped rather than joined: the consumers of
/// this accessor identify a package by the name its upstream project uses
/// (`vuln::cpe` builds a CPE product from it), and a purl namespace is a
/// registry-scoping detail no CPE dictionary records.
/// Example: `purl_name_of("pkg:maven/org.slf4j/slf4j-api@2.0.9")` ->
/// `"slf4j-api"`; `purl_name_of("pkg:conan/zlib@1.2.11")` -> `"zlib"`.
[[nodiscard]] std::string_view purl_name_of(std::string_view purl_without_extras);

/// Validate `purl` via `Purl::parse` and replace it with the canonical form on
/// success; on failure `purl` is left unchanged and one warning of the form
/// "<producer_name>: produced purl failed validation: <purl>" is appended to
/// `warnings`. Every ecosystem producer builds its own purl ad hoc before
/// trusting it: conan and vcpkg each used to repeat this exact
/// parse-then-canonicalize-or-warn sequence with only their own name in the
/// warning text, so it lives here once for every producer (present and
/// future, including BOMWERK_PRO ones, which link only `core`) to share.
void canonicalize_purl(std::string& purl, std::string_view producer_name,
                       std::vector<Warning>& warnings);

}  // namespace bomwerk::core
