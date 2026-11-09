// ctest unit test for PURL identity canonicalization
#include <cstdio>
#include <string>
#include <vector>

#include "core/purl.hpp"
#include "core/warning.hpp"
#include "support/check.hpp"

using bomwerk::core::canonicalize_purl;
using bomwerk::core::Purl;
using bomwerk::core::purl_identity_part;
using bomwerk::core::purl_name_of;
using bomwerk::core::purl_type_of;
using bomwerk::core::purl_version_of;
using bomwerk::core::Warning;

int main()
{
  // Given a PURL with uppercase scheme and type, when it is parsed, then only
  // the scheme and type are normalized.
  auto uppercase_type = Purl::parse("PKG:CONAN/OpenSSL@3.2.0");
  BOMWERK_TEST_CHECK(uppercase_type.complete);
  BOMWERK_TEST_CHECK(uppercase_type.warnings.empty());
  BOMWERK_TEST_CHECK(uppercase_type.value.canonical() == "pkg:conan/OpenSSL@3.2.0");

  // Given versions that look similar, when they are parsed, then the canonical
  // identity keeps the version exact.
  auto short_version = Purl::parse("pkg:conan/openssl@1.2");
  auto patch_version = Purl::parse("pkg:conan/openssl@1.2.0");
  auto padded_version = Purl::parse("pkg:conan/openssl@1.2.03");
  BOMWERK_TEST_CHECK(short_version.value.canonical() != patch_version.value.canonical());
  BOMWERK_TEST_CHECK(patch_version.value.canonical() != padded_version.value.canonical());

  // Given malformed PURLs, when they are parsed, then the result is incomplete
  // and carries warnings instead of throwing.
  auto missing_scheme = Purl::parse("conan/openssl@3.2.0");
  BOMWERK_TEST_CHECK(!missing_scheme.complete);
  BOMWERK_TEST_CHECK(missing_scheme.warnings.size() == 1);

  auto missing_name = Purl::parse("pkg:conan/");
  BOMWERK_TEST_CHECK(!missing_name.complete);
  BOMWERK_TEST_CHECK(missing_name.warnings.size() == 1);

  // Given a purl with qualifiers and/or a subpath, when its identity part is
  // taken, then both are stripped; given a bare purl with neither, then it is
  // returned unchanged (shared by core::match_coverage and vuln::osv, so
  // both must agree on where a purl's identity ends).
  BOMWERK_TEST_CHECK(purl_identity_part("pkg:generic/zlib@1.3.1?checksum=sha256:ab") ==
                     "pkg:generic/zlib@1.3.1");
  BOMWERK_TEST_CHECK(purl_identity_part("pkg:npm/left-pad@1.3.0#sub") == "pkg:npm/left-pad@1.3.0");
  BOMWERK_TEST_CHECK(purl_identity_part("pkg:npm/left-pad@1.3.0") == "pkg:npm/left-pad@1.3.0");
  BOMWERK_TEST_CHECK(purl_identity_part("") == "");

  // Given assorted purls, when the type segment is read, then it is the text
  // between "pkg:" and the first '/', or empty when not purl-shaped.
  BOMWERK_TEST_CHECK(purl_type_of("pkg:conan/openssl@3.2.0") == "conan");
  BOMWERK_TEST_CHECK(purl_type_of("pkg:github/harfbuzz/harfbuzz@abc") == "github");
  BOMWERK_TEST_CHECK(purl_type_of("not-a-purl") == "");
  BOMWERK_TEST_CHECK(purl_type_of("") == "");

  // Given assorted (already qualifier/subpath-stripped) purls, when the
  // version is read, then it is the text after the last '@', or empty when
  // there is none: including the edge case of a trailing '@' with nothing
  // after it (an unresolved version, not a parse error).
  BOMWERK_TEST_CHECK(purl_version_of("pkg:npm/left-pad@1.3.0") == "1.3.0");
  BOMWERK_TEST_CHECK(purl_version_of("pkg:vcpkg/zlib") == "");
  BOMWERK_TEST_CHECK(purl_version_of("pkg:vcpkg/zlib@") == "");

  // Given assorted (already qualifier/subpath-stripped) purls, when the name
  // is read, then it is the final '/'-separated segment with the type,
  // namespace and version all removed (vuln::cpe builds a CPE product
  // from this, and a CPE dictionary records no purl namespace).
  BOMWERK_TEST_CHECK(purl_name_of("pkg:conan/zlib@1.2.11") == "zlib");
  BOMWERK_TEST_CHECK(purl_name_of("pkg:vcpkg/zlib") == "zlib");  // unversioned is still a name
  BOMWERK_TEST_CHECK(purl_name_of("pkg:maven/org.slf4j/slf4j-api@2.0.9") == "slf4j-api");
  BOMWERK_TEST_CHECK(purl_name_of("pkg:npm/%40scope/name@1.0.0") == "name");
  // Case is preserved here: canonicalization is Purl::parse's job, and each
  // consumer lower-cases for its own target format.
  BOMWERK_TEST_CHECK(purl_name_of("pkg:conan/OpenSSL@3.2.0") == "OpenSSL");
  // Not purl-shaped, or a type with no name at all.
  BOMWERK_TEST_CHECK(purl_name_of("not-a-purl") == "");
  BOMWERK_TEST_CHECK(purl_name_of("") == "");
  BOMWERK_TEST_CHECK(purl_name_of("pkg:conan") == "");
  BOMWERK_TEST_CHECK(purl_name_of("pkg:conan/@1.2.11") == "");

  // Given a purl a producer built ad hoc with an uppercase type, when
  // canonicalized, then it is replaced in place with the canonical form and
  // no warning is raised (the shared helper every ecosystem producer's
  // own purl-then-canonicalize step now dogfoods, instead of each repeating
  // core::Purl::parse plus its own warning text).
  {
    std::string purl = "PKG:VCPKG/zlib@1.3.2";
    std::vector<Warning> warnings;
    canonicalize_purl(purl, "vcpkg", warnings);
    BOMWERK_TEST_CHECK(purl == "pkg:vcpkg/zlib@1.3.2");
    BOMWERK_TEST_CHECK(warnings.empty());
  }

  // Given a purl that fails validation, when canonicalized, then it is left
  // unchanged and one warning naming the producer is appended.
  {
    std::string purl = "not-a-purl";
    std::vector<Warning> warnings;
    canonicalize_purl(purl, "vcpkg", warnings);
    BOMWERK_TEST_CHECK(purl == "not-a-purl");
    BOMWERK_TEST_CHECK(warnings.size() == 1);
    BOMWERK_TEST_CHECK(warnings[0].message == "vcpkg: produced purl failed validation: not-a-purl");
  }

  std::puts("test_purl: OK");
  return 0;
}
