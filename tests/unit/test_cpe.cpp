#include <optional>
#include <string>

#include "support/check.hpp"
#include "vuln/cpe.hpp"

namespace vuln = bomwerk::vuln;

namespace
{

bool builds_to(const std::string& purl, const std::string& expected_match_string)
{
  const std::optional<std::string> built = vuln::cpe_match_string_for(purl);
  return built.has_value() && *built == expected_match_string;
}

bool is_rejected(const std::string& purl)
{
  return !vuln::cpe_match_string_for(purl).has_value();
}

bool identifier_builds_to(const std::string& purl, const std::string& expected_identifier)
{
  const std::optional<std::string> built = vuln::cpe_identifier_for(purl);
  return built.has_value() && *built == expected_identifier;
}

}  // namespace

int main()
{
  // Given a versioned purl of a type no OSV ecosystem covers, when a CPE match
  // string is built, then it is the application form with a wildcard vendor :
  // the shape verified against the live NVD API for zlib 1.2.11.
  {
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/zlib@1.2.11", "cpe:2.3:a:*:zlib:1.2.11"));
    BOMWERK_TEST_CHECK(builds_to("pkg:vcpkg/openssl@3.2.0", "cpe:2.3:a:*:openssl:3.2.0"));
    BOMWERK_TEST_CHECK(builds_to("pkg:generic/libpng@1.6.40", "cpe:2.3:a:*:libpng:1.6.40"));
  }

  // Given a purl that can form the NVD match prefix, when a publishable CPE is
  // requested, then all thirteen CPE 2.3 attributes are present. The NVD
  // helper above deliberately remains short, so SBOM publication cannot
  // silently change request URLs or cache keys.
  {
    BOMWERK_TEST_CHECK(
        identifier_builds_to("pkg:conan/zlib@1.2.11", "cpe:2.3:a:*:zlib:1.2.11:*:*:*:*:*:*:*"));
    BOMWERK_TEST_CHECK(identifier_builds_to("pkg:vcpkg/OpenSSL@1.0.2K?triplet=x64-linux",
                                            "cpe:2.3:a:*:openssl:1.0.2k:*:*:*:*:*:*:*"));
  }

  // Given a purl carrying qualifiers or a subpath, when a CPE match string is
  // built, then they are stripped through the same shared accessor the OSV
  // client uses: a qualifier must never leak into the query.
  {
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/zlib@1.2.11?os=linux", "cpe:2.3:a:*:zlib:1.2.11"));
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/zlib@1.2.11#sub/dir", "cpe:2.3:a:*:zlib:1.2.11"));
  }

  // Given a namespaced or mixed-case purl, when a CPE match string is built,
  // then the namespace is dropped and both segments are lower-cased: NVD files
  // dictionary entries in lower case (OpenSSL's 1.0.2K is `1.0.2k` there).
  {
    BOMWERK_TEST_CHECK(builds_to("pkg:generic/gnu/gzip@1.12", "cpe:2.3:a:*:gzip:1.12"));
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/OpenSSL@1.0.2K", "cpe:2.3:a:*:openssl:1.0.2k"));
  }

  // Given a purl with no resolved version, when a CPE match string is built,
  // then nothing is produced: a version-less query would return every advisory
  // the package ever had: noise, not matches.
  {
    BOMWERK_TEST_CHECK(is_rejected("pkg:vcpkg/zlib"));
    BOMWERK_TEST_CHECK(is_rejected("pkg:vcpkg/zlib@"));
  }

  // Given something that is not purl-shaped, when a CPE match string is built,
  // then nothing is produced.
  {
    BOMWERK_TEST_CHECK(is_rejected(""));
    BOMWERK_TEST_CHECK(is_rejected("zlib@1.2.11"));
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan"));
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/@1.2.11"));
  }

  // Given a hostile manifest name or version: the whole point of validating
  // rather than escaping: when a CPE match string is built, then nothing is
  // produced. Each case is a distinct forgery this would otherwise enable:
  // extra CPE fields, a wildcard widening the match to every package, extra
  // query parameters, a fragment, path traversal, and header/line injection.
  {
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zlib:extra@1.2.11"));     // forges a CPE field
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/*@1.2.11"));              // matches everything
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zlib@1.2.11&apiKey=x"));  // forges a parameter
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zlib@1.2.11%20or%201"));  // percent escape
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zli b@1.2.11"));          // whitespace
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zlib\t@1.2.11"));         // tab
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zlib\n@1.2.11"));         // line injection
    BOMWERK_TEST_CHECK(is_rejected(std::string("pkg:conan/zli") + '\0' + "b@1.2.11"));  // NUL
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/..%2fadmin@1.2.11"));  // traversal attempt
  }

  // Given a name or version longer than the hostile-input bound, when a CPE
  // match string is built, then nothing is produced: real CPE product names
  // sit far under this limit.
  {
    const std::string overlong_name(vuln::kMaxCpeSegmentBytes + 1, 'a');
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/" + overlong_name + "@1.0"));
    BOMWERK_TEST_CHECK(is_rejected("pkg:conan/zlib@" + overlong_name));
    // Exactly at the bound is still accepted: the check is inclusive.
    const std::string longest_allowed_name(vuln::kMaxCpeSegmentBytes, 'a');
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/" + longest_allowed_name + "@1.0",
                                 "cpe:2.3:a:*:" + longest_allowed_name + ":1.0"));
  }

  // Given the punctuation real package versions use, when a CPE match string is
  // built, then it survives: rejecting `-`, `.`, `+` or `_` would silently drop
  // most pre-release and distribution-patched versions.
  {
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/zlib@1.2.11-rc1", "cpe:2.3:a:*:zlib:1.2.11-rc1"));
    BOMWERK_TEST_CHECK(builds_to("pkg:conan/zlib@1.2.11+deb1", "cpe:2.3:a:*:zlib:1.2.11+deb1"));
    BOMWERK_TEST_CHECK(builds_to("pkg:generic/my_lib@2.0", "cpe:2.3:a:*:my_lib:2.0"));
  }

  // Given a value bound for a URL query parameter, when it is percent-encoded,
  // then every byte outside the RFC 3986 unreserved set is escaped: the
  // wildcard and the colons in a CPE included.
  {
    BOMWERK_TEST_CHECK(vuln::percent_encode_query_value("cpe:2.3:a:*:zlib:1.2.11") ==
                       "cpe%3A2.3%3Aa%3A%2A%3Azlib%3A1.2.11");
    BOMWERK_TEST_CHECK(vuln::percent_encode_query_value("a-b_c.d~e") == "a-b_c.d~e");
    BOMWERK_TEST_CHECK(vuln::percent_encode_query_value("&=#") == "%26%3D%23");
    BOMWERK_TEST_CHECK(vuln::percent_encode_query_value("") == "");
  }

  // Given a mixed component list, when CPE enrichment runs under the default
  // UnmappedOnly scope, then only the versioned unmapped ecosystems gain an
  // identifier. Existing operator or upstream identifiers (and whatever
  // provenance they carry) are preserved verbatim, and unsafe/unversioned or
  // OSV-native components remain empty without degrading the scan: the same
  // behavior this scope has always had, byte-identical before and after
  // --all-cpes existed.
  {
    bomwerk::core::Component conan;
    conan.purl = "pkg:conan/zlib@1.2.11";
    bomwerk::core::Component vcpkg;
    vcpkg.purl = "pkg:vcpkg/openssl@3.2.0";
    vcpkg.cpe = "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*";
    bomwerk::core::Component npm;
    npm.purl = "pkg:npm/left-pad@1.3.0";
    bomwerk::core::Component commit_pinned;
    commit_pinned.purl = "pkg:generic/libfoo@0123456789012345678901234567890123456789";
    bomwerk::core::Component unversioned;
    unversioned.purl = "pkg:generic/libfoo";
    bomwerk::core::Component unsafe;
    unsafe.purl = "pkg:generic/bad:name@1.0";
    std::vector<bomwerk::core::Component> components{conan,         vcpkg,       npm,
                                                     commit_pinned, unversioned, unsafe};

    vuln::populate_cpe_identifiers(components, vuln::CpePopulationScope::UnmappedOnly);

    BOMWERK_TEST_CHECK(components[0].cpe == "cpe:2.3:a:*:zlib:1.2.11:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[0].cpe_provenance == bomwerk::core::CpeProvenance::Unspecified);
    BOMWERK_TEST_CHECK(components[1].cpe == "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[1].cpe_provenance == bomwerk::core::CpeProvenance::Unspecified);
    BOMWERK_TEST_CHECK(components[2].cpe.empty());
    BOMWERK_TEST_CHECK(components[3].cpe.empty());
    BOMWERK_TEST_CHECK(components[4].cpe.empty());
    BOMWERK_TEST_CHECK(components[5].cpe.empty());
  }

  // Given the same shape of mixed component list, when CPE enrichment runs
  // under AllVersioned scope (--all-cpes), then npm and the commit-pinned
  // purl also gain an identifier, each marked SynthesizedWildcardVendor.
  // Unsafe/unversioned purls still remain empty without warnings or failure
  //: AllVersioned drops the ecosystem gate, not cpe_identifier_for's own
  // validation. An existing upstream CPE is still preserved verbatim, with
  // its provenance untouched (still Unspecified: it was never synthesized by
  // this run).
  {
    bomwerk::core::Component conan;
    conan.purl = "pkg:conan/zlib@1.2.11";
    bomwerk::core::Component vcpkg;
    vcpkg.purl = "pkg:vcpkg/openssl@3.2.0";
    vcpkg.cpe = "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*";
    bomwerk::core::Component npm;
    npm.purl = "pkg:npm/left-pad@1.3.0";
    bomwerk::core::Component go_module;
    go_module.purl = "pkg:golang/github.com/pkg/errors@v0.9.1";
    bomwerk::core::Component commit_pinned;
    commit_pinned.purl = "pkg:generic/libfoo@0123456789012345678901234567890123456789";
    bomwerk::core::Component unversioned;
    unversioned.purl = "pkg:generic/libfoo";
    bomwerk::core::Component unsafe;
    unsafe.purl = "pkg:generic/bad:name@1.0";
    std::vector<bomwerk::core::Component> components{conan,         vcpkg,       npm,   go_module,
                                                     commit_pinned, unversioned, unsafe};

    vuln::populate_cpe_identifiers(components, vuln::CpePopulationScope::AllVersioned);

    BOMWERK_TEST_CHECK(components[0].cpe == "cpe:2.3:a:*:zlib:1.2.11:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[0].cpe_provenance ==
                       bomwerk::core::CpeProvenance::SynthesizedWildcardVendor);
    // Pre-existing CPE: preserved verbatim, provenance untouched.
    BOMWERK_TEST_CHECK(components[1].cpe == "cpe:2.3:a:openssl:openssl:3.2.0:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[1].cpe_provenance == bomwerk::core::CpeProvenance::Unspecified);
    BOMWERK_TEST_CHECK(components[2].cpe == "cpe:2.3:a:*:left-pad:1.3.0:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[2].cpe_provenance ==
                       bomwerk::core::CpeProvenance::SynthesizedWildcardVendor);
    BOMWERK_TEST_CHECK(components[3].cpe == "cpe:2.3:a:*:errors:v0.9.1:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[3].cpe_provenance ==
                       bomwerk::core::CpeProvenance::SynthesizedWildcardVendor);
    BOMWERK_TEST_CHECK(components[4].cpe ==
                       "cpe:2.3:a:*:libfoo:0123456789012345678901234567890123456789:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(components[4].cpe_provenance ==
                       bomwerk::core::CpeProvenance::SynthesizedWildcardVendor);
    BOMWERK_TEST_CHECK(components[5].cpe.empty());
    BOMWERK_TEST_CHECK(components[5].cpe_provenance == bomwerk::core::CpeProvenance::Unspecified);
    BOMWERK_TEST_CHECK(components[6].cpe.empty());
    BOMWERK_TEST_CHECK(components[6].cpe_provenance == bomwerk::core::CpeProvenance::Unspecified);
  }

  return 0;
}
