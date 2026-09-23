// ctest unit test for match-coverage classification
#include <cstdio>
#include <string>
#include <vector>

#include "core/match_coverage.hpp"
#include "core/model.hpp"
#include "support/check.hpp"

using bomwerk::core::classify_match_coverage;
using bomwerk::core::Component;
using bomwerk::core::MatchCoverage;
using bomwerk::core::MatchCoverageSummary;
using bomwerk::core::summarize_match_coverage;
using bomwerk::core::to_string;

namespace
{

Component component_with_purl(const std::string& purl)
{
  Component component;
  component.purl = purl;
  return component;
}

}  // namespace

int main()
{
  // Given a purl that is not `pkg:`-shaped at all (including empty), when
  // classified, then it is NoIdentifier.
  BOMWERK_TEST_CHECK(classify_match_coverage("") == MatchCoverage::NoIdentifier);
  BOMWERK_TEST_CHECK(classify_match_coverage("left-pad@1.3.0") == MatchCoverage::NoIdentifier);
  BOMWERK_TEST_CHECK(classify_match_coverage("not-a-purl") == MatchCoverage::NoIdentifier);

  // Given a purl-shaped identifier with no resolved version, when classified,
  // then it is UnversionedPurl: a bare manifest dependency, not a dropped one.
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:npm/left-pad") == MatchCoverage::UnversionedPurl);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:vcpkg/zlib") == MatchCoverage::UnversionedPurl);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:npm/left-pad@") ==
                     MatchCoverage::UnversionedPurl);

  // Given a versioned purl whose type has no OSV ecosystem at all, when
  // classified, then it is UnmappedPurlType.
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:conan/openssl@3.2.0") ==
                     MatchCoverage::UnmappedPurlType);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:vcpkg/zlib@1.3.1") ==
                     MatchCoverage::UnmappedPurlType);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:generic/x@1.2") ==
                     MatchCoverage::UnmappedPurlType);

  // Given a versioned purl on a mapped ecosystem, when classified, then it is
  // Matched.
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:npm/left-pad@1.3.0") == MatchCoverage::Matched);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:github/harfbuzz/harfbuzz@" +
                                             std::string(40, 'a')) == MatchCoverage::Matched);

  // Given a Conan/vcpkg/generic purl pinned to a resolved 40/64-hex commit
  // id, when classified, then it is STILL Matched: this is the point: OSV's
  // commit index matches by sha regardless of purl type, so the commit check
  // must run before the unmapped-type check.
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:generic/x@" + std::string(40, 'a')) ==
                     MatchCoverage::Matched);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:conan/openssl@" + std::string(64, 'b')) ==
                     MatchCoverage::Matched);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:vcpkg/zlib@" + std::string(40, 'c')) ==
                     MatchCoverage::Matched);
  // A version merely shaped like a partial hex string (wrong length) is not a
  // commit id, so the type check still applies.
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:generic/x@" + std::string(39, 'a')) ==
                     MatchCoverage::UnmappedPurlType);

  // Given qualifiers/subpath, when classified, then they are stripped before
  // the version and type are read.
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:generic/zlib@1.3.1?checksum=sha256:ab") ==
                     MatchCoverage::UnmappedPurlType);
  BOMWERK_TEST_CHECK(classify_match_coverage("pkg:npm/left-pad@1.3.0#sub") ==
                     MatchCoverage::Matched);

  // Given the same purls wrapped in a Component, when classified via the
  // overload, then the result matches the bare-purl overload.
  BOMWERK_TEST_CHECK(classify_match_coverage(component_with_purl("pkg:conan/openssl@3.2.0")) ==
                     MatchCoverage::UnmappedPurlType);

  // Given each class's label, when stringified, then it is the lower-case
  // hyphenated CycloneDX property value.
  BOMWERK_TEST_CHECK(std::string(to_string(MatchCoverage::Matched)) == "matched");
  BOMWERK_TEST_CHECK(std::string(to_string(MatchCoverage::UnmappedPurlType)) ==
                     "unmapped-purl-type");
  BOMWERK_TEST_CHECK(std::string(to_string(MatchCoverage::UnversionedPurl)) == "unversioned-purl");
  BOMWERK_TEST_CHECK(std::string(to_string(MatchCoverage::NoIdentifier)) == "no-identifier");

  // Given an empty component set, when summarized, then every count is zero.
  const MatchCoverageSummary empty_summary = summarize_match_coverage({});
  BOMWERK_TEST_CHECK(empty_summary.total == 0);
  BOMWERK_TEST_CHECK(empty_summary.matchable == 0);

  // Given a mixed set spanning every class, when summarized, then each
  // component lands in exactly one bucket and matchable is the complement.
  const std::vector<Component> mixed{
      component_with_purl("pkg:npm/left-pad@1.3.0"),                 // Matched
      component_with_purl("pkg:conan/openssl@3.2.0"),                // UnmappedPurlType
      component_with_purl("pkg:vcpkg/zlib"),                         // UnversionedPurl
      component_with_purl(""),                                       // NoIdentifier
      component_with_purl("pkg:generic/x@" + std::string(40, 'a')),  // Matched (commit)
  };
  const MatchCoverageSummary mixed_summary = summarize_match_coverage(mixed);
  BOMWERK_TEST_CHECK(mixed_summary.total == 5);
  BOMWERK_TEST_CHECK(mixed_summary.matchable == 2);
  BOMWERK_TEST_CHECK(mixed_summary.unmapped_purl_type == 1);
  BOMWERK_TEST_CHECK(mixed_summary.unversioned_purl == 1);
  BOMWERK_TEST_CHECK(mixed_summary.no_identifier == 1);

  std::puts("test_match_coverage: OK");
  return 0;
}
