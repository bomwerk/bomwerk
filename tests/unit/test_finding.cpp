#include <string>
#include <string_view>
#include <vector>

#include "support/check.hpp"
#include "vuln/finding.hpp"

using bomwerk::core::ScoredAdvisory;
using bomwerk::vuln::canonical_cve_id;
using bomwerk::vuln::is_cve_shaped_id;
using bomwerk::vuln::MatchOutcome;
using bomwerk::vuln::MatchProvenance;
using bomwerk::vuln::merge_outcomes;
using bomwerk::vuln::OsvDeltaReport;
using bomwerk::vuln::PurlAdvisoryDelta;
using bomwerk::vuln::VulnerabilityHit;

int main()
{
  // Given a well-formed CVE id (4-digit year, 4+ digit sequence), when
  // checked, then it is recognized.
  {
    BOMWERK_TEST_CHECK(is_cve_shaped_id("CVE-2020-28500"));
    BOMWERK_TEST_CHECK(is_cve_shaped_id("CVE-2024-0001"));
    // The sequence number has no fixed upper bound (CVE.org spec).
    BOMWERK_TEST_CHECK(is_cve_shaped_id("CVE-2024-123456789"));
  }

  // Given a sequence with FEWER than the minimum 4 digits, when checked,
  // then it is rejected: the shape check is strict, not "starts with digits".
  {
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-2024-1"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-2024-12"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-2024-123"));
  }

  // Given a year that is not exactly 4 digits, when checked, then it is
  // rejected.
  {
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-202-0001"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-20244-0001"));
  }

  // Given non-digit characters where digits are required, when checked, then
  // it is rejected.
  {
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-202a-0001"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-2024-000a"));
  }

  // Given the dash in the wrong position, a missing dash, lowercase "cve-",
  // an empty string, or a non-CVE id (GHSA/OSV), when checked, then all are
  // rejected: this is what lets aliases be filtered to CVE-only.
  {
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE2024-0001"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-20240001"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("cve-2024-0001"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id(""));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("GHSA-29mw-wpgm-hmr9"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("OSV-2020-484"));
  }

  // Given a string that is merely a prefix of the CVE shape (too short to
  // even contain a full year+dash+minimum sequence), when checked, then it
  // is rejected without reading past the end of the string.
  {
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-2024"));
    BOMWERK_TEST_CHECK(!is_cve_shaped_id("CVE-2024-"));
  }

  // Given a CVE id an operator typed or pasted, when canonicalized, then
  // casing and surrounding whitespace are normalized away: matching runs
  // against the feed's own spelling, which is the only one a stored
  // finding_state row holds.
  {
    BOMWERK_TEST_CHECK(canonical_cve_id("cve-2026-1234") == "CVE-2026-1234");
    BOMWERK_TEST_CHECK(canonical_cve_id("Cve-2026-1234") == "CVE-2026-1234");
    BOMWERK_TEST_CHECK(canonical_cve_id("  cve-2026-1234  ") == "CVE-2026-1234");
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-2026-1234\n") == "CVE-2026-1234");
    BOMWERK_TEST_CHECK(canonical_cve_id("\tCVE-2026-1234\r\n") == "CVE-2026-1234");
  }

  // Given an id that already is canonical, when canonicalized, then the result
  // compares equal to the input: the caller reports a normalization by that
  // comparison, so an unchanged id must never look like one.
  {
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-2020-28500") == "CVE-2020-28500");
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-2024-123456789") == "CVE-2024-123456789");
  }

  // Given something that is not CVE-shaped even after normalizing, when
  // canonicalized, then it comes back empty rather than being coerced. An
  // advisory id is deliberately included: finding_state can be keyed by one,
  // but the value fills a field the SRP labels CVE.
  {
    BOMWERK_TEST_CHECK(canonical_cve_id("").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("   ").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-2026-12").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-202a-0001").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("cve2026-1234").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("ghsa-29mw-wpgm-hmr9").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("gateway-fw").empty());
  }

  // Given an id with INNER whitespace, when canonicalized, then it is rejected:
  // only the ends are trimmed, so a pasted fragment carrying a line break in
  // the middle never silently becomes a different id.
  {
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-2026 -1234").empty());
    BOMWERK_TEST_CHECK(canonical_cve_id("CVE-2026-\n1234").empty());
  }

  // Given two outcomes each carrying non-empty deltas, when merged, then the
  // result concatenates both sides' changed_purls in purl-sorted order and
  // sums purls_examined/purls_unchanged: the fold path `merge_outcomes` added
  // for the bulk feeds, previously only ever exercised with default-empty deltas on both
  // sides.
  {
    MatchOutcome purl_outcome;
    purl_outcome.hits.push_back(VulnerabilityHit{
        "pkg:npm/zzz@1.0", {ScoredAdvisory{"CVE-2024-0001", {}, {}}}, MatchProvenance::PurlExact});
    PurlAdvisoryDelta zzz_delta;
    zzz_delta.purl = "pkg:npm/zzz@1.0";
    zzz_delta.added_advisory_ids = {"CVE-2024-0001"};
    purl_outcome.deltas.changed_purls.push_back(zzz_delta);
    purl_outcome.deltas.purls_examined = 3;
    purl_outcome.deltas.purls_unchanged = 2;

    MatchOutcome cpe_outcome;
    PurlAdvisoryDelta aaa_delta;
    aaa_delta.purl = "pkg:conan/aaa@1.0";
    aaa_delta.removed_advisory_ids = {"CVE-2023-0001"};
    cpe_outcome.deltas.changed_purls.push_back(aaa_delta);
    cpe_outcome.deltas.purls_examined = 1;
    cpe_outcome.deltas.purls_unchanged = 0;

    const MatchOutcome merged = merge_outcomes(purl_outcome, cpe_outcome);
    BOMWERK_TEST_CHECK(merged.deltas.changed_purls.size() == 2);
    // purl-sorted: "pkg:conan/aaa@1.0" < "pkg:npm/zzz@1.0".
    BOMWERK_TEST_CHECK(merged.deltas.changed_purls[0].purl == "pkg:conan/aaa@1.0");
    BOMWERK_TEST_CHECK(merged.deltas.changed_purls[0].removed_advisory_ids ==
                       std::vector<std::string>{"CVE-2023-0001"});
    BOMWERK_TEST_CHECK(merged.deltas.changed_purls[1].purl == "pkg:npm/zzz@1.0");
    BOMWERK_TEST_CHECK(merged.deltas.changed_purls[1].added_advisory_ids ==
                       std::vector<std::string>{"CVE-2024-0001"});
    BOMWERK_TEST_CHECK(merged.deltas.purls_examined == 4);
    BOMWERK_TEST_CHECK(merged.deltas.purls_unchanged == 2);
  }

  // Given two outcomes with default (empty) deltas, when merged, then the
  // merged deltas stay empty: the earlier shape this function already
  // handled correctly, unaffected by the folding logic added alongside it.
  {
    MatchOutcome purl_outcome;
    MatchOutcome cpe_outcome;
    const MatchOutcome merged = merge_outcomes(purl_outcome, cpe_outcome);
    BOMWERK_TEST_CHECK(merged.deltas.changed_purls.empty());
    BOMWERK_TEST_CHECK(merged.deltas.purls_examined == 0);
    BOMWERK_TEST_CHECK(merged.deltas.purls_unchanged == 0);
  }

  return 0;
}
