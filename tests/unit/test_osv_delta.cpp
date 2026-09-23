#include <string>
#include <vector>

#include "support/check.hpp"
#include "vuln/delta.hpp"

using bomwerk::vuln::AdvisoryRevision;
using bomwerk::vuln::diff_advisory_revisions;
using bomwerk::vuln::PurlAdvisoryDelta;

namespace
{

constexpr const char* kPurl = "pkg:npm/lodash@4.17.15";

AdvisoryRevision revision(const char* advisory_id, const char* modified)
{
  return AdvisoryRevision{advisory_id, modified};
}

}  // namespace

int main()
{
  // Given no stored snapshot and three ALREADY-SORTED current advisories (the
  // contract `diff_advisory_revisions` documents: the caller sorts, osv.cpp's
  // `sort_and_deduplicate_revisions` is what does it in production), when
  // diffed, then all three are added and none modified or removed.
  {
    const std::vector<AdvisoryRevision> previous;
    const std::vector<AdvisoryRevision> current = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z"),
        revision("OSV-2024-9", "2026-01-01T00:00:00Z")};
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(delta.purl == kPurl);
    BOMWERK_TEST_CHECK(!delta.is_unchanged());
    BOMWERK_TEST_CHECK(delta.modified_advisory_ids.empty());
    BOMWERK_TEST_CHECK(delta.removed_advisory_ids.empty());
    const std::vector<std::string> expected_added = {"CVE-2024-0001", "GHSA-aaaa", "OSV-2024-9"};
    BOMWERK_TEST_CHECK(delta.added_advisory_ids == expected_added);
  }

  // Given a snapshot identical to the current answer, when diffed, then
  // is_unchanged() is true and all three lists are empty: the per-purl
  // idempotency contract.
  {
    const std::vector<AdvisoryRevision> previous = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z")};
    const std::vector<AdvisoryRevision> current = previous;
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(delta.is_unchanged());
    BOMWERK_TEST_CHECK(delta.added_advisory_ids.empty());
    BOMWERK_TEST_CHECK(delta.modified_advisory_ids.empty());
    BOMWERK_TEST_CHECK(delta.removed_advisory_ids.empty());
  }

  // Given one advisory whose `modified` string changed and another that did
  // not, when diffed, then exactly the changed one is reported modified.
  {
    const std::vector<AdvisoryRevision> previous = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z")};
    const std::vector<AdvisoryRevision> current = {
        revision("CVE-2024-0001", "2026-02-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z")};
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(!delta.is_unchanged());
    const std::vector<std::string> expected_modified = {"CVE-2024-0001"};
    BOMWERK_TEST_CHECK(delta.modified_advisory_ids == expected_modified);
    BOMWERK_TEST_CHECK(delta.added_advisory_ids.empty());
    BOMWERK_TEST_CHECK(delta.removed_advisory_ids.empty());
  }

  // Given an advisory present in the snapshot and absent from the current
  // answer, when diffed, then it is removed.
  {
    const std::vector<AdvisoryRevision> previous = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z")};
    const std::vector<AdvisoryRevision> current = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z")};
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(!delta.is_unchanged());
    const std::vector<std::string> expected_removed = {"GHSA-aaaa"};
    BOMWERK_TEST_CHECK(delta.removed_advisory_ids == expected_removed);
    BOMWERK_TEST_CHECK(delta.added_advisory_ids.empty());
    BOMWERK_TEST_CHECK(delta.modified_advisory_ids.empty());
  }

  // Given every previous advisory now absent (the "fixed" case: a purl that
  // HAD vulnerabilities and now has none), when diffed, then every one is
  // removed and none added or modified.
  {
    const std::vector<AdvisoryRevision> previous = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z")};
    const std::vector<AdvisoryRevision> current;
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(!delta.is_unchanged());
    const std::vector<std::string> expected_removed = {"CVE-2024-0001", "GHSA-aaaa"};
    BOMWERK_TEST_CHECK(delta.removed_advisory_ids == expected_removed);
  }

  // Given an advisory with an EMPTY `modified` on both sides (a feed that
  // omitted the field), when diffed, then it is unchanged: an omitted field
  // must never look like a change every single refresh.
  {
    const std::vector<AdvisoryRevision> previous = {revision("CVE-2024-0001", "")};
    const std::vector<AdvisoryRevision> current = {revision("CVE-2024-0001", "")};
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(delta.is_unchanged());
  }

  // Given both empty (a purl with no advisories before or after: the common
  // case for a clean repository), when diffed, then unchanged and empty :
  // computing a delta must never fabricate a change out of nothing.
  {
    const std::vector<AdvisoryRevision> previous;
    const std::vector<AdvisoryRevision> current;
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(delta.is_unchanged());
  }

  // Given a purl with one added, one modified, and one removed advisory all
  // in the SAME refresh, when diffed, then all three are classified
  // correctly and none leaks into the wrong list.
  {
    const std::vector<AdvisoryRevision> previous = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),  // stays, unmodified
        revision("GHSA-aaaa", "2026-01-01T00:00:00Z"),      // will be modified
        revision("OSV-2024-9", "2026-01-01T00:00:00Z")};    // will be removed
    const std::vector<AdvisoryRevision> current = {
        revision("CVE-2024-0001", "2026-01-01T00:00:00Z"),
        revision("CVE-2026-9999", "2026-03-01T00:00:00Z"),
        revision("GHSA-aaaa", "2026-02-15T00:00:00Z")};
    const PurlAdvisoryDelta delta = diff_advisory_revisions(kPurl, previous, current);
    BOMWERK_TEST_CHECK(!delta.is_unchanged());
    const std::vector<std::string> expected_added = {"CVE-2026-9999"};
    const std::vector<std::string> expected_modified = {"GHSA-aaaa"};
    const std::vector<std::string> expected_removed = {"OSV-2024-9"};
    BOMWERK_TEST_CHECK(delta.added_advisory_ids == expected_added);
    BOMWERK_TEST_CHECK(delta.modified_advisory_ids == expected_modified);
    BOMWERK_TEST_CHECK(delta.removed_advisory_ids == expected_removed);
  }

  // Given the purl string itself, when diffed, then it is carried onto the
  // result unchanged: the delta always knows which purl it describes.
  {
    const std::vector<AdvisoryRevision> previous;
    const std::vector<AdvisoryRevision> current;
    const PurlAdvisoryDelta delta =
        diff_advisory_revisions("pkg:pypi/requests@2.31.0", previous, current);
    BOMWERK_TEST_CHECK(delta.purl == "pkg:pypi/requests@2.31.0");
  }

  return 0;
}
