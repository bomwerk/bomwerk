#pragma once
#include <cstddef>
#include <string>
#include <vector>

namespace bomwerk::vuln
{

/// One purl's advisory identity as OSV last stated it: the advisory id plus
/// OSV's own `modified` timestamp for it. `modified` is stored VERBATIM and
/// compared for EQUALITY only: never parsed as a date. OSV documents it as
/// RFC3339, but a feed is untrusted input (rule 1) and equality is all a
/// delta needs. An absent `modified` is the empty string, which compares
/// stably against itself: a feed that omits the field yields "unchanged",
/// never "changed every refresh".
struct AdvisoryRevision
{
  std::string advisory_id;
  std::string modified;
};

/// What changed for one purl between a stored snapshot and the feed's latest
/// answer. The three lists are disjoint, sorted by advisory id and
/// deduplicated (rule 3).
struct PurlAdvisoryDelta
{
  std::string purl;
  std::vector<std::string> added_advisory_ids;
  std::vector<std::string> modified_advisory_ids;
  std::vector<std::string> removed_advisory_ids;

  /// True when this refresh confirmed the purl's advisory set is exactly
  /// what was already stored. THIS is what "feeds update idempotently" means
  /// at the per-purl level, expressed once so no caller re-derives it.
  [[nodiscard]] bool is_unchanged() const;
};

/// Every purl whose advisory set moved this refresh, sorted by purl. A purl
/// with an empty delta is deliberately ABSENT rather than present-and-empty:
/// a refresh that changed nothing yields an empty `changed_purls`, which is
/// the idempotency property a test asserts directly.
///
/// NOT what a finding-state machine keys its
/// NEW/still-open/resolved transitions off, despite an earlier plan to wire
/// it that way: a delta-only view is silent about a purl whose advisory set
/// is UNCHANGED, and "unchanged" is exactly the common case a persistent
/// still-open finding needs to keep matching every cycle: feeding only
/// `changed_purls` in would make an untouched, still-vulnerable component
/// vanish from the observed set and get misclassified as resolved on the
/// very next cycle. A cycle's own observation step
/// flattens `MatchOutcome::hits` instead, the full current match state, for
/// exactly this reason. This report remains what it always was: the
/// idempotency proof above, and raw material for a future "what changed
/// since last night" operator-facing summary.
struct OsvDeltaReport
{
  std::vector<PurlAdvisoryDelta> changed_purls;
  std::size_t purls_examined = 0;
  std::size_t purls_unchanged = 0;
};

/// Diff one purl's stored snapshot against what the feed just said.
///
/// Both ranges MUST already be sorted by advisory id and deduplicated: the
/// caller owns that (the SQL reads `ORDER BY advisory_id`; the OSV extractor
/// sorts). A classic two-pointer merge over `<algorithm>`: NOT
/// `std::ranges` (the AppleClang 14 toolchain caveat in docs/CONTRIBUTING.md): so this is
/// O(previous.size() + current.size()) with no allocation beyond the output.
///
/// Total function, never throws: a duplicate id within one input (a contract
/// violation by the caller) still produces a deterministic, non-crashing
/// classification rather than undefined behavior (rule 1).
[[nodiscard]] PurlAdvisoryDelta diff_advisory_revisions(
    const std::string& purl, const std::vector<AdvisoryRevision>& previous,
    const std::vector<AdvisoryRevision>& current);

}  // namespace bomwerk::vuln
