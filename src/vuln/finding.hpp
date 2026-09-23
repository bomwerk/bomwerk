#pragma once
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "core/cvss.hpp"
#include "vuln/delta.hpp"

namespace bomwerk::vuln
{

/// How a finding was matched: the difference between "this advisory names
/// this exact package" and "this advisory names *a* package with this name".
///
/// A CRA tool must not present the two with equal weight (rule: never claim
/// more accuracy than the data supports), so this travels with every hit all
/// the way to stdout and the HTML report.
enum class MatchProvenance
{
  PurlExact,   ///< matched by purl or by resolved commit id against OSV: the package
               ///< identity bomwerk queried is the identity the advisory names
  CpeFallback  ///< matched by a CPE match string with a WILDCARD VENDOR against NVD
               ///<, the only path available for a purl type no feed maps. A
               ///< different vendor's product sharing the name matches too, so these
               ///< are lower-confidence by construction
};

/// Lower-case, hyphenated label: the one user-facing string table shared by
/// the CLI listing and the HTML report (future `--lang` hook). Same shape as
/// `core::to_string(MatchCoverage)` and `core::to_string(Confidence)`.
constexpr const char* to_string(MatchProvenance provenance)
{
  switch (provenance)
  {
    case MatchProvenance::PurlExact:
      return "purl-exact";
    case MatchProvenance::CpeFallback:
      return "cpe-fallback";
  }
  return "purl-exact";  // unreachable: all enumerators handled above
}

/// True when findings from `provenance` must be presented as lower-confidence.
/// A positively-named predicate over the enum rather than an `== CpeFallback`
/// test scattered across surfaces: when a third provenance arrives, every
/// display decides correctly without being revisited.
constexpr bool is_high_confidence_provenance(MatchProvenance provenance)
{
  return provenance == MatchProvenance::PurlExact;
}

/// True when `candidate` has the CVE identifier SHAPE: `CVE-` + a 4-digit
/// year + `-` + at least 4 digits (the CVE.org spec: the sequence number is
/// never fewer than 4 digits and has no fixed upper bound). A strict, local,
/// non-regex check (rule 1: no `std::regex`, matching the CMake parser's
/// precedent against catastrophic backtracking on hostile input): used to
/// pick the CVE-shaped entries out of OSV's `aliases[]` array (osv.cpp) and,
/// for any CVE-keyed consumer, to recognize a lookup key before it
/// reaches a bound SQL parameter (defense in depth; parameters are never
/// concatenated into SQL regardless).
[[nodiscard]] bool is_cve_shaped_id(std::string_view candidate);

/// The canonical spelling of `candidate` when it is CVE-shaped once
/// surrounding ASCII whitespace is trimmed and the id is ASCII upper-cased;
/// empty for anything else. Feeds spell CVE ids in exactly one way, and a
/// stored `finding_state` row holds that spelling, so an operator's
/// `cve-2026-1234` (or an id pasted with a trailing newline) has to be
/// NORMALIZED rather than merely tolerated: accepting it without rewriting
/// it would match no stored row at all.
///
/// Returns a value equal to `candidate` when nothing needed changing, so a
/// caller reports a normalization by comparing the two rather than by asking
/// this function to describe what it did.
///
/// Deliberately narrower than the ids `finding_state` can be keyed by: an
/// advisory id (`GHSA-...`) is not CVE-shaped and comes back empty, because
/// the consumer of this value fills a field the SRP labels CVE.
[[nodiscard]] std::string canonical_cve_id(std::string_view candidate);

/// One affected component: the queried purl plus every advisory the feed knows
/// for it (CVE-…, GHSA-…, OSV-…), each carrying the CVSS severity resolved
/// from the advisory's full record. Advisories are deduplicated by id and
/// ordered worst-severity-first (`core::more_severe`), so the highest-severity
/// finding leads and the order is deterministic (rule 3).
///
/// `purl` is always the COMPONENT's purl, even on the CPE path where the query
/// itself used a CPE match string: every downstream surface joins findings to
/// components by purl, and a second identity would let those joins drift.
struct VulnerabilityHit
{
  std::string purl;
  std::vector<core::ScoredAdvisory> advisories;
  MatchProvenance provenance = MatchProvenance::PurlExact;
};

/// Result of one matching run. Separating `hits` from
/// `components_without_osv_coverage` matters for a CRA compliance tool: "0
/// hits" must never be printed in a way that reads as "checked and clean"
/// for a component the feed structurally cannot check at all (rule: never
/// claim more accuracy than the data supports).
struct MatchOutcome
{
  std::vector<VulnerabilityHit> hits;

  /// What moved since the previous refresh, per purl: the OSV client's
  /// own delta bookkeeping (osv.cpp), always empty for a CPE-fallback outcome
  /// (NVD CPE matching has no analogous "previous state" to diff against).
  /// Empty on a run that changed nothing, INCLUDING a run answered entirely
  /// from cache: that emptiness is the idempotency proof a test asserts
  /// directly. See `OsvDeltaReport`'s own doc comment (delta.hpp) for why
  /// the finding-state machine keys its NEW/still-open/resolved
  /// transitions off `hits` instead of this field.
  OsvDeltaReport deltas;

  /// Components skipped because their purl's package type has no OSV
  /// ecosystem today (Conan, vcpkg, generic: verified against OSV's own
  /// ecosystem list, not inferred from a failed query). These are never
  /// queried by the OSV path: sending them would waste a request, and a
  /// returned empty result would misleadingly look identical to "checked,
  /// clean". This stays a fact about the PURL, unchanged by whether the
  /// CPE fallback later checked the same component against NVD.
  std::size_t components_without_osv_coverage = 0;

  /// The purls of the components above that the CPE fallback actually
  /// resolved an answer for, sorted and deduplicated. Empty without
  /// `--cpe-fallback`, and empty for a component whose NVD query failed: this
  /// records what was genuinely checked, not what was attempted.
  ///
  /// Deliberately the LIST and not a count: every consumer (the stdout note,
  /// the report's tile, its notice and its per-row badges) derives its number
  /// from `size()`, so the figure shown and the rows tagged can never disagree
  ///: the same single-source-of-truth shape used for
  /// `ReportContext::components_without_osv_coverage_purls`.
  std::vector<std::string> cpe_checked_purls;
};

/// Fold a CPE-fallback outcome into a purl-driven one: hits are concatenated
/// and re-sorted by `(purl, provenance)` for a total, byte-stable order, and
/// the counters are summed.
///
/// This is the ONLY place the two feeds' results meet, deliberately: the two
/// runs may execute concurrently (the CLI puts the throttled NVD path on its
/// own thread), so ordering must come from the data and never from whichever
/// thread finished first (rule 3).
[[nodiscard]] MatchOutcome merge_outcomes(MatchOutcome purl_outcome, MatchOutcome cpe_outcome);

}  // namespace bomwerk::vuln
