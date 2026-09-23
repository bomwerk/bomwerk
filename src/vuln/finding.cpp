#include "vuln/finding.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

#include "core/text.hpp"

namespace bomwerk::vuln
{
namespace
{

/// Total order over hits: purl first, then provenance so a purl carrying both
/// a purl-exact and a CPE-fallback hit always lists the stronger evidence
/// first. Ties beyond that cannot occur: one feed contributes at most one hit
/// per purl: but the comparator stays total regardless (rule 3).
bool orders_before(const VulnerabilityHit& left, const VulnerabilityHit& right)
{
  if (left.purl != right.purl)
  {
    return left.purl < right.purl;
  }
  return static_cast<int>(left.provenance) < static_cast<int>(right.provenance);
}

/// Total order over per-purl deltas: purl alone, since `merge_outcomes` never
/// sees two deltas for the same purl (only the OSV pass produces any).
bool delta_orders_before(const PurlAdvisoryDelta& left, const PurlAdvisoryDelta& right)
{
  return left.purl < right.purl;
}

bool is_ascii_digit(char character)
{
  return character >= '0' && character <= '9';
}

}  // namespace

bool is_cve_shaped_id(std::string_view candidate)
{
  constexpr std::string_view kPrefix = "CVE-";
  constexpr std::size_t kYearDigitCount = 4;
  constexpr std::size_t kMinSequenceDigitCount = 4;

  if (!candidate.starts_with(kPrefix))
  {
    return false;
  }
  const std::string_view remainder = candidate.substr(kPrefix.size());
  if (remainder.size() < kYearDigitCount + 1 + kMinSequenceDigitCount)
  {
    return false;
  }
  const std::string_view year_digits = remainder.substr(0, kYearDigitCount);
  if (!std::all_of(year_digits.begin(), year_digits.end(), is_ascii_digit))
  {
    return false;
  }
  if (remainder[kYearDigitCount] != '-')
  {
    return false;
  }
  const std::string_view sequence_digits = remainder.substr(kYearDigitCount + 1);
  return std::all_of(sequence_digits.begin(), sequence_digits.end(), is_ascii_digit);
}

std::string canonical_cve_id(std::string_view candidate)
{
  std::string canonical = core::to_upper_ascii(core::trimmed_view(candidate));
  if (!is_cve_shaped_id(canonical))
  {
    return {};
  }
  return canonical;
}

MatchOutcome merge_outcomes(MatchOutcome purl_outcome, MatchOutcome cpe_outcome)
{
  MatchOutcome merged = std::move(purl_outcome);
  merged.hits.reserve(merged.hits.size() + cpe_outcome.hits.size());
  for (VulnerabilityHit& hit : cpe_outcome.hits)
  {
    merged.hits.push_back(std::move(hit));
  }
  std::sort(merged.hits.begin(), merged.hits.end(), orders_before);

  // Fold in whatever delta bookkeeping either side produced. Only the
  // OSV pass populates this today (`match_via_cpe` has no analogous "previous
  // state" to diff against), but folding both sides: rather than assuming
  // which one is which: keeps this correct if that ever changes.
  merged.deltas.changed_purls.reserve(merged.deltas.changed_purls.size() +
                                      cpe_outcome.deltas.changed_purls.size());
  for (PurlAdvisoryDelta& delta : cpe_outcome.deltas.changed_purls)
  {
    merged.deltas.changed_purls.push_back(std::move(delta));
  }
  std::sort(merged.deltas.changed_purls.begin(), merged.deltas.changed_purls.end(),
            delta_orders_before);
  merged.deltas.purls_examined += cpe_outcome.deltas.purls_examined;
  merged.deltas.purls_unchanged += cpe_outcome.deltas.purls_unchanged;

  // The OSV pass owns `components_without_osv_coverage` (a purl fact it alone
  // classifies); the CPE pass owns which of those it managed to query. Combine
  // rather than assign so neither field depends on which outcome is which.
  merged.components_without_osv_coverage += cpe_outcome.components_without_osv_coverage;
  for (std::string& checked_purl : cpe_outcome.cpe_checked_purls)
  {
    merged.cpe_checked_purls.push_back(std::move(checked_purl));
  }
  std::sort(merged.cpe_checked_purls.begin(), merged.cpe_checked_purls.end());
  merged.cpe_checked_purls.erase(
      std::unique(merged.cpe_checked_purls.begin(), merged.cpe_checked_purls.end()),
      merged.cpe_checked_purls.end());
  return merged;
}

}  // namespace bomwerk::vuln
