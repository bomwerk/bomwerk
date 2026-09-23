#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace bomwerk::core
{

/// Qualitative severity band (CVSS v3.1 §5, table 14), plus `Unknown` for a
/// vector we could not score. Ordered so a numeric comparison ranks severity.
enum class SeverityRating
{
  Unknown,
  None,
  Low,
  Medium,
  High,
  Critical
};

/// A scored CVSS vector: `score` in [0, 10] and its band, or `has_score ==
/// false` / `Unknown` when the vector could not be parsed (unsupported
/// version, malformed metric). "Unknown" is never silently treated as 0: a
/// CRA tool must not present an unscored advisory as harmless.
struct CvssScore
{
  double score = 0.0;
  SeverityRating rating = SeverityRating::Unknown;
  bool has_score = false;
};

/// Lower-case-free display label ("Critical", "High", …, "Unknown").
[[nodiscard]] const char* to_string(SeverityRating rating);

/// One advisory affecting a component: its id (CVE-…/GHSA-…/OSV-…) and the
/// severity resolved for it (`has_score == false` when no CVSS v3 vector was
/// available). Shared by the vuln matcher (which fills it) and the HTML report
/// (which displays and sorts by it): both may include core, so the type lives
/// here rather than being mirrored across the module boundary.
struct ScoredAdvisory
{
  std::string id;
  CvssScore severity;

  /// CVE ids OSV's `aliases[]` array says name the SAME vulnerability as
  /// `id`: sorted, deduplicated. Populated only for an id resolved through
  /// OSV's full-record hydration (`/v1/query`), which is where `aliases[]`
  /// lives; empty otherwise, INCLUDING for an id that genuinely has no CVE
  /// alias: this field answers "does OSV know of one", never "there is
  /// none". This is what lets a GHSA-only OSV finding still join a CVE-keyed
  /// CVE-keyed bulk feed: verified live against `pkg:npm/lodash@4.17.15`,
  /// every one of its advisories was GHSA-keyed with the CVE only in
  /// `aliases[]` (2026-08-23).
  std::vector<std::string> cve_aliases;
};

/// Order two advisories worst-first for display: higher CVSS score before
/// lower, a scored advisory before an unscored one, ties broken by id so the
/// order is total and deterministic (rule 3).
[[nodiscard]] bool more_severe(const ScoredAdvisory& left, const ScoredAdvisory& right);

/// Compute the CVSS **base score** from a vector string of the form
/// `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (the shape OSV records in an
/// advisory's `severity[].score`). Implements the CVSS v3.0/v3.1 base metric
/// formula (v3.1 specification §7.1). Returns `has_score == false` for any
/// other version (v2, v4) or a malformed vector: honestly unscored, never a
/// misleading 0. Total-function and never throws (rule 1): hostile feed input
/// yields `Unknown`, not a crash.
///
/// Example: `score_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")`
/// -> `{9.8, Critical, true}`.
[[nodiscard]] CvssScore score_cvss_vector(std::string_view vector_string);

}  // namespace bomwerk::core
