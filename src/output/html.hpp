#pragma once
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "core/cvss.hpp"
#include "core/model.hpp"
#include "core/result.hpp"
#include "core/warning.hpp"
#include "output/tool_info.hpp"

namespace bomwerk::output
{

/// Company-supplied look and metadata for the HTML report, loaded from a JSON
/// config (`scan --report-config <file>`) so branding lives in a file a
/// company edits, not in an ever-growing set of CLI flags. Every field is
/// optional; an all-default value renders the plain bomwerk report. Text
/// fields are HTML-escaped at render like any other dynamic value.
struct ReportBranding
{
  std::string company_name;  ///< shown in the header band and footer
  std::string contact;       ///< email or URL, display only (escaped, never linked blindly)
  std::string footer_note;   ///< e.g. "Confidential: internal CRA compliance use"

  /// A ready-to-embed `data:image/...;base64,...` URI built by
  /// `load_report_branding` from the config's `logo_path`: the bytes are
  /// inlined so the report stays one self-contained file. Empty => no logo.
  std::string logo_data_uri;

  /// Validated `#rgb`/`#rrggbb` accent color, or empty. This is the ONLY
  /// styling a company controls (a single metadata value, deliberately not
  /// arbitrary CSS): it recolors the header band and links in both themes.
  /// A malformed value is dropped with a warning, never interpolated raw.
  std::string accent_color;

  /// Label shown for an advisory whose CVSS severity could not be resolved.
  /// Empty => the built-in default ("No info"); a company can override the
  /// wording via the config's `unknown_severity_label` key. Never rendered as
  /// "0": an unscored advisory is unknown, not harmless.
  std::string unknown_severity_label;
};

/// Load `ReportBranding` from a JSON config file. Never throws and always
/// returns a usable value (rule 1): a missing/unreadable/oversized file, bad
/// JSON, wrong-typed fields, an unreadable or oversized logo, or a malformed
/// accent color each degrade to a warning and a partial/empty branding :
/// the report still renders. Relative `logo_path` is resolved against the
/// config file's own directory. Recognized keys: `company_name`, `contact`,
/// `footer_note`, `accent_color`, `unknown_severity_label`, `logo_path`
/// (png/jpg/jpeg/gif/svg/webp).
[[nodiscard]] core::Result<ReportBranding> load_report_branding(
    const std::filesystem::path& config_path);

/// One affected component in the report's vulnerability table: the queried
/// purl plus every advisory known for it, each carrying its CVSS severity
/// (`core::ScoredAdvisory`). Mirrors `vuln::VulnerabilityHit` on purpose but
/// is redefined here because output may only include core (module dependency
/// law): the CLI copies the fields across. The advisory type itself is a core
/// type, so no per-advisory mirroring is needed.
/// Which feed produced a finding, mirroring `vuln::MatchProvenance` (which
/// `output` may not include: module dependency law; the CLI maps across).
///
/// The report derives two separate things from this, which is why it is the
/// SOURCE and not a `bool lower_confidence`: how much to trust the finding, and
/// which vulnerability database to cite it to. A CPE-fallback finding linked to
/// osv.dev would send the reader to a database that, by definition, could not
/// match that component at all.
enum class FindingSource
{
  OsvPurlMatch,  ///< OSV matched the component's purl or its resolved commit id
  NvdCpeMatch    ///< CPE fallback: NVD matched a CPE with a WILDCARD VENDOR, so a
                 ///< different vendor's product of the same name matches too
};

/// True when findings from `source` may be presented at full weight.
constexpr bool is_high_confidence_source(FindingSource source)
{
  return source == FindingSource::OsvPurlMatch;
}

struct ReportVulnerability
{
  std::string purl;
  std::vector<core::ScoredAdvisory> advisories;

  /// Defaults to the OSV path so every earlier construction site stays correct.
  FindingSource source = FindingSource::OsvPurlMatch;
};

/// How the report's component list fared against build evidence. This mirrors
/// observe::UsedSetSummary without creating an output -> observe dependency.
struct BuildUsageSummary
{
  std::size_t judged = 0;         ///< components carrying a repository root
  std::size_t used = 0;           ///< of judged, those carrying a build signal
  std::size_t unused = 0;         ///< of judged, those carrying no build signal
  std::size_t not_judgeable = 0;  ///< rootless components a trace cannot speak to
};

/// Summarize used_in_build only for components that record a repository root.
/// The caller separately states whether a trace was actually applied: the
/// model defaults used_in_build to true, so this function alone can never
/// prove that a zero means the build was checked.
[[nodiscard]] BuildUsageSummary summarize_build_usage(
    const std::vector<core::Component>& components);

/// Everything the HTML report shows besides the component list itself,
/// aggregated by the caller (cli/) so this writer: like the CycloneDX one :
/// depends only on core.
struct ReportContext
{
  ToolInfo tool;                   ///< identifies bomwerk itself, never the scanned product
  core::ReleaseMeta release_meta;  ///< product identity; empty product_id => omitted
  ReportBranding branding;         ///< company look/metadata; all-default => plain report
  std::string scanned_root;        ///< directory that was scanned, display only
  std::size_t scanned_file_count = 0;

  /// false when rendering an existing SBOM (`trim --html`): CycloneDX does not
  /// retain the original scan's file count, so the report shows an explicit
  /// unknown instead of a misleading zero.
  bool scan_file_count_available = true;

  /// Set only after a usable observe trace was mapped onto the component list.
  /// The unused tile/card/badges are gated on this flag so a plain scan never
  /// presents the model's default used_in_build values as observed evidence.
  bool build_trace_applied = false;

  /// false => the report says "not checked" and never shows a reassuring
  /// zero (`--no-vuln`; rule: never claim more accuracy than the data
  /// supports).
  bool vulnerability_check_enabled = true;
  /// false for reports created by a command that does not perform matching at
  /// all (`trim --html`), so its not-checked text does not claim --no-vuln was
  /// passed to a scan.
  bool vulnerability_check_applicable = true;
  bool vulnerability_check_offline = false;  ///< true => cache-only match, labeled in the report
  std::vector<ReportVulnerability> vulnerabilities;

  /// The purls of every component OSV structurally cannot check
  /// (Conan/vcpkg/generic), populated by the caller from
  /// `vuln::has_no_known_osv_coverage`. This list is the single source of
  /// truth: the report tags exactly these rows AND derives the summary
  /// metric/notice count from its size, so the number and the tagged rows can
  /// never disagree. Surfaced so "0 findings" is never misread as "checked,
  /// clean" for a component OSV cannot check.
  std::vector<std::string> components_without_osv_coverage_purls;

  /// The subset of the list above that the CPE fallback actually checked
  /// against NVD (`scan --cpe-fallback`). These rows swap their "no OSV
  /// coverage" badge for a "checked via CPE" one, and their count is subtracted
  /// from the not-checked figure: so the two lists partition the uncovered
  /// components exactly and no component is ever reported as both. Empty
  /// without the flag, which leaves every match coverage surface byte-identical.
  std::vector<std::string> components_checked_via_cpe_fallback_purls;

  /// Scan warnings, replayed verbatim in the report's last section. Kept in
  /// caller order (the deterministic pipeline order tells the story of the
  /// run): the one collection this writer does not re-sort.
  std::vector<core::Warning> warnings;
};

/// Render `components` plus everything in `context` as ONE self-contained
/// HTML document: inline CSS, no JavaScript, no
/// external resource loads: the only outbound references are plain
/// `<a href>` links from well-formed advisory ids to osv.dev. Sections:
/// summary numbers, optional unused-components card, component table,
/// match-coverage card, vulnerability (CVE) table, warnings.
///
/// The match-coverage card, its summary tile, and each unmatched
/// component's per-row badge are computed from `components` alone via
/// `core::classify_match_coverage`: a pure function of a component's purl :
/// so unlike the vulnerability sections they are NOT gated on
/// `context.vulnerability_check_enabled` and survive `--no-vuln`.
///
/// Safe on hostile input (rule 1) and never throws: every dynamic value is
/// HTML-escaped, C0 control bytes and DEL are replaced with U+FFFD, and an
/// advisory id becomes a link only when it matches `[A-Za-z0-9._-]{1,100}`
/// (anything else degrades to escaped text): a component named
/// `<script>…</script>` renders as text, never as markup.
///
/// Deterministic (rule 3): components are sorted by
/// `core::component_identity` (same order as the CycloneDX writer),
/// vulnerabilities are merged by purl with ids sorted and deduplicated, so
/// caller ordering cannot change the bytes; the generated-at timestamp
/// honors `SOURCE_DATE_EPOCH` (see `core::current_timestamp_iso8601`: a
/// reproducibility mechanism, not a trust anchor). Two runs over the same
/// inputs with it pinned are byte-identical.
[[nodiscard]] std::string write_html_report(const std::vector<core::Component>& components,
                                            const ReportContext& context);

}  // namespace bomwerk::output
