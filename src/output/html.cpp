#include "output/html.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>
#include <utility>

#include "core/base64.hpp"
#include "core/file_io.hpp"
#include "core/json_utils.hpp"
#include "core/match_coverage.hpp"
#include "core/text.hpp"
#include "core/timestamp.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"

namespace bomwerk::output
{
namespace
{

/// Advisory ids longer than this never become links: real OSV/CVE/GHSA ids
/// are far shorter, so anything bigger is hostile or corrupt feed data.
constexpr std::size_t kMaxLinkableAdvisoryIdLength = 100;

/// osv.dev resolves every advisory id family OSV returns (CVE/GHSA/OSV/…).
constexpr std::string_view kOsvAdvisoryUrlPrefix = "https://osv.dev/vulnerability/";

/// A CPE-fallback finding is cited to NVD, the database that actually
/// produced it. Linking it to osv.dev would point the reader at a database
/// which: by the very definition of this path: cannot match that component.
constexpr std::string_view kNvdAdvisoryUrlPrefix = "https://nvd.nist.gov/vuln/detail/";

constexpr std::string_view advisory_url_prefix_for(FindingSource source)
{
  return source == FindingSource::NvdCpeMatch ? kNvdAdvisoryUrlPrefix : kOsvAdvisoryUrlPrefix;
}

/// A logo is inlined as a data URI (report stays self-contained); cap the
/// source file so a huge image cannot bloat every report unbounded.
constexpr std::size_t kMaxLogoBytes = 512u * 1024u;

/// Branding text caps (bytes). Generous for real company names/notes, but
/// bounded so an accidental novel in the config cannot break the header
/// layout: an over-long value is truncated with a warning, never dropped.
constexpr std::size_t kMaxCompanyNameBytes = 80;
constexpr std::size_t kMaxContactBytes = 160;
constexpr std::size_t kMaxFooterNoteBytes = 400;
constexpr std::size_t kMaxSeverityLabelBytes = 40;

/// Recognized logo extensions -> MIME type. The MIME is chosen from this fixed
/// table (never from the file's own bytes), so a data URI can only ever carry
/// a type we vetted. SVG is allowed because it is embedded via `<img src>`,
/// where browsers do NOT run any script the SVG contains.
constexpr std::array<std::pair<std::string_view, std::string_view>, 6> kLogoMimeByExtension{{
    {".png", "image/png"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".gif", "image/gif"},
    {".svg", "image/svg+xml"},
    {".webp", "image/webp"},
}};

/// U+FFFD REPLACEMENT CHARACTER (UTF-8), emitted in place of control bytes so
/// hostile component fields cannot inject raw controls into the document.
constexpr std::string_view kReplacementCharacter = "\xEF\xBF\xBD";

constexpr char kDeleteCharacter = '\x7F';

/// Rough document budget so building the report does a handful of
/// allocations instead of hundreds; correctness never depends on it.
constexpr std::size_t kReservedBaseBytes = 16 * 1024;
constexpr std::size_t kReservedBytesPerComponent = 512;

/// The report's entire appearance lives here (ONE self-contained
/// file, inline CSS, no JavaScript). Light/dark follows the reader's OS
/// preference; every color is a variable so both themes share one rule set.
constexpr std::string_view kStyleSheet = R"css(
:root {
  --page-bg: #f5f7fa; --card-bg: #ffffff; --ink: #1c2733; --muted: #5c6a78;
  --line: #e2e8ef; --link: #0b5fd7; --accent: #0b5fd7; --good: #1a7f37;
  --good-bg: #e7f4ec; --warn: #915c00; --warn-bg: #fff3d1; --bad: #c62828;
  --bad-bg: #fdecea; --chip-bg: #edf1f5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --page-bg: #10151c; --card-bg: #191f28; --ink: #e7ecf3; --muted: #98a5b3;
    --line: #2a3340; --link: #6ea8ff; --accent: #6ea8ff; --good: #4fbf72;
    --good-bg: #17301f; --warn: #e3b341; --warn-bg: #302708; --bad: #ff7b72;
    --bad-bg: #3b1a18; --chip-bg: #232b36;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--page-bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
    "Helvetica Neue", Arial, sans-serif;
}
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }
a { color: var(--link); text-decoration: none; }
a:hover { text-decoration: underline; }
main, footer.page { max-width: 1100px; margin: 0 auto; padding: 0 24px; }
header.page {
  border-top: 4px solid var(--accent); background: var(--card-bg);
  border-bottom: 1px solid var(--line);
}
.header-band {
  max-width: 1100px; margin: 0 auto; padding: 26px 24px 22px;
  display: flex; gap: 20px; align-items: center;
}
.logo { max-height: 64px; max-width: 220px; width: auto; height: auto; flex: 0 0 auto; }
.header-text { min-width: 0; }
.brand {
  margin: 0; color: var(--accent); font-weight: 700; letter-spacing: 0.08em;
  text-transform: uppercase; font-size: 0.8em;
}
h1 { margin: 4px 0 2px; font-size: 1.45em; }
.product { margin: 0 0 2px; font-size: 1.05em; font-weight: 600; }
.meta { margin: 2px 0 0; color: var(--muted); font-size: 0.9em; }
h2 { margin: 0; font-size: 1.05em; }
.posture {
  display: flex; align-items: center; gap: 10px; margin: 20px 0 4px;
  padding: 14px 18px; border-radius: 10px; font-weight: 600;
  border: 1px solid var(--line);
}
.posture::before { font-size: 1.2em; line-height: 1; }
.posture-good { color: var(--good); background: var(--good-bg); }
.posture-good::before { content: "\2714"; }
.posture-bad { color: var(--bad); background: var(--bad-bg); }
.posture-bad::before { content: "\2716"; }
.posture-warn { color: var(--warn); background: var(--warn-bg); }
.posture-warn::before { content: "\26A0"; }
section.card, details.card {
  background: var(--card-bg); border: 1px solid var(--line); border-radius: 10px;
  padding: 18px 20px; margin: 16px 0;
}
details.card { padding: 0; }
details.card > summary {
  list-style: none; cursor: pointer; padding: 16px 20px;
  display: flex; align-items: center; gap: 8px; user-select: none;
}
details.card > summary::-webkit-details-marker { display: none; }
details.card > summary::after {
  content: "\25BE"; margin-left: auto; color: var(--muted); transition: transform 0.15s;
}
details.card:not([open]) > summary::after { transform: rotate(-90deg); }
details.card > summary:hover { color: var(--accent); }
details.card .card-body { padding: 0 20px 18px; }
.count { color: var(--muted); font-weight: 400; }
.tag {
  font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.05em;
  padding: 1px 6px; border-radius: 4px; background: var(--chip-bg);
}
.summary {
  display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; margin: 20px 0 4px;
}
.metric {
  background: var(--card-bg); border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 16px;
}
.metric-value { display: block; font-size: 1.65em; font-weight: 700; }
.metric-label { color: var(--muted); font-size: 0.82em; }
.metric.good .metric-value { color: var(--good); }
.metric.warn .metric-value { color: var(--warn); }
.metric.bad .metric-value { color: var(--bad); }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; }
th, td {
  text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line);
  vertical-align: top;
}
th { color: var(--muted); font-size: 0.82em; text-transform: uppercase; letter-spacing: 0.04em; }
tbody tr:last-child td { border-bottom: none; }
td code { word-break: break-all; }
.badge {
  display: inline-block; padding: 1px 8px; border-radius: 999px;
  font-size: 0.78em; font-weight: 600; white-space: nowrap;
}
.badge.high { color: var(--good); background: var(--good-bg); }
.badge.medium { color: var(--warn); background: var(--warn-bg); }
.badge.low { color: var(--muted); background: var(--chip-bg); }
.badge.warn { color: var(--warn); background: var(--warn-bg); }
.badge.bad { color: var(--bad); background: var(--bad-bg); }
.badge.sev-critical { color: #fff; background: var(--bad); }
.badge.sev-high { color: var(--bad); background: var(--bad-bg); }
.badge.sev-medium { color: var(--warn); background: var(--warn-bg); }
.badge.sev-low { color: var(--good); background: var(--good-bg); }
.badge.sev-none { color: var(--muted); background: var(--chip-bg); }
.badge.sev-unknown { color: var(--muted); background: var(--chip-bg); font-style: italic; }
.advisory { display: inline-flex; align-items: center; gap: 6px; margin: 2px 10px 2px 0; }
.notice {
  margin: 10px 0 0; padding: 10px 14px; border-radius: 8px;
  color: var(--warn); background: var(--warn-bg);
}
.muted { color: var(--muted); }
.empty { color: var(--muted); font-style: italic; }
ol.warnings { margin: 0; padding-left: 22px; }
ol.warnings li { margin: 4px 0; overflow-wrap: anywhere; }
footer.page {
  max-width: 1100px; margin: 24px auto 0; padding: 16px 24px 36px;
  border-top: 1px solid var(--line); color: var(--muted); font-size: 0.85em;
}
.footer-note { margin: 0 0 4px; }
/* Print / PDF export (CRA evidence is filed on paper): flatten to ink on
   white, drop interactive chrome, and force every collapsible section open
   so nothing a reader collapsed is missing from the printed record. */
@media print {
  body { background: #fff; color: #000; }
  header.page, section.card, details.card, .metric, .posture { box-shadow: none; }
  details.card > summary { cursor: default; }
  details.card > summary::after { display: none; }
  details.card:not([open]) > .card-body { display: block !important; }
  a { color: #000; text-decoration: underline; }
}
)css";

/// HTML-escape `text` for both element and attribute contexts. C0 control
/// bytes (except tab/newline, which are plain whitespace in markup) and DEL
/// become U+FFFD so hostile input cannot place raw controls in the file;
/// all other bytes pass through untouched (the document declares UTF-8).
std::string escape_html(std::string_view text)
{
  std::string escaped;
  escaped.reserve(text.size());
  for (const char character : text)
  {
    switch (character)
    {
      case '&':
        escaped += "&amp;";
        break;
      case '<':
        escaped += "&lt;";
        break;
      case '>':
        escaped += "&gt;";
        break;
      case '"':
        escaped += "&quot;";
        break;
      case '\'':
        escaped += "&#39;";
        break;
      default:
        if ((static_cast<unsigned char>(character) < static_cast<unsigned char>(' ') &&
             character != '\t' && character != '\n') ||
            character == kDeleteCharacter)
        {
          escaped += kReplacementCharacter;
        }
        else
        {
          escaped += character;
        }
        break;
    }
  }
  return escaped;
}

bool is_ascii_alphanumeric(char character)
{
  return (character >= '0' && character <= '9') || (character >= 'a' && character <= 'z') ||
         (character >= 'A' && character <= 'Z');
}

/// True when `advisory_id` is safe to embed in an osv.dev URL. Anything
/// outside this strict shape (hostile cache/feed content) is rendered as
/// escaped text instead of a link: reported, never executable.
bool is_linkable_advisory_id(std::string_view advisory_id)
{
  if (advisory_id.empty() || advisory_id.size() > kMaxLinkableAdvisoryIdLength)
  {
    return false;
  }
  for (const char character : advisory_id)
  {
    if (!is_ascii_alphanumeric(character) && character != '-' && character != '.' &&
        character != '_')
    {
      return false;
    }
  }
  return true;
}

/// Truncate `text` to at most `max_bytes`, backing up off any partial UTF-8
/// sequence so a multi-byte character is never cut in half (a company name
/// deserves a clean end, not a mojibake tail). Returns true when it trimmed.
bool truncate_to_bytes(std::string& text, std::size_t max_bytes)
{
  if (text.size() <= max_bytes)
  {
    return false;
  }
  std::size_t cut = max_bytes;
  // UTF-8 continuation bytes are 0b10xxxxxx; step back over any so the cut
  // lands on a character boundary.
  while (cut > 0 && (static_cast<unsigned char>(text[cut]) & 0xC0) == 0x80)
  {
    --cut;
  }
  text.resize(cut);
  return true;
}

/// True when `value` is a strict `#rgb` or `#rrggbb` hex color. This is the
/// only company-controlled styling (see `ReportBranding::accent_color`), so
/// it is validated to a fixed shape and never interpolated raw into CSS.
bool is_valid_accent_color(std::string_view value)
{
  if (value.size() != 4 && value.size() != 7)
  {
    return false;
  }
  return value.front() == '#' && core::is_hex_digits(value.substr(1));
}

/// MIME type for a lower-cased logo extension (".png"), or empty when the
/// extension is not in the vetted allowlist.
std::string_view logo_mime_for_extension(std::string_view extension_lower)
{
  for (const auto& [extension, mime] : kLogoMimeByExtension)
  {
    if (extension == extension_lower)
    {
      return mime;
    }
  }
  return {};
}

/// ": " for an empty optional field, the escaped value otherwise.
std::string cell_text_or_dash(const std::string& value)
{
  return value.empty() ? std::string(": ") : escape_html(value);
}

std::string advisory_count_label(std::size_t advisory_count)
{
  if (advisory_count == 1)
  {
    return "1 advisory";
  }
  return std::to_string(advisory_count) + " advisories";
}

/// Present components strongest-evidence-first: highest confidence at the top
/// (a reader triages the High-confidence findings first), with
/// `core::component_identity` breaking ties so the order stays total and
/// byte-deterministic (rule 3). The CycloneDX writer keeps its own
/// identity-only order; the two documents serve different readers.
std::vector<const core::Component*> components_sorted_for_report(
    const std::vector<core::Component>& components)
{
  std::vector<const core::Component*> sorted_components;
  sorted_components.reserve(components.size());
  for (const core::Component& component : components)
  {
    sorted_components.push_back(&component);
  }
  std::sort(sorted_components.begin(), sorted_components.end(),
            [](const core::Component* left, const core::Component* right)
            {
              const core::Confidence left_confidence = core::highest_confidence(*left);
              const core::Confidence right_confidence = core::highest_confidence(*right);
              if (left_confidence != right_confidence)
              {
                return left_confidence > right_confidence;  // High -> Low
              }
              return core::component_identity(*left) < core::component_identity(*right);
            });
  return sorted_components;
}

/// Located components a successfully applied build trace did not touch,
/// identity-sorted independently of the main table's confidence-first order.
/// Root breaks an otherwise-equal identity tie so caller order can never
/// affect the unused card's bytes (rule 3).
std::vector<const core::Component*> unused_components_sorted_by_identity(
    const std::vector<core::Component>& components)
{
  std::vector<const core::Component*> unused_components;
  for (const core::Component& component : components)
  {
    if (!component.root.empty() && !component.used_in_build)
    {
      unused_components.push_back(&component);
    }
  }
  std::sort(unused_components.begin(), unused_components.end(),
            [](const core::Component* left, const core::Component* right)
            {
              const std::string left_identity = core::component_identity(*left);
              const std::string right_identity = core::component_identity(*right);
              if (left_identity != right_identity)
              {
                return left_identity < right_identity;
              }
              const std::string left_root = left->root.generic_string();
              const std::string right_root = right->root.generic_string();
              if (left_root != right_root)
              {
                return left_root < right_root;
              }
              return left->name < right->name;
            });
  return unused_components;
}

/// Merge duplicate purls, sort ids within each entry, deduplicate, and order
/// entries by purl: caller ordering cannot change the report bytes (rule 3).
/// The worst (first, since advisories are worst-first) severity of a report
/// entry, or an unscored default when it has no advisories.
core::CvssScore worst_severity_of(const ReportVulnerability& vulnerability)
{
  if (vulnerability.advisories.empty())
  {
    return {};
  }
  return vulnerability.advisories.front().severity;
}

/// Merge duplicate purls, deduplicate advisories by id (keeping the most
/// severe when an id somehow arrives twice), order advisories worst-first, and
/// order the components themselves worst-first (then by purl): so the report
/// leads with the highest-severity finding and caller ordering cannot change
/// the bytes (rule 3).
std::vector<ReportVulnerability> normalized_vulnerabilities(
    const std::vector<ReportVulnerability>& vulnerabilities)
{
  // ordered map => deterministic; inner map dedupes ids and keeps the whole
  // best-severity ScoredAdvisory, not just its score, so a field added to
  // ScoredAdvisory later (cve_aliases) survives this rebuild without a
  // second change here.
  std::map<std::string, std::map<std::string, core::ScoredAdvisory>> advisories_by_id_by_purl;
  // This function REBUILDS each entry, so anything not carried across here
  // is silently dropped before rendering. A merged purl keeps the STRONGEST
  // source behind it: if OSV matched the same purl exactly, the row is backed
  // by an exact match and must be neither discounted nor cited to NVD: the
  // same "stronger evidence wins" rule `vuln::merge_outcomes` sorts by.
  std::map<std::string, FindingSource> source_by_purl;
  for (const ReportVulnerability& vulnerability : vulnerabilities)
  {
    std::map<std::string, core::ScoredAdvisory>& by_id =
        advisories_by_id_by_purl[vulnerability.purl];
    const auto source_entry = source_by_purl.find(vulnerability.purl);
    if (source_entry == source_by_purl.end())
    {
      source_by_purl.emplace(vulnerability.purl, vulnerability.source);
    }
    else if (is_high_confidence_source(vulnerability.source))
    {
      source_entry->second = vulnerability.source;
    }
    for (const core::ScoredAdvisory& advisory : vulnerability.advisories)
    {
      const auto existing = by_id.find(advisory.id);
      if (existing == by_id.end() || core::more_severe(advisory, existing->second))
      {
        by_id[advisory.id] = advisory;
      }
    }
  }

  std::vector<ReportVulnerability> normalized;
  normalized.reserve(advisories_by_id_by_purl.size());
  for (const auto& [purl, by_id] : advisories_by_id_by_purl)
  {
    ReportVulnerability entry;
    entry.purl = purl;
    if (const auto source_entry = source_by_purl.find(purl); source_entry != source_by_purl.end())
    {
      entry.source = source_entry->second;
    }
    entry.advisories.reserve(by_id.size());
    for (const auto& [advisory_id, advisory] : by_id)
    {
      entry.advisories.push_back(advisory);
    }
    std::sort(entry.advisories.begin(), entry.advisories.end(), core::more_severe);
    normalized.push_back(std::move(entry));
  }

  // Worst-severity component first; purl breaks ties for a total, stable order.
  std::sort(normalized.begin(), normalized.end(),
            [](const ReportVulnerability& left, const ReportVulnerability& right)
            {
              const core::CvssScore left_worst = worst_severity_of(left);
              const core::CvssScore right_worst = worst_severity_of(right);
              if (left_worst.has_score != right_worst.has_score)
              {
                return left_worst.has_score;
              }
              if (left_worst.has_score && left_worst.score != right_worst.score)
              {
                return left_worst.score > right_worst.score;
              }
              return left.purl < right.purl;
            });
  return normalized;
}

/// `<title>` subject: the product when named, the scanned root
/// otherwise; degrades to just "<tool> report" when both are empty.
std::string report_title(const ReportContext& context)
{
  const std::string& subject = context.release_meta.product_id.empty()
                                   ? context.scanned_root
                                   : context.release_meta.product_id;
  if (subject.empty())
  {
    return context.tool.name + " report";
  }
  return context.tool.name + " report: " + subject;
}

/// A validated accent color overrides both themes' `--accent`/`--link`; a
/// later `:root` rule wins on source order, so this recolors dark mode too.
/// Emitted only when the color passed `is_valid_accent_color`, so nothing
/// unvalidated ever reaches the stylesheet.
void append_accent_override(std::string& document, const std::string& accent_color)
{
  if (accent_color.empty())
  {
    return;
  }
  document += "<style>:root{--accent:";
  document += accent_color;
  document += ";--link:";
  document += accent_color;
  document += ";}</style>\n";
}

void append_header(std::string& document, const ReportContext& context,
                   const std::string& generated_timestamp)
{
  // Brand line: the company name when supplied, otherwise the tool's own name.
  const std::string& brand_name =
      context.branding.company_name.empty() ? context.tool.name : context.branding.company_name;

  document += "  <header class=\"page\">\n    <div class=\"header-band\">\n";
  if (!context.branding.logo_data_uri.empty())
  {
    // The data URI carries only a vetted MIME plus base64 chars; alt text is
    // escaped like any other dynamic value.
    document += "      <img class=\"logo\" src=\"";
    document += context.branding.logo_data_uri;
    document += "\" alt=\"";
    document += escape_html(brand_name);
    document += "\">\n";
  }
  document += "      <div class=\"header-text\">\n        <p class=\"brand\">";
  document += escape_html(brand_name);
  document += "</p>\n        <h1>Software bill of materials report</h1>\n";
  if (!context.release_meta.product_id.empty())
  {
    document += "        <p class=\"product\">";
    document += escape_html(context.release_meta.product_id);
    if (!context.release_meta.version.empty())
    {
      document += ' ';
      document += escape_html(context.release_meta.version);
    }
    document += "</p>\n";
  }
  document += "        <p class=\"meta\">";
  if (!context.scanned_root.empty())
  {
    document += "scanned <code>";
    document += escape_html(context.scanned_root);
    document += "</code> · ";
  }
  document += "generated <time datetime=\"";
  document += escape_html(generated_timestamp);
  document += "\">";
  document += escape_html(generated_timestamp);
  document += "</time> · ";
  document += escape_html(context.tool.name);
  document += ' ';
  document += escape_html(context.tool.version);
  document += "</p>\n      </div>\n    </div>\n  </header>\n";
}

/// The report leads with one risk-posture line so a reader sees the verdict
/// before the detail tiles: green (clean), red (findings), or amber (not
/// checked). The amber path keeps the OSV matcher's honesty rule: nothing checked is never
/// shown as a clean result.
void append_posture(std::string& document, const ReportContext& context,
                    std::size_t affected_component_count, std::size_t advisory_total,
                    const core::CvssScore& worst_severity, bool every_finding_is_low_confidence)
{
  if (!context.vulnerability_check_enabled)
  {
    if (context.vulnerability_check_applicable)
    {
      document +=
          "    <div class=\"posture posture-warn\">Vulnerabilities were not checked for this scan "
          "(<code>--no-vuln</code>). This report is not evidence of absence.</div>\n";
    }
    else
    {
      document +=
          "    <div class=\"posture posture-warn\">Vulnerabilities were not checked. "
          "<code>bomwerk trim</code> evaluates build usage and does not run vulnerability "
          "matching. This report is not evidence of absence.</div>\n";
    }
    return;
  }
  if (affected_component_count == 0)
  {
    document +=
        "    <div class=\"posture posture-good\">No known vulnerabilities in the checked "
        "components.</div>\n";
    return;
  }
  document += "    <div class=\"posture posture-bad\">";
  document += std::to_string(affected_component_count);
  document +=
      affected_component_count == 1 ? " component affected by " : " components affected by ";
  document += std::to_string(advisory_total);
  document += advisory_total == 1 ? " advisory." : " advisories.";
  // Lead with the worst score when any advisory was scored: the single number
  // a reader triages on. Silent when nothing scored (never a misleading 0).
  if (worst_severity.has_score)
  {
    char worst_text[48];
    std::snprintf(worst_text, sizeof(worst_text), " Highest severity %.1f (%s).",
                  worst_severity.score, core::to_string(worst_severity.rating));
    document += worst_text;
  }
  // The posture line is the loudest element on the page. When EVERY
  // finding behind it came from a wildcard-vendor CPE match, saying so here is
  // the difference between a verdict and an overstatement: the same rule that
  // stops `--no-vuln` showing a reassuring zero, applied in the other
  // direction. Silent when even one finding is a purl-exact match, so a real
  // OSV hit is never softened by weaker company.
  //
  // Kept to one clause on purpose: this is a bold single-line verdict, not a
  // place to explain. The "why" belongs to the notice in the Vulnerabilities
  // section, which spells out the wildcard vendor in full.
  if (every_finding_is_low_confidence)
  {
    document += " All from CPE matches. Treat as leads, not confirmed.";
  }
  document += "</div>\n";
}

/// One summary tile. `tone` is a CSS class ("", "good", "warn", "bad");
/// `value_text` must already be escaped or static: it is emitted verbatim.
void append_metric_tile(std::string& document, std::string_view tone, const std::string& value_text,
                        std::string_view label_text)
{
  document += "      <div class=\"metric";
  if (!tone.empty())
  {
    document += ' ';
    document += tone;
  }
  document += "\"><span class=\"metric-value\">";
  document += value_text;
  document += "</span><span class=\"metric-label\">";
  document += label_text;
  document += "</span></div>\n";
}

void append_summary_section(std::string& document, const ReportContext& context,
                            std::size_t component_count, std::size_t affected_component_count,
                            std::size_t advisory_total, std::size_t unmatched_coverage_count,
                            const BuildUsageSummary& build_usage_summary)
{
  document += "    <section class=\"summary\" aria-label=\"Summary\">\n";
  if (context.scan_file_count_available)
  {
    append_metric_tile(document, "", std::to_string(context.scanned_file_count), "files scanned");
  }
  else
  {
    append_metric_tile(document, "warn", ": ", "files scanned (not recorded)");
  }
  append_metric_tile(document, "", std::to_string(component_count), "components");
  if (!context.build_trace_applied)
  {
    append_metric_tile(document, "warn", ": ", "unused (no build trace)");
  }
  else if (build_usage_summary.judged == 0)
  {
    append_metric_tile(document, "warn", ": ", "unused (nothing locatable)");
  }
  else
  {
    const std::string unused_label =
        "unused of " + std::to_string(build_usage_summary.judged) + " located";
    append_metric_tile(document, build_usage_summary.unused > 0 ? "warn" : "good",
                       std::to_string(build_usage_summary.unused), unused_label);
  }
  // Identifier quality is a fact about the SBOM, not about whether OSV
  // ran, so this tile is unconditional: unlike the vuln-gated block below,
  // it does not disappear under `--no-vuln`.
  append_metric_tile(document, unmatched_coverage_count > 0 ? "warn" : "",
                     std::to_string(unmatched_coverage_count), "unmatched (coverage)");
  if (context.vulnerability_check_enabled)
  {
    append_metric_tile(document, affected_component_count > 0 ? "bad" : "good",
                       std::to_string(affected_component_count), "vulnerable components");
    append_metric_tile(document, advisory_total > 0 ? "bad" : "good",
                       std::to_string(advisory_total), "advisories");
    // The uncovered set splits in two. Only what the CPE fallback did not
    // reach may still be called "not checked": reporting the whole set that
    // way once part of it was checked would understate coverage exactly as
    // badly as the reverse would overstate it.
    const std::size_t uncovered_count = context.components_without_osv_coverage_purls.size();
    const std::size_t cpe_checked_count =
        std::min(context.components_checked_via_cpe_fallback_purls.size(), uncovered_count);
    const std::size_t not_checked_count = uncovered_count - cpe_checked_count;
    // The label follows the split too. "no OSV coverage (not checked)" names
    // two facts at once, which is only true while they coincide: once the CPE
    // fallback checks part of the uncovered set, a tile reading 0 under a "no
    // OSV coverage" label contradicts the components still listed as uncovered
    // in the coverage card. So when the fallback ran, this tile counts exactly
    // one thing: what stayed unchecked: and the tile beside it counts the
    // rest. Without the fallback the wording is untouched, byte for byte.
    append_metric_tile(document, not_checked_count > 0 ? "warn" : "",
                       std::to_string(not_checked_count),
                       cpe_checked_count > 0 ? "not checked" : "no OSV coverage (not checked)");
    if (cpe_checked_count > 0)
    {
      append_metric_tile(document, "warn", std::to_string(cpe_checked_count),
                         "checked via CPE (low confidence)");
    }
  }
  else
  {
    // Never a reassuring zero when nothing was checked (--no-vuln).
    append_metric_tile(document, "warn", ": ", "vulnerable components (not checked)");
    append_metric_tile(document, "warn", ": ", "advisories (not checked)");
  }
  append_metric_tile(document, context.warnings.empty() ? "" : "warn",
                     std::to_string(context.warnings.size()), "warnings");
  document += "    </section>\n";
}

/// Git short-SHA length (the width GitHub abbreviates commit ids to).
constexpr std::size_t kShortCommitLength = 10;

/// The version cell. A commit-pinned dependency's "version" is a 40/64-hex
/// object id (what the submodule and CMake-FetchContent producers emit): the
/// full hash is unreadable in a table, so it is shown abbreviated with a
/// "commit" tag and the full id on hover, distinguishing a pinned commit from
/// a semver release at a glance.
void append_version_cell(std::string& document, const std::string& version)
{
  if (version.empty())
  {
    document += ": ";
    return;
  }
  if (core::is_hex_object_id(version))
  {
    document += "<code title=\"";
    document += escape_html(version);
    document += "\">";
    document += escape_html(version.substr(0, kShortCommitLength));
    document += "</code> <span class=\"muted tag\">commit</span>";
    return;
  }
  document += escape_html(version);
}

/// What a row says about the vulnerability run's reach over its component.
/// A row carries at most ONE of these: the states are exclusive by
/// construction, so a component can never be tagged both unchecked and checked.
enum class OsvCoverageBadge
{
  None,          ///< OSV can query it (or `--no-vuln`): no coverage badge at all
  NotChecked,    ///< no OSV ecosystem for the type, and nothing else reached it
  CheckedViaCpe  ///< the CPE fallback: no OSV ecosystem, but NVD answered a CPE match for it
};

void append_component_row(std::string& document, const core::Component& component,
                          std::size_t advisory_count, OsvCoverageBadge coverage_badge,
                          bool build_trace_applied)
{
  document += "            <tr>\n              <td>";
  document += escape_html(component.name);
  if (advisory_count > 0)
  {
    document += " <span class=\"badge bad\">";
    document += advisory_count_label(advisory_count);
    document += "</span>";
  }
  if (build_trace_applied && !component.root.empty() && !component.used_in_build)
  {
    document +=
        " <span class=\"badge warn\" title=\"Located component with no compile, link, or "
        "include-path signal in the applied build trace\">UNUSED</span>";
  }
  // Both variants use `badge low`, the same weight as every other advisory
  // badge in this table: a coverage caveat is context, never an alarm, and a
  // lower-confidence result must not out-shout a confirmed one.
  if (coverage_badge == OsvCoverageBadge::NotChecked)
  {
    // Names the "N components have no OSV coverage" summary at the row level,
    // so a reader sees exactly which components were structurally uncheckable.
    document +=
        " <span class=\"badge low\" title=\"No OSV ecosystem for this package type\">"
        "no OSV coverage</span>";
  }
  else if (coverage_badge == OsvCoverageBadge::CheckedViaCpe)
  {
    // Still no OSV ecosystem, but NVD answered a wildcard-vendor CPE
    // query: checked, and honestly labeled as the weaker match it is.
    document +=
        " <span class=\"badge low\" title=\"No OSV ecosystem for this package type; matched "
        "against NVD by CPE with a wildcard vendor, which may also match a different vendor's "
        "product of the same name\">checked via CPE</span>";
  }
  // Match coverage is a fact about the SBOM's identifiers, not about
  // whether OSV ran, so this badge is computed directly from the component
  // (core::classify_match_coverage) rather than from `context`: it appears
  // even under `--no-vuln`, unlike the `osv_coverage_absent` badge above.
  // A coverage badge above is always a subset of "not Matched" (either variant
  // is only ever set for the UnmappedPurlType class, under --vuln), so the two
  // conditions can only ever BOTH fire for the exact same class on the exact
  // same row: skip this one then rather than showing two badges that say
  // the same thing.
  if (const core::MatchCoverage coverage = core::classify_match_coverage(component);
      coverage_badge == OsvCoverageBadge::None && coverage != core::MatchCoverage::Matched)
  {
    document += " <span class=\"badge low\" title=\"";
    document += escape_html(core::match_coverage_reason(coverage));
    document += "\">";
    document += core::to_string(coverage);
    document += "</span>";
  }
  // Column order (identity and trust first): Name, Confidence, Version, PURL,
  // Supplier, License: identity and trust first, provenance detail after.
  document += "</td>\n              <td><span class=\"badge ";
  const char* confidence_label = core::to_string(core::highest_confidence(component));
  document += confidence_label;
  document += "\">";
  document += confidence_label;
  document += "</span></td>\n              <td>";
  append_version_cell(document, component.version);
  document += "</td>\n              <td><code>";
  document += cell_text_or_dash(component.purl);
  document += "</code></td>\n              <td>";
  document += cell_text_or_dash(component.supplier);
  document += "</td>\n              <td>";
  document += cell_text_or_dash(component.license);
  document += "</td>\n            </tr>\n";
}

void append_components_section(std::string& document,
                               const std::vector<const core::Component*>& sorted_components,
                               const std::map<std::string, std::size_t>& advisory_count_by_purl,
                               const std::set<std::string>& uncovered_purls,
                               const std::set<std::string>& cpe_checked_purls,
                               bool build_trace_applied)
{
  document +=
      "    <details class=\"card\" open>\n      <summary><h2>Components</h2> "
      "<span class=\"count\">";
  document += std::to_string(sorted_components.size());
  document += "</span></summary>\n      <div class=\"card-body\">\n";
  if (sorted_components.empty())
  {
    document += "        <p class=\"empty\">No components were found.</p>\n";
  }
  else
  {
    document +=
        "        <div class=\"table-wrap\">\n          <table>\n            <thead>\n"
        "              <tr><th>Name</th><th>Confidence</th><th>Version</th><th>PURL</th>"
        "<th>Supplier</th><th>License</th></tr>\n            </thead>\n            <tbody>\n";
    for (const core::Component* component : sorted_components)
    {
      std::size_t advisory_count = 0;
      const auto advisory_entry = advisory_count_by_purl.find(component->purl);
      if (advisory_entry != advisory_count_by_purl.end())
      {
        advisory_count = advisory_entry->second;
      }
      // The CPE-checked set is a subset of the uncovered set, so testing it
      // second turns the two lists into one exclusive badge state per row.
      OsvCoverageBadge coverage_badge = OsvCoverageBadge::None;
      if (uncovered_purls.count(component->purl) > 0)
      {
        coverage_badge = cpe_checked_purls.count(component->purl) > 0
                             ? OsvCoverageBadge::CheckedViaCpe
                             : OsvCoverageBadge::NotChecked;
      }
      append_component_row(document, *component, advisory_count, coverage_badge,
                           build_trace_applied);
    }
    document += "            </tbody>\n          </table>\n        </div>\n";
  }
  document += "      </div>\n    </details>\n";
}

/// trim's evidence-focused card: only located components judged unused by an
/// applied trace. Name, purl and root are enough to find and remove the dead
/// dependency without repeating the main table's inventory metadata.
void append_unused_components_section(std::string& document,
                                      const std::vector<const core::Component*>& unused_components)
{
  document +=
      "    <details class=\"card\" open>\n      <summary><h2>Unused components</h2> "
      "<span class=\"count\">";
  document += std::to_string(unused_components.size());
  document +=
      "</span></summary>\n      <div class=\"card-body\">\n"
      "        <p>Located components with no compile, link, or include-path signal in the "
      "applied build trace.</p>\n"
      "        <div class=\"table-wrap\">\n          <table>\n            <thead>\n"
      "              <tr><th>Name</th><th>PURL</th><th>Root</th></tr>\n"
      "            </thead>\n            <tbody>\n";
  for (const core::Component* component : unused_components)
  {
    document += "              <tr>\n                <td>";
    document += escape_html(component->name);
    document += "</td>\n                <td><code>";
    document += cell_text_or_dash(component->purl);
    document += "</code></td>\n                <td><code>";
    document += escape_html(component->root.generic_string());
    document += "</code></td>\n              </tr>\n";
  }
  document += "            </tbody>\n          </table>\n        </div>\n";
  document += "      </div>\n    </details>\n";
}

/// One row of the coverage card's per-class table: name and purl only: the
/// class and reason are already the section heading, and confidence/version/
/// supplier/license belong to the Components table above, not a repeat here.
void append_match_coverage_row(std::string& document, const core::Component& component)
{
  document += "              <tr>\n                <td>";
  document += escape_html(component.name);
  document += "</td>\n                <td><code>";
  document += cell_text_or_dash(component.purl);
  document += "</code></td>\n              </tr>\n";
}

/// The "Match coverage" card: turns the industry-wide silent drop
/// (CRANE/Syft/Trivy all drop a component whose purl they cannot map,
/// without saying so) into a visible, honest artifact: the sharpest "why
/// us" demo available. Leads with the ticket's own summary-line shape ("N
/// components, M matchable (X%), K unmatched: reasons below."), then one
/// sub-table per unmatched class with its plain-English reason
/// (`core::match_coverage_reason`) and exactly the components in it.
///
/// Computed directly from `sorted_components` via
/// `core::classify_match_coverage`: a pure function of a component's purl :
/// so unlike the Vulnerabilities section this card is NOT gated on
/// `context.vulnerability_check_enabled`: identifier quality is a fact about
/// the SBOM, not about whether OSV ran, and must survive `--no-vuln`.
void append_match_coverage_section(std::string& document,
                                   const std::vector<const core::Component*>& sorted_components)
{
  // Grouped by class; std::map<MatchCoverage, ...> iterates in the enum's
  // declared (least-to-most-structural) order, and each group keeps the
  // incoming strongest-evidence-first order: both derived, never
  // caller-supplied (rule 3). `Matched` never enters the map.
  std::map<core::MatchCoverage, std::vector<const core::Component*>> unmatched_by_class;
  std::size_t matchable_count = 0;
  for (const core::Component* component : sorted_components)
  {
    const core::MatchCoverage coverage = core::classify_match_coverage(*component);
    if (coverage == core::MatchCoverage::Matched)
    {
      ++matchable_count;
    }
    else
    {
      unmatched_by_class[coverage].push_back(component);
    }
  }
  const std::size_t total_count = sorted_components.size();
  const std::size_t unmatched_count = total_count - matchable_count;

  document +=
      "    <details class=\"card\" open>\n      <summary><h2>Match coverage</h2> "
      "<span class=\"count\">";
  document += std::to_string(unmatched_count);
  document += "</span></summary>\n      <div class=\"card-body\">\n";

  if (total_count == 0)
  {
    document +=
        "        <p class=\"empty\">No components were found.</p>\n      </div>\n    </details>\n";
    return;
  }

  document += "        <p>";
  document += std::to_string(total_count);
  document += total_count == 1 ? " component, " : " components, ";
  document += std::to_string(matchable_count);
  document += " matchable (";
  constexpr std::size_t kPercentageTextBytes = 16;  // "100.0" plus margin, never truncates
  char percentage_text[kPercentageTextBytes];
  std::snprintf(percentage_text, sizeof(percentage_text), "%.1f",
                (100.0 * static_cast<double>(matchable_count)) / static_cast<double>(total_count));
  document += percentage_text;
  document += "%), ";
  document += std::to_string(unmatched_count);
  document += " unmatched: reasons below.</p>\n";

  if (unmatched_count == 0)
  {
    document +=
        "        <p class=\"empty\">Every component matched.</p>\n      </div>\n    </details>\n";
    return;
  }

  for (const auto& [coverage, class_components] : unmatched_by_class)
  {
    document += "        <p><strong>";
    document += std::to_string(class_components.size());
    document += "</strong> <code>";
    document += core::to_string(coverage);
    document += "</code>: ";
    document += escape_html(core::match_coverage_reason(coverage));
    document += "</p>\n";
    document +=
        "        <div class=\"table-wrap\">\n          <table>\n            <thead>\n"
        "              <tr><th>Name</th><th>PURL</th></tr>\n            </thead>\n"
        "            <tbody>\n";
    for (const core::Component* component : class_components)
    {
      append_match_coverage_row(document, *component);
    }
    document += "            </tbody>\n          </table>\n        </div>\n";
  }
  document += "      </div>\n    </details>\n";
}

/// The CSS modifier for a severity rating ("sev-critical" … "sev-unknown").
const char* severity_badge_class(core::SeverityRating rating)
{
  switch (rating)
  {
    case core::SeverityRating::Critical:
      return "sev-critical";
    case core::SeverityRating::High:
      return "sev-high";
    case core::SeverityRating::Medium:
      return "sev-medium";
    case core::SeverityRating::Low:
      return "sev-low";
    case core::SeverityRating::None:
      return "sev-none";
    case core::SeverityRating::Unknown:
      return "sev-unknown";
  }
  return "sev-unknown";
}

/// Shown for an advisory whose CVSS severity could not be resolved when the
/// company config does not override `unknown_severity_label`.
constexpr std::string_view kDefaultNoInfoLabel = "No info";

/// A severity badge: "9.8 Critical" when scored, otherwise `no_info_label`
/// (italic, never a reassuring 0): the advisory is unscored, not harmless.
void append_severity_badge(std::string& document, const core::CvssScore& severity,
                           std::string_view no_info_label)
{
  document += "<span class=\"badge ";
  document += severity_badge_class(severity.rating);
  document += "\">";
  if (severity.has_score)
  {
    char score_text[16];
    std::snprintf(score_text, sizeof(score_text), "%.1f ", severity.score);
    document += score_text;
    document += core::to_string(severity.rating);
  }
  else
  {
    document += escape_html(no_info_label);
  }
  document += "</span>";
}

/// One advisory: its id (linked to the database that produced it, in a new tab,
/// when the id matches a strict shape: plain escaped text otherwise) followed
/// by its severity badge.
void append_advisory(std::string& document, const core::ScoredAdvisory& advisory,
                     std::string_view no_info_label, FindingSource source)
{
  document += "<span class=\"advisory\">";
  if (is_linkable_advisory_id(advisory.id))
  {
    // Opens the advisory in a new tab; rel=noopener keeps that tab from
    // reaching back into this document (window.opener) and noreferrer
    // withholds the report's local file path as a Referer.
    document += "<a href=\"";
    document += advisory_url_prefix_for(source);
    document += escape_html(advisory.id);
    document += "\" target=\"_blank\" rel=\"noopener noreferrer\">";
    document += escape_html(advisory.id);
    document += "</a>";
  }
  else
  {
    document += escape_html(advisory.id);
  }
  document += ' ';
  append_severity_badge(document, advisory.severity, no_info_label);
  document += "</span>";
}

void append_vulnerabilities_section(std::string& document, const ReportContext& context,
                                    const std::vector<ReportVulnerability>& vulnerabilities)
{
  const std::string_view no_info_label =
      context.branding.unknown_severity_label.empty()
          ? kDefaultNoInfoLabel
          : std::string_view(context.branding.unknown_severity_label);
  document +=
      "    <details class=\"card\" open>\n      <summary><h2>Vulnerabilities</h2> "
      "<span class=\"count\">";
  document += context.vulnerability_check_enabled ? std::to_string(vulnerabilities.size())
                                                  : std::string("not checked");
  document += "</span></summary>\n      <div class=\"card-body\">\n";
  if (!context.vulnerability_check_enabled)
  {
    if (context.vulnerability_check_applicable)
    {
      document +=
          "        <p class=\"notice\">Not checked. Vulnerability matching was disabled for this "
          "scan (<code>--no-vuln</code>). Absence of findings here is not evidence of "
          "absence.</p>\n      </div>\n    </details>\n";
    }
    else
    {
      document +=
          "        <p class=\"notice\">Not checked. <code>bomwerk trim</code> evaluates build "
          "usage from an existing SBOM and does not run vulnerability matching. Absence of "
          "findings here is not evidence of absence.</p>\n      </div>\n    </details>\n";
    }
    return;
  }
  if (context.vulnerability_check_offline)
  {
    document +=
        "        <p class=\"muted\">Matched against the local cache only "
        "(<code>--offline</code>): feed data may be stale.</p>\n";
  }
  if (vulnerabilities.empty())
  {
    document +=
        "        <p class=\"empty\">No known vulnerabilities were found for the checked "
        "components.</p>\n";
  }
  else
  {
    // Sorted worst-first by normalized_vulnerabilities; the Severity column
    // shows each component's worst score so the ordering is legible at a glance.
    document +=
        "        <div class=\"table-wrap\">\n          <table>\n            <thead>\n"
        "              <tr><th>Component</th><th>Worst severity</th><th>Advisories</th></tr>\n"
        "            </thead>\n            <tbody>\n";
    for (const ReportVulnerability& vulnerability : vulnerabilities)
    {
      document += "              <tr>\n                <td><code>";
      document += escape_html(vulnerability.purl);
      document += "</code>";
      if (!is_high_confidence_source(vulnerability.source))
      {
        // `badge low` on purpose: deliberately not `bad` (that weight
        // belongs to advisory counts) and not a `sev-*` class (those mean a
        // CVSS band). A wildcard-vendor guess must read quieter than the
        // purl-exact OSV rows it sits beside, never louder.
        document +=
            " <span class=\"badge low\" title=\"Matched against NVD by CPE with a wildcard "
            "vendor because no OSV ecosystem covers this package type. A different vendor's "
            "product of the same name can match too.\">CPE match, low confidence</span>";
      }
      document += "</td>\n                <td>";
      append_severity_badge(document, worst_severity_of(vulnerability), no_info_label);
      document += "</td>\n                <td>";
      for (const core::ScoredAdvisory& advisory : vulnerability.advisories)
      {
        append_advisory(document, advisory, no_info_label, vulnerability.source);
      }
      document += "</td>\n              </tr>\n";
    }
    document += "            </tbody>\n          </table>\n        </div>\n";
  }
  // Counts derive from the tagged-purl lists themselves, so these numbers and
  // the badges in the component table can never disagree. The CPE fallback splits the
  // uncovered set the same way the tiles above do: what the CPE fallback
  // reached is reported as checked-but-weaker, and only the remainder as not
  // checked at all.
  const std::size_t uncovered_count = context.components_without_osv_coverage_purls.size();
  const std::size_t cpe_checked_count =
      std::min(context.components_checked_via_cpe_fallback_purls.size(), uncovered_count);
  if (cpe_checked_count > 0)
  {
    document += "        <p class=\"notice\">";
    document += std::to_string(cpe_checked_count);
    document +=
        " component(s) have no OSV ecosystem coverage (Conan, vcpkg, generic) and were matched "
        "against NVD by CPE instead. Each is tagged <span class=\"badge low\">checked via "
        "CPE</span> in the component table above. That match uses a wildcard vendor, so a "
        "different vendor's product of the same name can match too: treat these findings as "
        "leads to confirm, not as confirmed.</p>\n";
  }
  if (uncovered_count > cpe_checked_count)
  {
    document += "        <p class=\"notice\">";
    document += std::to_string(uncovered_count - cpe_checked_count);
    document +=
        " component(s) have no OSV ecosystem coverage (Conan, vcpkg, generic) and were not "
        "checked. Each is tagged <span class=\"badge low\">no OSV coverage</span> in the "
        "component table above. Absence here is not evidence of absence.</p>\n";
  }
  document += "      </div>\n    </details>\n";
}

void append_warnings_section(std::string& document, const std::vector<core::Warning>& warnings)
{
  // Collapsed by default regardless of count: warnings are often numerous and
  // noisy (parser diagnostics), and would otherwise dominate the page: a
  // reader opens it deliberately rather than being confronted with it first.
  document +=
      "    <details class=\"card\">\n      <summary><h2>Warnings</h2> <span class=\"count\">";
  document += std::to_string(warnings.size());
  document += "</span></summary>\n      <div class=\"card-body\">\n";
  if (warnings.empty())
  {
    document += "        <p class=\"empty\">None. The scan completed without warnings.</p>\n";
  }
  else
  {
    document += "        <ol class=\"warnings\">\n";
    for (const core::Warning& warning : warnings)
    {
      document += "          <li>";
      document += escape_html(std::string(core::code_info_of(warning).id) + ": " + warning.message);
      document += "</li>\n";
    }
    document += "        </ol>\n";
  }
  document += "      </div>\n    </details>\n";
}

void append_footer(std::string& document, const ReportContext& context,
                   bool any_cpe_fallback_finding)
{
  document += "  <footer class=\"page\">\n";
  if (!context.branding.footer_note.empty())
  {
    document += "    <p class=\"footer-note\">";
    document += escape_html(context.branding.footer_note);
    document += "</p>\n";
  }
  document += "    <p>";
  if (!context.branding.company_name.empty())
  {
    document += escape_html(context.branding.company_name);
    if (!context.branding.contact.empty())
    {
      document += " · ";
      document += escape_html(context.branding.contact);
    }
    document += " · ";
  }
  document += "generated by ";
  document += escape_html(context.tool.name);
  document += ' ';
  document += escape_html(context.tool.version);
  document += ": build-accurate SBOMs &amp; EU Cyber Resilience Act evidence. ";
  // Only mention NVD when this report actually contains a CPE-matched
  // finding: a plain OSV-only report (the overwhelming majority, and every
  // report ever produced before `--cpe-fallback` existed) must stay
  // byte-identical to what it said before this feature landed.
  document += any_cpe_fallback_finding
                  ? "Each advisory links to the database it was matched against: osv.dev, or "
                    "nvd.nist.gov for CPE-matched findings."
                  : "Advisory links resolve at osv.dev.";
  document += "</p>\n  </footer>\n";
}

}  // namespace

BuildUsageSummary summarize_build_usage(const std::vector<core::Component>& components)
{
  BuildUsageSummary summary;
  for (const core::Component& component : components)
  {
    if (component.root.empty())
    {
      ++summary.not_judgeable;
    }
    else if (component.used_in_build)
    {
      ++summary.judged;
      ++summary.used;
    }
    else
    {
      ++summary.judged;
      ++summary.unused;
    }
  }
  return summary;
}

core::Result<ReportBranding> load_report_branding(const std::filesystem::path& config_path)
{
  core::Result<ReportBranding> result;
  const std::string label = config_path.filename().generic_string();

  const core::BoundedFileRead file_read =
      core::read_file_bounded(config_path, core::json_utils::kMaxFileBytes);
  if (!file_read.readable)
  {
    result.warn(core::WarningCode::kUnreadableFile,
                "report-config: unreadable file: " + config_path.generic_string());
    return result;
  }
  if (file_read.truncated)
  {
    result.warn(core::WarningCode::kFileSizeLimitExceeded,
                "report-config: file exceeds size limit, ignored: " + label);
    return result;
  }

  const std::string_view json_bytes = core::json_utils::without_utf8_bom(file_read.bytes);
  if (core::json_utils::exceeds_json_nesting_depth(json_bytes,
                                                   core::json_utils::kMaxJsonNestingDepth))
  {
    result.warn(core::WarningCode::kJsonNestingDepthExceeded,
                "report-config: " + label + ": JSON nesting exceeds depth limit, ignored");
    return result;
  }
  const nlohmann::json parsed =
      nlohmann::json::parse(json_bytes, nullptr, /*allow_exceptions=*/false);
  if (parsed.is_discarded() || !parsed.is_object())
  {
    result.warn(core::WarningCode::kInvalidJson,
                "report-config: " + label + ": not a valid JSON object, ignored");
    return result;
  }

  // A string field is taken when present and string-typed; a wrong type warns
  // rather than silently vanishing, so a typo in the config is visible. An
  // over-long value is truncated to `max_bytes` (with a warning) so a stray
  // giant string cannot break the header/footer layout.
  const auto take_string_field = [&](const char* key, std::string& target, std::size_t max_bytes)
  {
    const auto field = parsed.find(key);
    if (field == parsed.end())
    {
      return;
    }
    if (!field->is_string())
    {
      result.warn(
          core::WarningCode::kReportConfigFieldInvalid,
          std::string("report-config: ") + label + ": '" + key + "' is not a string, ignored");
      return;
    }
    target = field->get<std::string>();
    if (truncate_to_bytes(target, max_bytes))
    {
      result.warn(core::WarningCode::kReportConfigFieldInvalid,
                  std::string("report-config: ") + label + ": '" + key + "' exceeds " +
                      std::to_string(max_bytes) + " bytes, truncated");
    }
  };
  take_string_field("company_name", result.value.company_name, kMaxCompanyNameBytes);
  take_string_field("contact", result.value.contact, kMaxContactBytes);
  take_string_field("footer_note", result.value.footer_note, kMaxFooterNoteBytes);
  take_string_field("unknown_severity_label", result.value.unknown_severity_label,
                    kMaxSeverityLabelBytes);

  const auto accent_field = parsed.find("accent_color");
  if (accent_field != parsed.end())
  {
    if (accent_field->is_string() && is_valid_accent_color(accent_field->get<std::string>()))
    {
      result.value.accent_color = accent_field->get<std::string>();
    }
    else
    {
      result.warn(core::WarningCode::kReportConfigFieldInvalid,
                  "report-config: " + label + ": 'accent_color' must be #rgb or #rrggbb, ignored");
    }
  }

  const auto logo_field = parsed.find("logo_path");
  if (logo_field != parsed.end())
  {
    if (!logo_field->is_string())
    {
      result.warn(core::WarningCode::kReportConfigFieldInvalid,
                  "report-config: " + label + ": 'logo_path' is not a string, ignored");
    }
    else
    {
      // Relative logo paths resolve against the config file's own directory,
      // so a config is portable with its assets.
      std::filesystem::path logo_path = logo_field->get<std::string>();
      if (logo_path.is_relative())
      {
        logo_path = config_path.parent_path() / logo_path;
      }
      const std::string extension_lower = core::to_lower_ascii(logo_path.extension().string());
      const std::string_view mime = logo_mime_for_extension(extension_lower);
      if (mime.empty())
      {
        result.warn(core::WarningCode::kReportConfigFieldInvalid,
                    "report-config: " + label + ": unsupported logo type '" + extension_lower +
                        "' (want png/jpg/gif/svg/webp), ignored");
      }
      else
      {
        const core::BoundedFileRead logo_read = core::read_file_bounded(logo_path, kMaxLogoBytes);
        if (!logo_read.readable)
        {
          result.warn(core::WarningCode::kUnreadableFile,
                      "report-config: unreadable logo: " + logo_path.generic_string());
        }
        else if (logo_read.truncated)
        {
          result.warn(
              core::WarningCode::kFileSizeLimitExceeded,
              "report-config: logo exceeds size limit, ignored: " + logo_path.generic_string());
        }
        else
        {
          result.value.logo_data_uri =
              "data:" + std::string(mime) + ";base64," + core::base64_encode(logo_read.bytes);
        }
      }
    }
  }

  return result;
}

std::string write_html_report(const std::vector<core::Component>& components,
                              const ReportContext& context)
{
  const std::string generated_timestamp = core::current_timestamp_iso8601();
  const std::vector<const core::Component*> sorted_components =
      components_sorted_for_report(components);
  const std::vector<const core::Component*> unused_components =
      unused_components_sorted_by_identity(components);
  const BuildUsageSummary build_usage_summary = summarize_build_usage(components);
  const std::vector<ReportVulnerability> vulnerabilities =
      normalized_vulnerabilities(context.vulnerabilities);

  std::map<std::string, std::size_t> advisory_count_by_purl;
  std::size_t advisory_total = 0;
  core::CvssScore worst_overall_severity;  // Unknown until a scored advisory is seen
  // Qualifies the posture line only when NOTHING behind it is a
  // purl-exact match. Vacuously true for an empty list, which the posture's
  // own zero-findings branch handles before it is ever read.
  bool every_finding_is_low_confidence = true;
  // The footer's database mention is opt-in the other way: vacuously
  // FALSE for an empty (or all-purl-exact) list, so a plain OSV report's
  // footer stays exactly what it said before this feature existed.
  bool any_cpe_fallback_finding = false;
  for (const ReportVulnerability& vulnerability : vulnerabilities)
  {
    advisory_count_by_purl[vulnerability.purl] = vulnerability.advisories.size();
    advisory_total += vulnerability.advisories.size();
    every_finding_is_low_confidence =
        every_finding_is_low_confidence && !is_high_confidence_source(vulnerability.source);
    any_cpe_fallback_finding =
        any_cpe_fallback_finding || !is_high_confidence_source(vulnerability.source);
    const core::CvssScore component_worst = worst_severity_of(vulnerability);
    if (component_worst.has_score &&
        (!worst_overall_severity.has_score || component_worst.score > worst_overall_severity.score))
    {
      worst_overall_severity = component_worst;
    }
  }

  const std::set<std::string> uncovered_purls(context.components_without_osv_coverage_purls.begin(),
                                              context.components_without_osv_coverage_purls.end());
  // A subset of the above: empty unless `--cpe-fallback` ran, which
  // leaves every match coverage surface byte-identical to before.
  const std::set<std::string> cpe_checked_purls(
      context.components_checked_via_cpe_fallback_purls.begin(),
      context.components_checked_via_cpe_fallback_purls.end());
  // Independent of vulnerability_check_enabled: identifier quality is a
  // fact about the SBOM regardless of whether OSV ran this scan.
  const core::MatchCoverageSummary coverage_summary = core::summarize_match_coverage(components);
  const std::size_t unmatched_coverage_count = coverage_summary.total - coverage_summary.matchable;

  std::string document;
  document.reserve(kReservedBaseBytes + components.size() * kReservedBytesPerComponent);
  document += "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
  document += "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n";
  document += "<title>";
  document += escape_html(report_title(context));
  document += "</title>\n<style>";
  document += kStyleSheet;
  document += "</style>\n";
  append_accent_override(document, context.branding.accent_color);
  document += "</head>\n<body>\n";
  append_header(document, context, generated_timestamp);
  document += "  <main>\n";
  append_posture(document, context, vulnerabilities.size(), advisory_total, worst_overall_severity,
                 every_finding_is_low_confidence);
  append_summary_section(document, context, components.size(), vulnerabilities.size(),
                         advisory_total, unmatched_coverage_count, build_usage_summary);
  if (context.build_trace_applied && !unused_components.empty())
  {
    append_unused_components_section(document, unused_components);
  }
  append_components_section(document, sorted_components, advisory_count_by_purl, uncovered_purls,
                            cpe_checked_purls, context.build_trace_applied);
  append_match_coverage_section(document, sorted_components);
  append_vulnerabilities_section(document, context, vulnerabilities);
  append_warnings_section(document, context.warnings);
  document += "  </main>\n";
  append_footer(document, context, any_cpe_fallback_finding);
  document += "</body>\n</html>\n";
  return document;
}

}  // namespace bomwerk::output
