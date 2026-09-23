#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>

#include "core/model.hpp"
#include "core/result.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "output/html.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::CvssScore;
using bomwerk::core::Evidence;
using bomwerk::core::ScoredAdvisory;
using bomwerk::core::SeverityRating;
using bomwerk::core::Source;
using bomwerk::output::BuildUsageSummary;
using bomwerk::output::FindingSource;
using bomwerk::output::load_report_branding;
using bomwerk::output::ReportBranding;
using bomwerk::output::ReportContext;
using bomwerk::output::ReportVulnerability;
using bomwerk::output::summarize_build_usage;
using bomwerk::output::ToolInfo;
using bomwerk::output::write_html_report;
using bomwerk::test::TempTree;

namespace
{

bool contains(const std::string& document, std::string_view needle)
{
  return document.find(needle) != std::string::npos;
}

/// An advisory with no CVSS (unknown severity): the common test shape.
ScoredAdvisory adv(std::string id)
{
  return ScoredAdvisory{std::move(id), CvssScore{}, {}};
}

/// An advisory carrying a CVSS base score + rating.
ScoredAdvisory adv(std::string id, double score, SeverityRating rating)
{
  return ScoredAdvisory{std::move(id), CvssScore{score, rating, true}, {}};
}

Component make_component(std::string name, std::string version, std::string purl,
                         Confidence confidence)
{
  Component component;
  component.name = std::move(name);
  component.version = std::move(version);
  component.purl = std::move(purl);
  component.evidence.push_back(Evidence{Source::Manifest, "test-manifest", confidence});
  return component;
}

ReportContext make_context()
{
  ReportContext context;
  context.tool = ToolInfo{"bomwerk", "0.1.0"};
  context.scanned_root = "/repo";
  context.scanned_file_count = 123;
  return context;
}

}  // namespace

int main()
{
  // Pinned for every case (rule 3): the generated-at timestamp must come from
  // SOURCE_DATE_EPOCH so document bytes are reproducible across the test run.
  // 1700000000 = 2023-11-14T22:13:20Z.
  setenv("SOURCE_DATE_EPOCH", "1700000000", 1);

  // Given a populated scan (components, one vulnerable, a warning, release
  // metadata, uncheckable components), when rendered, then every documented
  // section carries its data and the document is one self-contained HTML file.
  {
    Component zlib = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1", Confidence::High);
    zlib.supplier = "zlib contributors";
    zlib.license = "Zlib";
    Component harfbuzz = make_component("harfbuzz", "8.3.0", "pkg:github/harfbuzz/harfbuzz@8.3.0",
                                        Confidence::Medium);

    ReportContext context = make_context();
    context.release_meta.product_id = "acme-firmware";
    context.release_meta.version = "2.4.1";
    context.vulnerabilities.push_back(ReportVulnerability{
        "pkg:github/harfbuzz/harfbuzz@8.3.0",
        {adv("CVE-2023-25193", 9.8, SeverityRating::Critical), adv("GHSA-1234-5678-9abc")}});
    context.components_without_osv_coverage_purls.push_back("pkg:vcpkg/zlib@1.3.1");
    context.warnings.push_back(
        bomwerk::core::Warning{bomwerk::core::WarningCode::kUnresolvedVariableOrInterpolation,
                               "conanfile.py:12: unresolved f-string interpolation",
                               {},
                               {}});

    const std::string document = write_html_report({zlib, harfbuzz}, context);

    BOMWERK_TEST_CHECK(document.rfind("<!doctype html>", 0) == 0);
    BOMWERK_TEST_CHECK(contains(document, "<meta charset=\"utf-8\">"));
    BOMWERK_TEST_CHECK(contains(document, "<style>"));
    BOMWERK_TEST_CHECK(contains(document, "acme-firmware"));
    BOMWERK_TEST_CHECK(contains(document, "2023-11-14T22:13:20Z"));
    BOMWERK_TEST_CHECK(contains(document, "metric-value\">123<"));  // files-scanned tile
    BOMWERK_TEST_CHECK(contains(document, "zlib contributors"));
    BOMWERK_TEST_CHECK(contains(document, "pkg:vcpkg/zlib@1.3.1"));
    BOMWERK_TEST_CHECK(contains(document, "class=\"badge high\""));
    BOMWERK_TEST_CHECK(contains(document, "class=\"badge medium\""));
    BOMWERK_TEST_CHECK(contains(document, "2 advisories"));  // red badge on the harfbuzz row
    BOMWERK_TEST_CHECK(contains(document, "href=\"https://osv.dev/vulnerability/CVE-2023-25193\""));
    BOMWERK_TEST_CHECK(contains(document, "1 component(s) have no OSV ecosystem coverage"));
    BOMWERK_TEST_CHECK(contains(document, "conanfile.py:12: unresolved f-string interpolation"));
    BOMWERK_TEST_CHECK(contains(document, "</html>"));
    BOMWERK_TEST_CHECK(!contains(document, "<script"));  // no JavaScript anywhere, ever
  }

  // Given hostile component fields (markup in name/version/license), when
  // rendered, then they appear as escaped text and never as live markup.
  {
    Component hostile = make_component("<script>alert(1)</script>", "1.0\"", "pkg:generic/evil@1.0",
                                       Confidence::Low);
    hostile.license = "\"quoted\" & <b>bold</b>";
    const std::string document = write_html_report({hostile}, make_context());
    BOMWERK_TEST_CHECK(!contains(document, "<script"));
    BOMWERK_TEST_CHECK(contains(document, "&lt;script&gt;alert(1)&lt;/script&gt;"));
    BOMWERK_TEST_CHECK(contains(document, "&quot;quoted&quot; &amp; &lt;b&gt;bold&lt;/b&gt;"));
  }

  // Given hostile advisory ids (attribute breakout, javascript: scheme), when
  // rendered, then no link is emitted for them: they degrade to escaped
  // text, still reported but never executable.
  {
    ReportContext context = make_context();
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/evil@1.0",
                            {adv("CVE-2024-1\"><script>x</script>"), adv("javascript:alert(1)")}});
    Component component = make_component("evil", "1.0", "pkg:generic/evil@1.0", Confidence::Low);
    const std::string document = write_html_report({component}, context);
    BOMWERK_TEST_CHECK(!contains(document, "<script"));
    BOMWERK_TEST_CHECK(!contains(document, "href=\"javascript:"));
    BOMWERK_TEST_CHECK(!contains(document, "https://osv.dev/vulnerability/"));  // nothing linkable
    BOMWERK_TEST_CHECK(contains(document, "javascript:alert(1)"));  // reported as plain text
  }

  // Given a C0 control byte in a component name (hostile manifest), when
  // rendered, then the raw byte never reaches the file: it becomes U+FFFD.
  {
    Component control_bytes =
        make_component(std::string("evil\x01name"), "1.0", "pkg:generic/evil@1.0", Confidence::Low);
    const std::string document = write_html_report({control_bytes}, make_context());
    BOMWERK_TEST_CHECK(!contains(document, std::string_view("\x01", 1)));
    BOMWERK_TEST_CHECK(contains(document,
                                "evil\xEF\xBF\xBD"
                                "name"));
  }

  // Given nothing at all (empty scan), when rendered, then the document is
  // still complete and every section shows an explicit empty state.
  {
    const std::string document = write_html_report({}, make_context());
    BOMWERK_TEST_CHECK(document.rfind("<!doctype html>", 0) == 0);
    BOMWERK_TEST_CHECK(contains(document, "No components were found."));
    BOMWERK_TEST_CHECK(contains(document, "No known vulnerabilities were found"));
    BOMWERK_TEST_CHECK(contains(document, "None. The scan completed without warnings."));
    BOMWERK_TEST_CHECK(contains(document, "</html>"));
  }

  // Given vulnerability matching was disabled (--no-vuln), when rendered,
  // then the report says NOT CHECKED and never shows a reassuring zero.
  {
    ReportContext context = make_context();
    context.vulnerability_check_enabled = false;
    const std::string document = write_html_report({}, context);
    BOMWERK_TEST_CHECK(contains(document, "Not checked"));
    BOMWERK_TEST_CHECK(contains(document, "--no-vuln"));
    BOMWERK_TEST_CHECK(!contains(document, "No known vulnerabilities"));
  }

  // Given rooted components but no applied build trace, when rendered,
  // then the cover shows an explicit unknown and neither the unused card nor
  // an UNUSED row badge appears. used_in_build defaults true, and even a false
  // value supplied by a caller is not evidence unless the context says mapping
  // completed.
  {
    Component unproven = make_component("unproven", "1", "pkg:generic/unproven@1", Confidence::Low);
    unproven.root = "third_party/unproven";
    unproven.used_in_build = false;

    const std::string document = write_html_report({unproven}, make_context());
    BOMWERK_TEST_CHECK(contains(
        document, "metric-value\">: </span><span class=\"metric-label\">unused (no build trace)"));
    BOMWERK_TEST_CHECK(!contains(document, "<h2>Unused components</h2>"));
    BOMWERK_TEST_CHECK(!contains(document, ">UNUSED</span>"));
  }

  // Given an applied trace with two unused rooted components, one used
  // rooted component and one rootless component, when rendered, then the pure
  // summary, cover count, dedicated card and main-table badges all agree. The
  // unused card is identity-sorted and its bytes do not depend on caller order.
  {
    Component beta = make_component("beta", "1", "pkg:generic/beta@1", Confidence::Low);
    beta.root = "third_party/beta";
    beta.used_in_build = false;
    Component alpha = make_component("alpha", "1", "pkg:generic/alpha@1", Confidence::Low);
    alpha.root = "third_party/alpha";
    alpha.used_in_build = false;
    Component used = make_component("used", "1", "pkg:generic/used@1", Confidence::High);
    used.root = "third_party/used";
    Component rootless = make_component("rootless", "1", "pkg:npm/rootless@1", Confidence::High);
    rootless.used_in_build = false;

    const BuildUsageSummary summary = summarize_build_usage({beta, rootless, used, alpha});
    BOMWERK_TEST_CHECK(summary.judged == 3);
    BOMWERK_TEST_CHECK(summary.used == 1);
    BOMWERK_TEST_CHECK(summary.unused == 2);
    BOMWERK_TEST_CHECK(summary.not_judgeable == 1);

    ReportContext context = make_context();
    context.build_trace_applied = true;
    const std::string forward = write_html_report({beta, rootless, used, alpha}, context);
    const std::string reversed = write_html_report({alpha, used, rootless, beta}, context);
    BOMWERK_TEST_CHECK(forward == reversed);
    BOMWERK_TEST_CHECK(contains(
        forward, "metric-value\">2</span><span class=\"metric-label\">unused of 3 located"));
    const std::size_t unused_card = forward.find("<h2>Unused components</h2>");
    const std::size_t alpha_in_card = forward.find("pkg:generic/alpha@1", unused_card);
    const std::size_t beta_in_card = forward.find("pkg:generic/beta@1", unused_card);
    const std::size_t components_card = forward.find("<h2>Components</h2>", unused_card);
    BOMWERK_TEST_CHECK(unused_card != std::string::npos);
    BOMWERK_TEST_CHECK(alpha_in_card < beta_in_card && beta_in_card < components_card);
    const std::size_t first_badge = forward.find(">UNUSED</span>");
    const std::size_t second_badge = forward.find(">UNUSED</span>", first_badge + 1);
    BOMWERK_TEST_CHECK(first_badge != std::string::npos && second_badge != std::string::npos);
    BOMWERK_TEST_CHECK(forward.find(">UNUSED</span>", second_badge + 1) == std::string::npos);
  }

  // Given a trace was applied to a lockfile-only SBOM, when rendered,
  // then the cover says nothing was locatable rather than claiming zero unused.
  {
    Component rootless =
        make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0", Confidence::High);
    ReportContext context = make_context();
    context.build_trace_applied = true;
    const std::string document = write_html_report({rootless}, context);
    BOMWERK_TEST_CHECK(contains(
        document,
        "metric-value\">: </span><span class=\"metric-label\">unused (nothing locatable)"));
    BOMWERK_TEST_CHECK(!contains(document, "<h2>Unused components</h2>"));
  }

  // Given a located component and an applied trace that used it, when
  // rendered, then zero unused is a real green result rather than an unknown.
  {
    Component used = make_component("used", "1", "pkg:generic/used@1", Confidence::High);
    used.root = "third_party/used";
    ReportContext context = make_context();
    context.build_trace_applied = true;
    const std::string document = write_html_report({used}, context);
    BOMWERK_TEST_CHECK(contains(document,
                                "class=\"metric good\"><span class=\"metric-value\">0</span><span "
                                "class=\"metric-label\">unused of 1 located"));
  }

  // Given trim renders an existing SBOM, when its scan count and
  // vulnerability pass are unavailable, then both are explicit unknowns and
  // the text does not pretend this was `scan --no-vuln`.
  {
    ReportContext context = make_context();
    context.scan_file_count_available = false;
    context.vulnerability_check_enabled = false;
    context.vulnerability_check_applicable = false;
    const std::string document = write_html_report({}, context);
    BOMWERK_TEST_CHECK(contains(document, "files scanned (not recorded)"));
    BOMWERK_TEST_CHECK(contains(document, "<code>bomwerk trim</code>"));
    BOMWERK_TEST_CHECK(!contains(document, "<code>--no-vuln</code>"));
  }

  // Given an offline (cache-only) match, when rendered, then the report
  // labels the data source so stale feeds are never mistaken for fresh ones.
  {
    ReportContext context = make_context();
    context.vulnerability_check_offline = true;
    const std::string document = write_html_report({}, context);
    BOMWERK_TEST_CHECK(contains(document, "local cache only"));
    BOMWERK_TEST_CHECK(contains(document, "--offline"));
  }

  // Given the same scan handed over in two different orders (components,
  // vulnerability entries, and ids all shuffled; ids duplicated), when both
  // are rendered with SOURCE_DATE_EPOCH pinned, then the bytes are identical
  //: rule 3 applied to the report.
  {
    Component alpha = make_component("alpha", "1.0", "pkg:generic/alpha@1.0", Confidence::High);
    Component beta = make_component("beta", "2.0", "pkg:generic/beta@2.0", Confidence::Low);

    ReportContext forward_context = make_context();
    forward_context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/beta@2.0", {adv("OSV-2"), adv("OSV-1"), adv("OSV-1")}});
    forward_context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/alpha@1.0", {adv("CVE-A")}});
    const std::string forward = write_html_report({alpha, beta}, forward_context);

    ReportContext reversed_context = make_context();
    reversed_context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/alpha@1.0", {adv("CVE-A")}});
    reversed_context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/beta@2.0", {adv("OSV-1"), adv("OSV-2")}});
    const std::string reversed = write_html_report({beta, alpha}, reversed_context);

    BOMWERK_TEST_CHECK(forward == reversed);
    BOMWERK_TEST_CHECK(forward.find("pkg:generic/alpha@1.0") <
                       forward.find("pkg:generic/beta@2.0"));  // identity-sorted
  }

  // Given the three content sections, when rendered, then Components and
  // Vulnerabilities are native collapsible <details> open by default (so the
  // report still "opens clean"), while Warnings is collapsed by default even
  // when it has content: warnings are often numerous parser diagnostics that
  // would otherwise dominate the page, so a reader opens that section
  // deliberately. No JavaScript is involved in any of it.
  {
    Component component = make_component("z", "1", "pkg:generic/z@1", Confidence::Low);
    ReportContext context = make_context();
    context.warnings.push_back(bomwerk::core::Warning{
        bomwerk::core::WarningCode::kMalformedEntrySkipped, "some warning", {}, {}});
    const std::string document = write_html_report({component}, context);
    BOMWERK_TEST_CHECK(
        contains(document, "<details class=\"card\" open>\n      <summary><h2>Components"));
    BOMWERK_TEST_CHECK(
        contains(document, "<details class=\"card\" open>\n      <summary><h2>Vulnerabilities"));
    BOMWERK_TEST_CHECK(contains(document, "<details class=\"card\">\n      <summary><h2>Warnings"));
    BOMWERK_TEST_CHECK(contains(document, "@media print"));  // PDF/print stylesheet present
  }

  // Given a clean scan vs. one with findings vs. one not checked, when
  // rendered, then the leading risk-posture line reflects each verdict and the
  // not-checked path never reads as clean (honesty rule).
  {
    // The two-token class sequence ("posture posture-good") appears only in the
    // emitted `class="..."`, never in the stylesheet's `.posture-good` rule, so
    // these assertions test the rendered verdict rather than the always-present
    // CSS.
    const std::string clean = write_html_report({}, make_context());
    BOMWERK_TEST_CHECK(contains(clean, "posture posture-good"));
    BOMWERK_TEST_CHECK(contains(clean, "No known vulnerabilities"));

    ReportContext affected_context = make_context();
    affected_context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/x@1", {adv("CVE-2024-1")}});
    Component component = make_component("x", "1", "pkg:generic/x@1", Confidence::Low);
    const std::string affected = write_html_report({component}, affected_context);
    BOMWERK_TEST_CHECK(contains(affected, "posture posture-bad"));
    BOMWERK_TEST_CHECK(contains(affected, "1 component affected by 1 advisory."));

    ReportContext unchecked_context = make_context();
    unchecked_context.vulnerability_check_enabled = false;
    const std::string unchecked = write_html_report({}, unchecked_context);
    BOMWERK_TEST_CHECK(contains(unchecked, "posture posture-warn"));
    BOMWERK_TEST_CHECK(!contains(unchecked, "posture posture-good"));
  }

  // Given branding (company, contact, footer note, logo, accent), when
  // rendered, then each appears: the logo as an embedded data URI, the accent
  // as a validated CSS override, and the text fields in header/footer.
  {
    ReportContext context = make_context();
    context.branding.company_name = "Acme Corp";
    context.branding.contact = "security@acme.example";
    context.branding.footer_note = "Confidential: internal CRA use.";
    context.branding.accent_color = "#ff6600";
    context.branding.logo_data_uri = "data:image/png;base64,AAAA";
    const std::string document = write_html_report({}, context);
    BOMWERK_TEST_CHECK(contains(document, "<p class=\"brand\">Acme Corp</p>"));
    BOMWERK_TEST_CHECK(contains(document, "src=\"data:image/png;base64,AAAA\""));
    BOMWERK_TEST_CHECK(contains(document, "--accent:#ff6600"));
    BOMWERK_TEST_CHECK(contains(document, "Confidential: internal CRA use."));
    BOMWERK_TEST_CHECK(contains(document, "security@acme.example"));
  }

  // Given a valid config file with a PNG logo, when loaded, then the logo is
  // embedded as a base64 data URI and every text/accent field is populated.
  {
    TempTree tree;
    tree.write("brand/logo.png", std::string("\x89PNG\r\n\x1a\n", 8));  // 8 arbitrary bytes
    tree.write(
        "brand.json",
        R"({"company_name":"Acme","contact":"a@b.c","footer_note":"note",)"
        R"("accent_color":"#0af","unknown_severity_label":"No data","logo_path":"brand/logo.png"})");

    const bomwerk::core::Result<ReportBranding> loaded =
        load_report_branding(tree.root() / "brand.json");
    BOMWERK_TEST_CHECK(loaded.warnings.empty());
    BOMWERK_TEST_CHECK(loaded.value.company_name == "Acme");
    BOMWERK_TEST_CHECK(loaded.value.contact == "a@b.c");
    BOMWERK_TEST_CHECK(loaded.value.footer_note == "note");
    BOMWERK_TEST_CHECK(loaded.value.accent_color == "#0af");  // short #rgb form accepted
    BOMWERK_TEST_CHECK(loaded.value.unknown_severity_label == "No data");
    // "\x89PNG\r\n\x1a\n" base64-encodes to this known value.
    BOMWERK_TEST_CHECK(loaded.value.logo_data_uri == "data:image/png;base64,iVBORw0KGgo=");
  }

  // Given a config with a malformed accent color and an unsupported logo type,
  // when loaded, then each bad field warns and is dropped: the rest still
  // loads (never throws, partial beats nothing; rule 1).
  {
    TempTree tree;
    tree.write("logo.bmp", "whatever");
    tree.write("brand.json",
               R"({"company_name":"Ok","accent_color":"red","logo_path":"logo.bmp"})");

    const bomwerk::core::Result<ReportBranding> loaded =
        load_report_branding(tree.root() / "brand.json");
    BOMWERK_TEST_CHECK(loaded.value.company_name == "Ok");   // good field survives
    BOMWERK_TEST_CHECK(loaded.value.accent_color.empty());   // "red" rejected
    BOMWERK_TEST_CHECK(loaded.value.logo_data_uri.empty());  // .bmp unsupported
    BOMWERK_TEST_CHECK(loaded.warnings.size() == 2);         // one per bad field
  }

  // Given a missing config file, when loaded, then it degrades to a warning and
  // an empty branding rather than throwing.
  {
    const bomwerk::core::Result<ReportBranding> loaded =
        load_report_branding("/no/such/report-config.json");
    BOMWERK_TEST_CHECK(!loaded.warnings.empty());
    BOMWERK_TEST_CHECK(loaded.value.company_name.empty());
    BOMWERK_TEST_CHECK(loaded.value.logo_data_uri.empty());
  }

  // Given a commit-pinned dependency (its "version" is a 40-hex object id),
  // when rendered, then the version cell shows the abbreviated commit with a
  // "commit" tag and the full id on hover: not an unreadable 40-char blob.
  {
    const std::string commit = "6879efc2c1596d11a6a6ad296f80063b558d5e0f";
    Component harfbuzz = make_component("harfbuzz", commit,
                                        "pkg:github/harfbuzz/harfbuzz@" + commit, Confidence::High);
    const std::string document = write_html_report({harfbuzz}, make_context());
    BOMWERK_TEST_CHECK(contains(document, "title=\"" + commit + "\""));  // full id on hover
    BOMWERK_TEST_CHECK(contains(document, ">6879efc2c1</code>"));        // abbreviated display
    BOMWERK_TEST_CHECK(contains(document, "class=\"muted tag\">commit</span>"));
  }

  // Given a component OSV structurally cannot check, when its purl is listed in
  // components_without_osv_coverage_purls, then its row is tagged so the reader
  // sees exactly which component was not checked (not just a count).
  {
    Component conan_dep =
        make_component("boost", "1.83.0", "pkg:conan/boost@1.83.0", Confidence::High);
    ReportContext context = make_context();
    context.components_without_osv_coverage_purls.push_back("pkg:conan/boost@1.83.0");
    const std::string document = write_html_report({conan_dep}, context);
    BOMWERK_TEST_CHECK(contains(document, "no OSV coverage"));
    // The tag rides in the same <td> as the component name, before the version.
    const std::size_t name_pos = document.find("boost");
    const std::size_t tag_pos = document.find("no OSV coverage");
    BOMWERK_TEST_CHECK(name_pos != std::string::npos && tag_pos != std::string::npos);
    // Given the SAME row also satisfies the broader match-coverage badge
    // condition (`unmapped-purl-type`, since Conan has no OSV ecosystem),
    // when rendered, then boost's COMPONENT-TABLE ROW carries the "no OSV
    // coverage" badge only, not both: the two badges would say the same
    // thing for exactly this case (osv_coverage_absent is always a subset of
    // "not Matched"). Scoped to the row itself (not the whole document): the
    // separate Match coverage card below still lists boost under its own
    // "unmapped-purl-type" heading, which is a different section entirely.
    const std::size_t row_end = document.find("</tr>", name_pos);
    BOMWERK_TEST_CHECK(row_end != std::string::npos);
    const std::string row = document.substr(name_pos, row_end - name_pos);
    BOMWERK_TEST_CHECK(!contains(row, "unmapped-purl-type"));
  }

  // Given a linkable advisory, when rendered, then its osv.dev link opens in a
  // new tab and severs window.opener / Referer back to the local report.
  {
    ReportContext context = make_context();
    context.vulnerabilities.push_back(ReportVulnerability{"pkg:generic/x@1", {adv("CVE-2024-1")}});
    Component component = make_component("x", "1", "pkg:generic/x@1", Confidence::Low);
    const std::string document = write_html_report({component}, context);
    BOMWERK_TEST_CHECK(contains(document, "target=\"_blank\" rel=\"noopener noreferrer\""));
  }

  // Given a config whose text fields exceed the layout caps, when loaded, then
  // each is truncated to its byte budget with a warning (partial beats a broken
  // header; rule 1) and a clean value survives.
  {
    TempTree tree;
    const std::string long_name(200, 'A');  // > kMaxCompanyNameBytes (80)
    tree.write("brand.json", R"({"company_name":")" + long_name + R"("})");
    const bomwerk::core::Result<ReportBranding> loaded =
        load_report_branding(tree.root() / "brand.json");
    BOMWERK_TEST_CHECK(loaded.value.company_name.size() == 80);
    BOMWERK_TEST_CHECK(loaded.warnings.size() == 1);
    BOMWERK_TEST_CHECK(contains(loaded.warnings[0].message, "truncated"));
  }

  // Given advisories carrying CVSS scores, when rendered, then each shows a
  // severity badge, the vulnerability table is ordered worst-severity-first
  // (overriding purl order), and the posture line reports the highest score.
  {
    ReportContext context = make_context();
    // Purl identity order is aaa < zzz, but severity order is the reverse: so
    // the badge order proves the table sorted by severity, not by purl.
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/aaa@1", {adv("CVE-LOW", 3.4, SeverityRating::Low)}});
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/zzz@1", {adv("CVE-CRIT", 9.1, SeverityRating::Critical)}});
    Component low = make_component("aaa", "1", "pkg:generic/aaa@1", Confidence::Low);
    Component crit = make_component("zzz", "1", "pkg:generic/zzz@1", Confidence::Low);
    const std::string document = write_html_report({low, crit}, context);

    BOMWERK_TEST_CHECK(contains(document, "badge sev-critical"));
    BOMWERK_TEST_CHECK(contains(document, "9.1 Critical"));
    BOMWERK_TEST_CHECK(contains(document, "3.4 Low"));
    BOMWERK_TEST_CHECK(contains(document, "Highest severity 9.1 (Critical)."));
    // Severity badges appear only in the vulnerability table, so their relative
    // order is the table's order: Critical (9.1) before Low (3.4).
    BOMWERK_TEST_CHECK(document.find("9.1 Critical") < document.find("3.4 Low"));
  }

  // Given an advisory with no CVSS vector, when rendered, then its badge reads
  // the default "No info" (never a reassuring 0) and the posture omits a
  // highest-severity number rather than inventing one.
  {
    ReportContext context = make_context();
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/u@1", {adv("CVE-UNSCORED")}});
    Component component = make_component("u", "1", "pkg:generic/u@1", Confidence::Low);
    const std::string document = write_html_report({component}, context);
    BOMWERK_TEST_CHECK(contains(document, "sev-unknown"));
    BOMWERK_TEST_CHECK(contains(document, ">No info</span>"));
    BOMWERK_TEST_CHECK(!contains(document, "Highest severity"));
  }

  // Given a company-configured label for unscored advisories, when rendered,
  // then that wording replaces the default "No info".
  {
    ReportContext context = make_context();
    context.branding.unknown_severity_label = "Sin datos";
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:generic/u@1", {adv("CVE-UNSCORED")}});
    Component component = make_component("u", "1", "pkg:generic/u@1", Confidence::Low);
    const std::string document = write_html_report({component}, context);
    BOMWERK_TEST_CHECK(contains(document, ">Sin datos</span>"));
    BOMWERK_TEST_CHECK(!contains(document, ">No info</span>"));
  }

  // Given components of differing confidence, when rendered, then the component
  // table is ordered High -> Low (a reader triages strong evidence first).
  {
    Component low = make_component("aaa-low", "1", "pkg:generic/aaa-low@1", Confidence::Low);
    Component high = make_component("zzz-high", "1", "pkg:generic/zzz-high@1", Confidence::High);
    // Passed low-first; confidence sort must still place the High row first even
    // though its purl sorts last.
    const std::string document = write_html_report({low, high}, make_context());
    BOMWERK_TEST_CHECK(document.find("zzz-high") < document.find("aaa-low"));
  }

  // Given components spanning three unmatched classes plus one matched
  // component, when rendered, then the "Match coverage" card's summary line,
  // its "unmatched (coverage)" summary tile, and the per-class labels all
  // agree on the same counts: every surface derives from
  // `core::classify_match_coverage`, so the numbers cannot disagree.
  {
    Component matched =
        make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0", Confidence::High);
    Component unmapped =
        make_component("openssl", "3.2.0", "pkg:conan/openssl@3.2.0", Confidence::Low);
    Component unversioned = make_component("zlib", "", "pkg:vcpkg/zlib", Confidence::Low);
    Component no_identifier = make_component("mystery", "", "", Confidence::Low);
    const std::string document =
        write_html_report({matched, unmapped, unversioned, no_identifier}, make_context());

    BOMWERK_TEST_CHECK(contains(document, "<h2>Match coverage</h2>"));
    BOMWERK_TEST_CHECK(contains(document, "4 components, 1 matchable (25.0%), 3 unmatched"));
    BOMWERK_TEST_CHECK(contains(
        document,
        "metric-value\">3</span><span class=\"metric-label\">unmatched (coverage)</span>"));
    BOMWERK_TEST_CHECK(contains(document, "class=\"metric warn\""));  // non-zero => warn-toned
    BOMWERK_TEST_CHECK(contains(document, "unmapped-purl-type"));
    BOMWERK_TEST_CHECK(contains(document, "unversioned-purl"));
    BOMWERK_TEST_CHECK(contains(document, "no-identifier"));
    // A matched component never carries the coverage badge: same "gains
    // nothing" rule as the CycloneDX writer's `component.properties`: its
    // name cell closes immediately, with no badge span in between.
    BOMWERK_TEST_CHECK(contains(document, "left-pad</td>"));
  }

  // Given vulnerability matching disabled (--no-vuln) alongside an unmatched
  // component, when rendered, then the Match coverage card and its summary
  // tile STILL appear : : identifier quality is a fact about the SBOM,
  // not about whether OSV ran, unlike the Vulnerabilities section right below
  // it, which does say "Not checked".
  {
    ReportContext context = make_context();
    context.vulnerability_check_enabled = false;
    Component unmapped =
        make_component("openssl", "3.2.0", "pkg:conan/openssl@3.2.0", Confidence::Low);
    const std::string document = write_html_report({unmapped}, context);
    BOMWERK_TEST_CHECK(contains(document, "<h2>Match coverage</h2>"));
    BOMWERK_TEST_CHECK(contains(document, "unmapped-purl-type"));
    BOMWERK_TEST_CHECK(contains(
        document,
        "metric-value\">1</span><span class=\"metric-label\">unmatched (coverage)</span>"));
    BOMWERK_TEST_CHECK(
        contains(document, "Not checked"));  // the Vulnerabilities section, separately
  }

  // Given a hostile component name on an unmatched-class component, when
  // rendered, then the Match coverage card's per-class table escapes it like
  // every other surface in the document.
  {
    Component hostile =
        make_component("<script>evil</script>", "", "pkg:conan/evil", Confidence::Low);
    const std::string document = write_html_report({hostile}, make_context());
    BOMWERK_TEST_CHECK(!contains(document, "<script>evil</script>"));
    BOMWERK_TEST_CHECK(contains(document, "&lt;script&gt;evil&lt;/script&gt;"));
  }

  // Given an uncovered component the CPE fallback checked, when rendered,
  // then its row swaps the "no OSV coverage" badge for "checked via CPE": and
  // carries exactly one of them, never both, so the row cannot contradict
  // itself.
  {
    Component zlib = make_component("zlib", "1.2.11", "pkg:conan/zlib@1.2.11", Confidence::High);
    ReportContext context = make_context();
    context.components_without_osv_coverage_purls.push_back("pkg:conan/zlib@1.2.11");
    context.components_checked_via_cpe_fallback_purls.push_back("pkg:conan/zlib@1.2.11");

    const std::string document = write_html_report({zlib}, context);
    BOMWERK_TEST_CHECK(contains(document, ">checked via CPE</span>"));
    BOMWERK_TEST_CHECK(!contains(document, ">no OSV coverage</span>"));
    // The caveat is `badge low`: never `bad`, which is the advisory-count
    // weight, and never a `sev-*` class, which means a CVSS band.
    BOMWERK_TEST_CHECK(contains(document,
                                "class=\"badge low\" title=\"No OSV ecosystem for this "
                                "package type; matched against NVD by CPE"));
    // Checked, so it is no longer part of the not-checked figure: and the tile
    // now counts ONE thing, so a 0 under it cannot be read as "0 components
    // have no OSV coverage" while the coverage card lists one that does.
    BOMWERK_TEST_CHECK(
        contains(document, "metric-value\">0</span><span class=\"metric-label\">not checked<"));
    BOMWERK_TEST_CHECK(!contains(document, "no OSV coverage (not checked)"));
    // ...and is counted under its own tile instead.
    BOMWERK_TEST_CHECK(contains(document,
                                "metric-value\">1</span><span class=\"metric-label\">checked via "
                                "CPE (low confidence)"));
    BOMWERK_TEST_CHECK(contains(document,
                                "1 component(s) have no OSV ecosystem coverage (Conan, "
                                "vcpkg, generic) and were matched against NVD by CPE"));
    BOMWERK_TEST_CHECK(!contains(document, "and were not checked"));
  }

  // Given two uncovered components of which the fallback reached only one,
  // when rendered, then the two lists partition the set exactly: one row of
  // each badge, and the counts sum back to the uncovered total.
  {
    Component checked = make_component("zlib", "1.2.11", "pkg:conan/zlib@1.2.11", Confidence::High);
    Component unreachable =
        make_component("mystery", "9.9", "pkg:conan/mystery@9.9", Confidence::Low);
    ReportContext context = make_context();
    context.components_without_osv_coverage_purls = {"pkg:conan/zlib@1.2.11",
                                                     "pkg:conan/mystery@9.9"};
    context.components_checked_via_cpe_fallback_purls = {"pkg:conan/zlib@1.2.11"};

    const std::string document = write_html_report({checked, unreachable}, context);
    BOMWERK_TEST_CHECK(contains(document, ">checked via CPE</span>"));
    BOMWERK_TEST_CHECK(contains(document, ">no OSV coverage</span>"));
    BOMWERK_TEST_CHECK(
        contains(document, "metric-value\">1</span><span class=\"metric-label\">not checked<"));
    BOMWERK_TEST_CHECK(contains(document,
                                "metric-value\">1</span><span class=\"metric-label\">checked via "
                                "CPE (low confidence)"));
  }

  // Given a lower-confidence finding beside a purl-exact one, when
  // rendered, then only the CPE row is tagged: and with `badge low`, so a
  // wildcard-vendor guess never reads louder than a confirmed match.
  {
    Component conan_zlib =
        make_component("zlib", "1.2.11", "pkg:conan/zlib@1.2.11", Confidence::High);
    Component npm_lib =
        make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0", Confidence::High);
    ReportContext context = make_context();
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:npm/left-pad@1.3.0",
                            {adv("CVE-2020-1111", 7.5, SeverityRating::High)},
                            FindingSource::OsvPurlMatch});
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:conan/zlib@1.2.11",
                            {adv("CVE-2022-37434", 9.8, SeverityRating::Critical)},
                            FindingSource::NvdCpeMatch});

    const std::string document = write_html_report({conan_zlib, npm_lib}, context);
    BOMWERK_TEST_CHECK(contains(document, ">CPE match, low confidence</span>"));
    // Each advisory cites the database that produced it. Sending a CPE-matched
    // finding to osv.dev would point the reader at a database that, by the
    // definition of this path, could not match the component at all.
    BOMWERK_TEST_CHECK(
        contains(document, "href=\"https://nvd.nist.gov/vuln/detail/CVE-2022-37434\""));
    BOMWERK_TEST_CHECK(contains(document, "href=\"https://osv.dev/vulnerability/CVE-2020-1111\""));
    BOMWERK_TEST_CHECK(!contains(document, "https://osv.dev/vulnerability/CVE-2022-37434"));
    // One finding is purl-exact, so the posture line must NOT be qualified :
    // a real OSV hit is never softened by weaker company.
    BOMWERK_TEST_CHECK(!contains(document, "All from CPE matches"));
    BOMWERK_TEST_CHECK(contains(document,
                                "class=\"badge low\" title=\"Matched against NVD by CPE "
                                "with a wildcard vendor"));
    // Exactly one row is tagged: the purl-exact finding carries no such badge.
    BOMWERK_TEST_CHECK(document.find("CPE match, low confidence") ==
                       document.rfind("CPE match, low confidence"));
  }

  // Given the SAME purl reported by both feeds, when the report merges the
  // two entries into one row, then the row is NOT discounted: an exact OSV
  // match backs it, and the merge must not let the weaker evidence set the
  // label. (`normalized_vulnerabilities` rebuilds every entry, so a field that
  // is not carried across is silently dropped; this pins that it is.)
  {
    Component zlib = make_component("zlib", "1.2.11", "pkg:conan/zlib@1.2.11", Confidence::High);
    ReportContext context = make_context();
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:conan/zlib@1.2.11",
                            {adv("CVE-2022-37434", 9.8, SeverityRating::Critical)},
                            FindingSource::NvdCpeMatch});
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:conan/zlib@1.2.11",
                            {adv("CVE-2018-25032", 7.5, SeverityRating::High)},
                            FindingSource::OsvPurlMatch});

    const std::string document = write_html_report({zlib}, context);
    BOMWERK_TEST_CHECK(!contains(document, "CPE match, low confidence"));
    // Still one merged row carrying both advisories.
    BOMWERK_TEST_CHECK(contains(document, "CVE-2022-37434"));
    BOMWERK_TEST_CHECK(contains(document, "CVE-2018-25032"));
    // The merged row is backed by an exact OSV match, so it is cited there.
    BOMWERK_TEST_CHECK(contains(document, "href=\"https://osv.dev/vulnerability/CVE-2022-37434\""));
    BOMWERK_TEST_CHECK(!contains(document, "nvd.nist.gov/vuln/detail"));
  }

  // Given the same purl reported twice by the CPE fallback alone, when the
  // entries merge, then the row stays labeled: "all entries were weak" is the
  // condition, not "any entry was strong".
  {
    Component zlib = make_component("zlib", "1.2.11", "pkg:conan/zlib@1.2.11", Confidence::High);
    ReportContext context = make_context();
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:conan/zlib@1.2.11",
                            {adv("CVE-2022-37434", 9.8, SeverityRating::Critical)},
                            FindingSource::NvdCpeMatch});
    context.vulnerabilities.push_back(
        ReportVulnerability{"pkg:conan/zlib@1.2.11",
                            {adv("CVE-2018-25032", 7.5, SeverityRating::High)},
                            FindingSource::NvdCpeMatch});

    const std::string document = write_html_report({zlib}, context);
    BOMWERK_TEST_CHECK(contains(document, ">CPE match, low confidence</span>"));
    BOMWERK_TEST_CHECK(
        contains(document, "href=\"https://nvd.nist.gov/vuln/detail/CVE-2022-37434\""));
    // Nothing here is a purl-exact match, so the loudest element on the
    // page, the red posture line, must say so rather than presenting
    // wildcard-vendor guesses as a verdict.
    BOMWERK_TEST_CHECK(contains(document,
                                "All from CPE matches. Treat as leads, not "
                                "confirmed.</div>"));
    // The footer only mentions NVD when a CPE-matched finding is actually in
    // this report: here one is, so it does.
    BOMWERK_TEST_CHECK(contains(document, "nvd.nist.gov for CPE-matched findings"));
  }

  // regression. Given only purl-exact findings (every earlier scan), when
  // rendered, then the posture line is unqualified and every advisory still
  // links to osv.dev: the default path is untouched.
  {
    Component npm_lib =
        make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0", Confidence::High);
    ReportContext context = make_context();
    context.vulnerabilities.push_back(ReportVulnerability{
        "pkg:npm/left-pad@1.3.0", {adv("CVE-2020-1111", 7.5, SeverityRating::High)}});

    const std::string document = write_html_report({npm_lib}, context);
    BOMWERK_TEST_CHECK(!contains(document, "All from CPE matches"));
    BOMWERK_TEST_CHECK(!contains(document, "CPE match, low confidence"));
    BOMWERK_TEST_CHECK(contains(document, "href=\"https://osv.dev/vulnerability/CVE-2020-1111\""));
    BOMWERK_TEST_CHECK(!contains(document, "nvd.nist.gov"));
    // The footer's own byte-identical guarantee: an OSV-only report must say
    // exactly what every report said before the CPE fallback existed.
    BOMWERK_TEST_CHECK(contains(document, "Advisory links resolve at osv.dev.</p>"));
  }

  // CPE-fallback regression. Given no CPE fallback (the default), when rendered,
  // then every match-coverage surface behaves exactly as before: no new tile, no new badge,
  // no reworded notice.
  {
    Component zlib = make_component("zlib", "1.2.11", "pkg:conan/zlib@1.2.11", Confidence::High);
    ReportContext context = make_context();
    context.components_without_osv_coverage_purls.push_back("pkg:conan/zlib@1.2.11");

    const std::string document = write_html_report({zlib}, context);
    BOMWERK_TEST_CHECK(contains(document, ">no OSV coverage</span>"));
    BOMWERK_TEST_CHECK(!contains(document, "checked via CPE"));
    BOMWERK_TEST_CHECK(!contains(document, "CPE match, low confidence"));
    BOMWERK_TEST_CHECK(contains(
        document,
        "metric-value\">1</span><span class=\"metric-label\">no OSV coverage (not checked)"));
    BOMWERK_TEST_CHECK(contains(document, "and were not checked"));
  }

  std::puts("test_html_report: OK");
  return 0;
}
