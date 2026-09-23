#include <cstdio>
#include <cstdlib>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

#include "core/model.hpp"
#include "output/coverage.hpp"
#include "support/check.hpp"

using bomwerk::core::Component;
using bomwerk::core::ReleaseMeta;
using bomwerk::output::ToolInfo;
using bomwerk::output::write_coverage_report;

namespace
{

Component make_component(std::string name, std::string version, std::string purl)
{
  Component component;
  component.name = std::move(name);
  component.version = std::move(version);
  component.purl = std::move(purl);
  return component;
}

}  // namespace

int main()
{
  // Given one component of each match-coverage class, when written, then
  // every component is present (not just the unmatched ones: this file is
  // the FULL classification, unlike the CycloneDX/HTML surfaces) with its
  // class, identity, and confidence, and the summary agrees with the
  // per-component classes.
  {
    Component matched = make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");
    Component unmapped = make_component("openssl", "3.2.0", "pkg:conan/openssl@3.2.0");
    Component unversioned = make_component("zlib", "", "pkg:vcpkg/zlib");
    Component no_identifier = make_component("mystery", "", "");
    const std::string document = write_coverage_report(
        {matched, unmapped, unversioned, no_identifier}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);

    BOMWERK_TEST_CHECK(parsed["tool"]["name"] == "bomwerk");
    BOMWERK_TEST_CHECK(parsed["tool"]["version"] == "0.1.0");
    BOMWERK_TEST_CHECK(parsed.contains("generated_at"));

    BOMWERK_TEST_CHECK(parsed["summary"]["components"] == 4);
    BOMWERK_TEST_CHECK(parsed["summary"]["matchable"] == 1);
    BOMWERK_TEST_CHECK(parsed["summary"]["unmatched"] == 3);
    BOMWERK_TEST_CHECK(parsed["summary"]["by_class"]["matched"] == 1);
    BOMWERK_TEST_CHECK(parsed["summary"]["by_class"]["unmapped-purl-type"] == 1);
    BOMWERK_TEST_CHECK(parsed["summary"]["by_class"]["unversioned-purl"] == 1);
    BOMWERK_TEST_CHECK(parsed["summary"]["by_class"]["no-identifier"] == 1);

    BOMWERK_TEST_CHECK(parsed["components"].size() == 4);
    // Identity-sorted: name@version fallback for the purl-less component
    // ("mystery@") sorts before every "pkg:..." identity.
    BOMWERK_TEST_CHECK(parsed["components"][0]["name"] == "mystery");
    BOMWERK_TEST_CHECK(parsed["components"][0]["coverage"] == "no-identifier");
    BOMWERK_TEST_CHECK(!parsed["components"][0].contains("purl"));
    BOMWERK_TEST_CHECK(!parsed["components"][0].contains("version"));
    BOMWERK_TEST_CHECK(parsed["components"][0]["confidence"] == "low");
  }

  // Given the same components in two different orders, when written, then
  // the full byte output is identical either way: determinism (rule 3)
  // holds for this writer exactly like the CycloneDX/SPDX ones.
  {
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    Component first = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    Component second = make_component("fmt", "10.2.1", "pkg:vcpkg/fmt@10.2.1");
    const std::string forward =
        write_coverage_report({first, second}, ToolInfo{"bomwerk", "0.1.0"});
    const std::string reversed =
        write_coverage_report({second, first}, ToolInfo{"bomwerk", "0.1.0"});
    BOMWERK_TEST_CHECK(forward == reversed);
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given no ReleaseMeta (the default), when written, then `product` is
  // omitted entirely; given one with product_id set, when written, then
  // `product` records it, and an empty version stays omitted.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    const std::string without_product =
        write_coverage_report({component}, ToolInfo{"bomwerk", "0.1.0"});
    BOMWERK_TEST_CHECK(!nlohmann::json::parse(without_product).contains("product"));

    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    const std::string with_product =
        write_coverage_report({component}, ToolInfo{"bomwerk", "0.1.0"}, release_meta);
    const nlohmann::json parsed_with_product = nlohmann::json::parse(with_product);
    BOMWERK_TEST_CHECK(parsed_with_product["product"]["id"] == "widget-firmware");
    BOMWERK_TEST_CHECK(!parsed_with_product["product"].contains("version"));
  }

  // Given an empty component list, when written, then the document is still
  // schema-shaped: an empty (not absent) components array and an all-zero
  // summary.
  {
    const std::string document = write_coverage_report({}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(parsed["components"].empty());
    BOMWERK_TEST_CHECK(parsed["summary"]["components"] == 0);
    BOMWERK_TEST_CHECK(parsed["summary"]["matchable"] == 0);
  }

  // Given a component whose name contains invalid UTF-8 (hostile evidence),
  // when written, then the document still parses as valid JSON rather than
  // throwing across the module boundary (rule 1).
  {
    Component component = make_component(std::string("bad-\xff-utf8"), "1.0", "pkg:generic/weird");
    const std::string document = write_coverage_report({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);  // must not throw
    BOMWERK_TEST_CHECK(parsed.is_object());
  }

  std::puts("test_coverage_report: OK");
  return 0;
}
