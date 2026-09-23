#include <cstdio>
#include <cstdlib>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "output/tool_info.hpp"
#include "output/warnings_report.hpp"
#include "support/check.hpp"

using bomwerk::core::ReleaseMeta;
using bomwerk::core::Warning;
using bomwerk::core::WarningCode;
using bomwerk::output::ToolInfo;
using bomwerk::output::write_warnings_report;

int main()
{
  // Given many occurrences of the same (code, ecosystem) cause across different files, when
  // written, then they collapse into one entry with a count and a deduplicated, sorted list
  // of affected paths: the ticket's "604 repeated vcpkg lines" case.
  {
    std::vector<Warning> warnings;
    for (int index = 0; index < 3; ++index)
    {
      warnings.push_back(Warning{WarningCode::kUnreadableFile, "vcpkg: unreadable file: vcpkg.json",
                                 "vcpkg",
                                 "third_party/pkg" + std::to_string(index) + "/vcpkg.json"});
    }
    const std::string document = write_warnings_report(warnings, {}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);

    BOMWERK_TEST_CHECK(parsed["tool"]["name"] == "bomwerk");
    BOMWERK_TEST_CHECK(parsed.contains("generated_at"));
    BOMWERK_TEST_CHECK(parsed["total_occurrences"] == 3);
    BOMWERK_TEST_CHECK(parsed["warnings"].size() == 1);
    const nlohmann::json& entry = parsed["warnings"][0];
    BOMWERK_TEST_CHECK(entry["code"] == "BW-CORE-009");
    BOMWERK_TEST_CHECK(entry["ecosystem"] == "vcpkg");
    BOMWERK_TEST_CHECK(entry["count"] == 3);
    BOMWERK_TEST_CHECK(entry["suppressed"] == false);
    BOMWERK_TEST_CHECK(entry["affected_paths"].size() == 3);
    BOMWERK_TEST_CHECK(entry["affected_paths"][0] == "third_party/pkg0/vcpkg.json");
  }

  // Given a code the caller marked suppressed, when written, then the entry is still present
  // (suppression never hides a warning from an artifact) but flagged "suppressed": true.
  {
    std::vector<Warning> warnings = {
        Warning{WarningCode::kManifestNoLockfileAlongside,
                "npm: found package.json (1 file(s)) with no lockfile alongside",
                "npm",
                {}}};
    const std::set<std::string> suppressed = {"BW-CORE-004"};
    const std::string document =
        write_warnings_report(warnings, suppressed, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(parsed["warnings"].size() == 1);
    BOMWERK_TEST_CHECK(parsed["warnings"][0]["code"] == "BW-CORE-004");
    BOMWERK_TEST_CHECK(parsed["warnings"][0]["suppressed"] == true);
  }

  // Given an ecosystem-specific suppression, when written, then only the matching ecosystem
  // entry is marked suppressed.
  {
    std::vector<Warning> warnings = {
        Warning{WarningCode::kManifestNoLockfileAlongside, "npm gap", "npm", {}},
        Warning{WarningCode::kManifestNoLockfileAlongside, "python gap", "python", {}}};
    const std::set<std::string> suppressed = {"BW-CORE-004:npm"};
    const nlohmann::json parsed = nlohmann::json::parse(
        write_warnings_report(warnings, suppressed, ToolInfo{"bomwerk", "0.1.0"}));
    BOMWERK_TEST_CHECK(parsed["warnings"].size() == 2);
    BOMWERK_TEST_CHECK(parsed["warnings"][0]["ecosystem"] == "npm");
    BOMWERK_TEST_CHECK(parsed["warnings"][0]["suppressed"] == true);
    BOMWERK_TEST_CHECK(parsed["warnings"][1]["ecosystem"] == "python");
    BOMWERK_TEST_CHECK(parsed["warnings"][1]["suppressed"] == false);
  }

  // Given two distinct (code, ecosystem) pairs, when written, then entries are ordered by
  // (code id, ecosystem) regardless of the order warnings were recorded in (rule 3).
  {
    std::vector<Warning> forward = {
        Warning{WarningCode::kUnreadableFile, "python: unreadable file: a", "python", {}},
        Warning{WarningCode::kInvalidJson, "npm: not valid JSON", "npm", {}}};
    std::vector<Warning> reversed = {forward[1], forward[0]};
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    const std::string forward_document =
        write_warnings_report(forward, {}, ToolInfo{"bomwerk", "0.1.0"});
    const std::string reversed_document =
        write_warnings_report(reversed, {}, ToolInfo{"bomwerk", "0.1.0"});
    unsetenv("SOURCE_DATE_EPOCH");
    BOMWERK_TEST_CHECK(forward_document == reversed_document);
    const nlohmann::json parsed = nlohmann::json::parse(forward_document);
    BOMWERK_TEST_CHECK(parsed["warnings"][0]["code"] == "BW-CORE-002");
    BOMWERK_TEST_CHECK(parsed["warnings"][1]["code"] == "BW-CORE-009");
  }

  // Given no warnings, when written, then the document is still schema-shaped: an empty
  // array, not an absent field.
  {
    const std::string document = write_warnings_report({}, {}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(parsed["warnings"].empty());
    BOMWERK_TEST_CHECK(parsed["total_occurrences"] == 0);
  }

  // Given a warning message containing invalid UTF-8 (hostile evidence), when written, then
  // the document still parses as valid JSON rather than throwing across the module boundary
  // (rule 1).
  {
    std::vector<Warning> warnings = {
        Warning{WarningCode::kUnreadableFile, std::string("bad-\xff-utf8"), "npm", {}}};
    const std::string document = write_warnings_report(warnings, {}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json parsed = nlohmann::json::parse(document);  // must not throw
    BOMWERK_TEST_CHECK(parsed.is_object());
  }

  // Given a non-empty product id, when written, then `product` records it, and an empty
  // version stays omitted.
  {
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    const std::string document =
        write_warnings_report({}, {}, ToolInfo{"bomwerk", "0.1.0"}, release_meta);
    const nlohmann::json parsed = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(parsed["product"]["id"] == "widget-firmware");
    BOMWERK_TEST_CHECK(!parsed["product"].contains("version"));
  }

  std::puts("test_warnings_report: OK");
  return 0;
}
