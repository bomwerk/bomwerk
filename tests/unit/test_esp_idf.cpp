// ctest unit test for the ESP-IDF component manager producer
// (dependencies.lock and idf_component.yml).
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "core/warning_code.hpp"
#include "parsers/embedded/esp_idf.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

using bomwerk::core::Component;
using bomwerk::core::Confidence;
using bomwerk::core::highest_confidence;
using bomwerk::core::Result;
using bomwerk::core::WarningCode;
using bomwerk::test::TempTree;

namespace fs = std::filesystem;
namespace esp_idf = bomwerk::parsers::embedded::esp_idf;

namespace
{

const fs::path kFixtures = fs::path(BOMWERK_FIXTURES_DIR);
const fs::path kEspIdfFixtures = kFixtures / "esp_idf";
const fs::path kHostile = kEspIdfFixtures / "hostile";

std::size_t warnings_with_code(const Result<std::vector<Component>>& result, WarningCode code)
{
  return static_cast<std::size_t>(std::count_if(result.warnings.begin(), result.warnings.end(),
                                                [code](const bomwerk::core::Warning& warning)
                                                { return warning.code == code; }));
}

bool any_warning_contains(const Result<std::vector<Component>>& result, const std::string& fragment)
{
  return std::any_of(result.warnings.begin(), result.warnings.end(),
                     [&fragment](const bomwerk::core::Warning& warning)
                     { return warning.message.find(fragment) != std::string::npos; });
}

/// The component whose purl is `purl`, or nullptr: output order is the merge
/// order, so tests look components up rather than index them.
const Component* find_purl(const Result<std::vector<Component>>& result, const std::string& purl)
{
  for (const Component& component : result.value)
  {
    if (component.purl == purl)
    {
      return &component;
    }
  }
  return nullptr;
}

bool has_evidence_containing(const Component& component, const std::string& fragment)
{
  return std::any_of(component.evidence.begin(), component.evidence.end(),
                     [&fragment](const bomwerk::core::Evidence& evidence)
                     { return evidence.detail.find(fragment) != std::string::npos; });
}

}  // namespace

int main()
{
  // Given a 2.x lock with registry, idf, git and local entries, when parsed,
  // then each non-local entry is one versioned High component, the hash lands
  // in sha256 (lower-cased), the git entry keeps its repository subdirectory as
  // the purl subpath, and nothing is warned.
  {
    const auto result = esp_idf::parse(kFixtures / "golden" / "esp-idf-lock" / "tree");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 4);

    const Component* led_strip = find_purl(result, "pkg:generic/espressif/led_strip@2.5.5");
    BOMWERK_TEST_CHECK(led_strip != nullptr);
    BOMWERK_TEST_CHECK(led_strip->name == "led_strip");
    BOMWERK_TEST_CHECK(led_strip->version == "2.5.5");
    BOMWERK_TEST_CHECK(led_strip->supplier == "espressif");
    BOMWERK_TEST_CHECK(led_strip->sha256 ==
                       "5c1a2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9");
    BOMWERK_TEST_CHECK(highest_confidence(*led_strip) == Confidence::High);
    BOMWERK_TEST_CHECK(
        has_evidence_containing(*led_strip, "dependencies.lock -> espressif/led_strip"));

    const Component* idf = find_purl(result, "pkg:generic/espressif/esp-idf@5.3.1");
    BOMWERK_TEST_CHECK(idf != nullptr);
    BOMWERK_TEST_CHECK(idf->name == "esp-idf");
    BOMWERK_TEST_CHECK(idf->sha256.empty());

    const Component* mdns =
        find_purl(result,
                  "pkg:github/espressif/"
                  "esp-protocols@0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c#components/mdns");
    BOMWERK_TEST_CHECK(mdns != nullptr);
    BOMWERK_TEST_CHECK(mdns->name == "mdns");
    BOMWERK_TEST_CHECK(mdns->supplier == "espressif");
    BOMWERK_TEST_CHECK(highest_confidence(*mdns) == Confidence::High);

    const Component* littlefs = find_purl(result, "pkg:generic/joltwallet/littlefs@1.14.8");
    BOMWERK_TEST_CHECK(littlefs != nullptr);
    BOMWERK_TEST_CHECK(littlefs->supplier == "joltwallet");
    BOMWERK_TEST_CHECK(littlefs->sha256 ==
                       "a0b1c2d3e4f5061728394a5b6c7d8e9fa0b1c2d3e4f5061728394a5b6c7d8e9f");

    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.name != "sensor_driver");  // local: the project itself
    }
  }

  // Given a 1.x lock (service_url sources), when parsed, then it reads like a
  // 2.x one and Espressif's own api host is not noted as another registry.
  {
    const auto result = esp_idf::parse(kEspIdfFixtures / "lock-v1");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    const Component* tinyusb = find_purl(result, "pkg:generic/espressif/esp_tinyusb@1.0.4");
    BOMWERK_TEST_CHECK(tinyusb != nullptr);
    BOMWERK_TEST_CHECK(!has_evidence_containing(*tinyusb, "registry"));
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/esp-idf@4.4.6") != nullptr);
  }

  // Given a component from another registry, then its identity is unchanged
  // and the registry is named in the evidence detail.
  {
    const auto result = esp_idf::parse(kEspIdfFixtures / "registry-mirror");
    BOMWERK_TEST_CHECK(result.warnings.empty());
    const Component* motor = find_purl(result, "pkg:generic/acme/motor_ctl@3.1.0");
    BOMWERK_TEST_CHECK(motor != nullptr);
    BOMWERK_TEST_CHECK(
        has_evidence_containing(*motor, "registry https://components.acme.example/"));
  }

  // Given lockless manifests, when parsed, then registry declarations are
  // version-less Medium with the constraint kept in the evidence, a bare name
  // is in the espressif namespace, idf becomes esp-idf, a git SHA pin is
  // versioned High, local path/override_path entries are dropped, and the same
  // component declared twice merges into one with both constraints.
  {
    const auto result = esp_idf::parse(kFixtures / "golden" / "esp-idf-manifest-only" / "tree");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 7);

    const Component* led_strip = find_purl(result, "pkg:generic/espressif/led_strip");
    BOMWERK_TEST_CHECK(led_strip != nullptr);
    BOMWERK_TEST_CHECK(led_strip->version.empty());
    BOMWERK_TEST_CHECK(highest_confidence(*led_strip) == Confidence::Medium);
    BOMWERK_TEST_CHECK(has_evidence_containing(*led_strip, "(requires ^2.4.1)"));
    BOMWERK_TEST_CHECK(has_evidence_containing(*led_strip, "(requires >=2.0)"));

    const Component* idf = find_purl(result, "pkg:generic/espressif/esp-idf");
    BOMWERK_TEST_CHECK(idf != nullptr);
    BOMWERK_TEST_CHECK(has_evidence_containing(*idf, "(requires >=5.0)"));

    const Component* tinyusb = find_purl(result, "pkg:generic/espressif/esp_tinyusb");
    BOMWERK_TEST_CHECK(tinyusb != nullptr);
    BOMWERK_TEST_CHECK(has_evidence_containing(*tinyusb, "(requires ^1.4, conditional)"));

    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/button") != nullptr);
    const Component* lvgl = find_purl(result, "pkg:generic/lvgl/lvgl");
    BOMWERK_TEST_CHECK(lvgl != nullptr);
    BOMWERK_TEST_CHECK(has_evidence_containing(*lvgl, "(requires ^8.3)"));
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/esp-dsp") != nullptr);

    const Component* u8g2 =
        find_purl(result, "pkg:github/olikraus/u8g2@1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d");
    BOMWERK_TEST_CHECK(u8g2 != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*u8g2) == Confidence::High);

    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.name != "sensor_driver");
      BOMWERK_TEST_CHECK(component.name != "protocol_examples_common");
      BOMWERK_TEST_CHECK(component.name != "cmake_utilities");
    }
  }

  // Given a lock above main/ and managed_components/, beside a lockless
  // project, when parsed, then the covered manifests are not read, and the
  // lockless project keeps only what no lock resolved: its version-less
  // led_strip and idf are shadowed by the lock's versioned ones.
  {
    const auto result = esp_idf::parse(kFixtures / "golden" / "esp-idf-lock-and-manifest" / "tree");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 3);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/led_strip@2.5.5") != nullptr);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/esp-idf@5.2.3") != nullptr);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/esp_websocket_client") != nullptr);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/led_strip") == nullptr);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/esp-idf") == nullptr);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/never_resolved") == nullptr);
  }

  // Given a lock that sorts after the manifest it covers (components/ <
  // dependencies.lock), then the manifest is still skipped.
  {
    TempTree tree;
    tree.write("components/motor/idf_component.yml", "dependencies:\n  espressif/pid: \"^1\"\n");
    tree.write("dependencies.lock",
               "dependencies:\n  idf:\n    source:\n      type: idf\n    version: 5.1.2\n"
               "manifest_hash: 00\nversion: 2.0.0\n");
    const auto result = esp_idf::parse(tree.root());
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/espressif/esp-idf@5.1.2") != nullptr);
  }

  // Given real upstream ESP-IDF manifests, then the git SHA pin is High and
  // every registry constraint is reported once, with no warning.
  {
    const auto result = esp_idf::parse(kEspIdfFixtures / "esp-idf-c712a0dd");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.warnings.empty());
    BOMWERK_TEST_CHECK(result.value.size() == 8);
    const Component* u8g2 =
        find_purl(result, "pkg:github/olikraus/u8g2@c2935e962cbcaa9ed76b7cae30f47be14c860651");
    BOMWERK_TEST_CHECK(u8g2 != nullptr);
    BOMWERK_TEST_CHECK(highest_confidence(*u8g2) == Confidence::High);
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:generic/esp-qa/wifi-cmd") != nullptr);
    const Component* hosted = find_purl(result, "pkg:generic/espressif/esp_hosted");
    BOMWERK_TEST_CHECK(hosted != nullptr);
    BOMWERK_TEST_CHECK(has_evidence_containing(*hosted, "(requires ~2, conditional)"));
  }

  // Given a budget of one component, then one is kept, the scan is incomplete
  // and the limit is warned once.
  {
    esp_idf::ParseOptions options;
    options.max_total_components = 1;
    const auto result = esp_idf::parse(kFixtures / "golden" / "esp-idf-lock" / "tree", options);
    BOMWERK_TEST_CHECK(!result.complete);
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kEntryLimitReached) == 1);
  }

  // Hostile: a dependencies.lock the component manager did not write is
  // silently ignored.
  {
    const auto result = esp_idf::parse(kHostile / "not-a-lock");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(result.warnings.empty());
  }

  // Hostile: an unknown lock major is skipped whole, with one warning.
  {
    const auto result = esp_idf::parse(kHostile / "unknown-major");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kLockfileFormatUnsupported) == 1);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "'3.0.0'"));
  }

  // Hostile: a hash that is not 64 hex digits is never a sha256.
  {
    const auto result = esp_idf::parse(kHostile / "bad-hash");
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.sha256.empty());
    }
  }

  // Hostile: a git path that climbs claims no subpath.
  {
    const auto result = esp_idf::parse(kHostile / "climbing-subpath");
    BOMWERK_TEST_CHECK(result.value.size() == 1);
    BOMWERK_TEST_CHECK(result.value.front().purl ==
                       "pkg:github/example/escape@0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c");
  }

  // Hostile: unknown source type, no source, scalar entry: three malformed.
  {
    const auto result = esp_idf::parse(kHostile / "unknown-source-type");
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(any_warning_contains(result, "3 malformed entrie(s)"));
  }

  // Hostile: ${VAR} in a name or a git url is skipped and named.
  {
    const auto result = esp_idf::parse(kHostile / "variable-name");
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(
        warnings_with_code(result, WarningCode::kUnresolvedVariableOrInterpolation) == 1);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "'fork'"));
  }

  // Hostile: list-form dependencies, bad registry names and a one-line flow
  // dependencies map are malformed, never components.
  for (const char* directory : {"list-form", "bad-registry-name", "flow-dependencies"})
  {
    const auto result = esp_idf::parse(kHostile / directory);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kMalformedEntrySkipped) >= 1);
  }

  // Hostile: a block scalar body holding a dependencies: block is skipped as
  // one unit, and tab indentation recognizes nothing.
  for (const char* directory : {"block-scalar-fake-entry", "tabs"})
  {
    const auto result = esp_idf::parse(kHostile / directory);
    BOMWERK_TEST_CHECK(result.complete);
    BOMWERK_TEST_CHECK(result.value.empty());
  }

  // Hostile: a git source with an empty url is skipped with a warning.
  {
    const auto result = esp_idf::parse(kHostile / "git-no-url");
    BOMWERK_TEST_CHECK(result.value.empty());
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kDependencyMissingSource) == 1);
  }

  // Hostile: a git source with no version, or `*`, is version-less at Low with
  // one warning naming both.
  {
    const auto result = esp_idf::parse(kHostile / "git-no-version");
    BOMWERK_TEST_CHECK(result.value.size() == 2);
    for (const Component& component : result.value)
    {
      BOMWERK_TEST_CHECK(component.version.empty());
      BOMWERK_TEST_CHECK(highest_confidence(component) == Confidence::Low);
    }
    BOMWERK_TEST_CHECK(find_purl(result, "pkg:github/example/star") != nullptr);
    BOMWERK_TEST_CHECK(warnings_with_code(result, WarningCode::kUnpinnedOrUnresolvedRef) == 1);
    BOMWERK_TEST_CHECK(any_warning_contains(result, "'tracking', 'star'"));
  }

  // parse_bytes: a manifest under managed_components/ is someone else's
  // declaration, and a foreign name is not read.
  {
    const std::string manifest = "dependencies:\n  espressif/led_strip: \"^2\"\n";
    BOMWERK_TEST_CHECK(esp_idf::parse_bytes("main/idf_component.yml", manifest, {}).value.size() ==
                       1);
    BOMWERK_TEST_CHECK(
        esp_idf::parse_bytes("managed_components/espressif__x/idf_component.yml", manifest, {})
            .value.empty());
    BOMWERK_TEST_CHECK(esp_idf::parse_bytes("idf_component.yaml", manifest, {}).value.empty());
  }

  std::puts("test_esp_idf: OK");
  return 0;
}
