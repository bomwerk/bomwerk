#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <nlohmann/json.hpp>
#include <string>

#include "core/model.hpp"
#include "output/cra_sidecar.hpp"
#include "support/check.hpp"

using bomwerk::core::CraMetadata;
using bomwerk::core::ReleaseMeta;
using bomwerk::output::cra_sidecar_path_for;
using bomwerk::output::has_cra_sidecar_content;
using bomwerk::output::write_cra_sidecar;

int main()
{
  // Given a release and CRA metadata with every field set, when written, then
  // every field lands under the exact camelCase key the consumer's
  // deny_unknown_fields schema expects, and the support date is widened to a
  // full RFC-3339 datetime.
  {
    ReleaseMeta release_meta;
    release_meta.product_id = "gateway-fw";
    release_meta.version = "2.3.0";
    release_meta.support_until = "2028-01-01";

    CraMetadata cra_metadata;
    cra_metadata.manufacturer_name = "Acme Corp";
    cra_metadata.manufacturer_email = "legal@acme.example";
    cra_metadata.security_contact = "security@acme.example";
    cra_metadata.vulnerability_disclosure_url = "https://acme.example/security";

    BOMWERK_TEST_CHECK(has_cra_sidecar_content(release_meta, cra_metadata));
    const std::string document = write_cra_sidecar(release_meta, cra_metadata);
    const nlohmann::json parsed = nlohmann::json::parse(document);

    BOMWERK_TEST_CHECK(parsed["productName"] == "gateway-fw");
    BOMWERK_TEST_CHECK(parsed["productVersion"] == "2.3.0");
    BOMWERK_TEST_CHECK(parsed["supportEndDate"] == "2028-01-01T00:00:00Z");
    BOMWERK_TEST_CHECK(parsed["manufacturerName"] == "Acme Corp");
    BOMWERK_TEST_CHECK(parsed["manufacturerEmail"] == "legal@acme.example");
    BOMWERK_TEST_CHECK(parsed["securityContact"] == "security@acme.example");
    BOMWERK_TEST_CHECK(parsed["vulnerabilityDisclosureUrl"] == "https://acme.example/security");
    // deny_unknown_fields on the consumer side: no field beyond these seven.
    BOMWERK_TEST_CHECK(parsed.size() == 7);
  }

  // Given a support date that is already a full datetime, when written, then
  // it passes through unchanged rather than being widened a second time.
  {
    ReleaseMeta release_meta;
    release_meta.support_until = "2028-01-01T12:30:00Z";
    const std::string document = write_cra_sidecar(release_meta, CraMetadata{});
    const nlohmann::json parsed = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(parsed["supportEndDate"] == "2028-01-01T12:30:00Z");
  }

  // Given no product id, when written, then productVersion is never emitted
  // on its own: same "version without a name is meaningless" convention
  // write_cyclonedx's metadata.component already applies.
  {
    ReleaseMeta release_meta;
    release_meta.version = "2.3.0";
    const std::string document = write_cra_sidecar(release_meta, CraMetadata{});
    const nlohmann::json parsed = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!parsed.contains("productName"));
    BOMWERK_TEST_CHECK(!parsed.contains("productVersion"));
  }

  // Given a completely empty release and CRA metadata, when checked, then
  // there is nothing worth writing a sidecar for: the caller's signal to
  // skip the file entirely rather than emit a pointless "{}" document.
  {
    BOMWERK_TEST_CHECK(!has_cra_sidecar_content(ReleaseMeta{}, CraMetadata{}));
    const std::string document = write_cra_sidecar(ReleaseMeta{}, CraMetadata{});
    BOMWERK_TEST_CHECK(document == "{}");
  }

  // Given a CycloneDX output path, when the sidecar path is derived, then it
  // strips both the .json extension and the .cdx format suffix, landing at
  // the short canonical form next to the SBOM.
  {
    BOMWERK_TEST_CHECK(cra_sidecar_path_for("sbom.cdx.json") ==
                       std::filesystem::path("sbom.cra.json"));
    BOMWERK_TEST_CHECK(cra_sidecar_path_for("out/report.spdx.json") ==
                       std::filesystem::path("out/report.cra.json"));
    // No known format suffix to strip: only the .json extension goes.
    BOMWERK_TEST_CHECK(cra_sidecar_path_for("bom.json") == std::filesystem::path("bom.cra.json"));
    // No extension at all: the whole name is the stem.
    BOMWERK_TEST_CHECK(cra_sidecar_path_for("sbom") == std::filesystem::path("sbom.cra.json"));
  }

  std::puts("test_cra_sidecar: OK");
  return 0;
}
