#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

#include "core/model.hpp"
#include "core/sbom_format.hpp"
#include "output/spdx.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::ReleaseMeta;
using bomwerk::core::SpdxVersion;
using bomwerk::output::ToolInfo;
using bomwerk::output::write_spdx;

namespace
{

// The known-answer UUIDv5 of `pkg:vcpkg/zlib@1.3.1`: the same identity
// test_cyclonedx asserts for its bom-ref. The SPDX writer must reuse it, so a
// component has one identifier across both formats.
constexpr const char* kZlibUuid = "4a33ce74-17ee-58ce-b2e0-4524c65bf3bf";

Component make_component(std::string name, std::string version, std::string purl)
{
  Component component;
  component.name = std::move(name);
  component.version = std::move(version);
  component.purl = std::move(purl);
  return component;
}

// The first SPDX 3.0.1 @graph element of a given `type` (a null json when
// absent), so a test can pull out the CreationInfo/Tool/software_Package/… it
// asserts on without depending on their order in the graph.
nlohmann::json find_element(const nlohmann::json& document, const std::string& type_name)
{
  for (const nlohmann::json& element : document.at("@graph"))
  {
    if (element.contains("type") && element["type"] == type_name)
    {
      return element;
    }
  }
  return nlohmann::json();
}

}  // namespace

int main()
{
  // ---- SPDX 3.0.1 (the default serialization) ----

  // Given a component with an optional hash, when written as SPDX 3.0.1, then
  // the document is a JSON-LD @graph under the SPDX 3.0.1 context whose
  // software_Package carries name/version/purl/hash and whose spdxId embeds the
  // same UUIDv5 identity the CycloneDX writer uses for bom-ref.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    component.cpe = "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*";
    component.sha256 = std::string(64, 'a');

    const std::string text =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V3_0);
    const nlohmann::json document = nlohmann::json::parse(text);

    BOMWERK_TEST_CHECK(document["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld");
    BOMWERK_TEST_CHECK(document["@graph"].is_array());
    BOMWERK_TEST_CHECK(find_element(document, "CreationInfo")["specVersion"] == "3.0.1");

    const nlohmann::json package = find_element(document, "software_Package");
    BOMWERK_TEST_CHECK(package["name"] == "zlib");
    BOMWERK_TEST_CHECK(package["software_packageVersion"] == "1.3.1");
    BOMWERK_TEST_CHECK(package["software_packageUrl"] == "pkg:vcpkg/zlib@1.3.1");
    BOMWERK_TEST_CHECK(package["externalIdentifier"][0]["type"] == "ExternalIdentifier");
    BOMWERK_TEST_CHECK(package["externalIdentifier"][0]["externalIdentifierType"] == "cpe23");
    BOMWERK_TEST_CHECK(package["externalIdentifier"][0]["identifier"] ==
                       "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(package["spdxId"] ==
                       std::string("https://bomwerk.dev/spdx/3.0.1/package/") + kZlibUuid);
    BOMWERK_TEST_CHECK(package["verifiedUsing"][0]["algorithm"] == "sha256");
    BOMWERK_TEST_CHECK(package["verifiedUsing"][0]["hashValue"] == std::string(64, 'a'));

    // bomwerk's version lives only in the Tool name (mirrors CycloneDX
    // metadata.tools): one place, so a golden snapshot can template it out.
    BOMWERK_TEST_CHECK(find_element(document, "Tool")["name"] == "bomwerk-0.1.0");

    const nlohmann::json relationship = find_element(document, "Relationship");
    BOMWERK_TEST_CHECK(relationship["relationshipType"] == "describes");
    BOMWERK_TEST_CHECK(relationship["to"][0] == package["spdxId"]);
  }

  // Given a component with only name and purl, when written as 3.0.1, then
  // version/hash are omitted rather than emitted empty.
  {
    Component component = make_component("libfoo", "", "pkg:generic/libfoo");
    const std::string text =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V3_0);
    const nlohmann::json package = find_element(nlohmann::json::parse(text), "software_Package");
    BOMWERK_TEST_CHECK(!package.contains("software_packageVersion"));
    BOMWERK_TEST_CHECK(!package.contains("verifiedUsing"));
    BOMWERK_TEST_CHECK(!package.contains("externalIdentifier"));
    BOMWERK_TEST_CHECK(package["software_packageUrl"] == "pkg:generic/libfoo");
  }

  // Given an empty component list, when written as 3.0.1, then the document is
  // still well-formed: an SpdxDocument with an empty rootElement and no
  // describes relationship (there is nothing to describe).
  {
    const std::string text = write_spdx({}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V3_0);
    const nlohmann::json document = nlohmann::json::parse(text);
    BOMWERK_TEST_CHECK(find_element(document, "SpdxDocument")["rootElement"].empty());
    BOMWERK_TEST_CHECK(find_element(document, "Relationship").is_null());
  }

  // ---- SPDX 2.3 ----

  // Given a component with every optional field, when written as SPDX 2.3, then
  // the flat document carries the expected package shape, the same UUIDv5
  // identity in its SPDXID, and a DESCRIBES relationship from the document.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    component.supplier = "zlib contributors";
    component.license = "Zlib";
    component.cpe = "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*";
    component.sha256 = std::string(64, 'a');

    const std::string text =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    const nlohmann::json document = nlohmann::json::parse(text);

    BOMWERK_TEST_CHECK(document["spdxVersion"] == "SPDX-2.3");
    BOMWERK_TEST_CHECK(document["dataLicense"] == "CC0-1.0");
    BOMWERK_TEST_CHECK(document["SPDXID"] == "SPDXRef-DOCUMENT");
    BOMWERK_TEST_CHECK(document["creationInfo"]["creators"][0] == "Tool: bomwerk-0.1.0");

    BOMWERK_TEST_CHECK(document["packages"].size() == 1);
    const nlohmann::json& package = document["packages"][0];
    BOMWERK_TEST_CHECK(package["SPDXID"] == std::string("SPDXRef-Package-") + kZlibUuid);
    BOMWERK_TEST_CHECK(package["name"] == "zlib");
    BOMWERK_TEST_CHECK(package["versionInfo"] == "1.3.1");
    BOMWERK_TEST_CHECK(package["downloadLocation"] == "NOASSERTION");
    BOMWERK_TEST_CHECK(package["licenseDeclared"] == "Zlib");
    BOMWERK_TEST_CHECK(package["supplier"] == "Organization: zlib contributors");
    BOMWERK_TEST_CHECK(package["checksums"][0]["algorithm"] == "SHA256");
    BOMWERK_TEST_CHECK(package["checksums"][0]["checksumValue"] == std::string(64, 'a'));
    BOMWERK_TEST_CHECK(package["externalRefs"][0]["referenceType"] == "purl");
    BOMWERK_TEST_CHECK(package["externalRefs"][0]["referenceLocator"] == "pkg:vcpkg/zlib@1.3.1");
    BOMWERK_TEST_CHECK(package["externalRefs"].size() == 2);
    BOMWERK_TEST_CHECK(package["externalRefs"][1]["referenceCategory"] == "SECURITY");
    BOMWERK_TEST_CHECK(package["externalRefs"][1]["referenceType"] == "cpe23");
    BOMWERK_TEST_CHECK(package["externalRefs"][1]["referenceLocator"] ==
                       "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*");

    const nlohmann::json& relationship = document["relationships"][0];
    BOMWERK_TEST_CHECK(relationship["spdxElementId"] == "SPDXRef-DOCUMENT");
    BOMWERK_TEST_CHECK(relationship["relationshipType"] == "DESCRIBES");
    BOMWERK_TEST_CHECK(relationship["relatedSpdxElement"] ==
                       std::string("SPDXRef-Package-") + kZlibUuid);
  }

  // Given a component with no license/supplier/hash, when written as 2.3, then
  // licenseDeclared falls back to NOASSERTION and supplier/checksums/versionInfo
  // are omitted rather than emitted empty.
  {
    Component component = make_component("libfoo", "", "pkg:generic/libfoo");
    const std::string text =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    const nlohmann::json document = nlohmann::json::parse(text);
    const nlohmann::json& package = document["packages"][0];
    BOMWERK_TEST_CHECK(package["licenseDeclared"] == "NOASSERTION");
    BOMWERK_TEST_CHECK(!package.contains("supplier"));
    BOMWERK_TEST_CHECK(!package.contains("checksums"));
    BOMWERK_TEST_CHECK(!package.contains("versionInfo"));
    BOMWERK_TEST_CHECK(package["externalRefs"].size() == 1);
  }

  // Given a component whose license is a recognized SPDX id in a different
  // case ("mit"), when written as 2.3, then licenseDeclared is normalized to
  // the list's own canonical spelling ("MIT") and no extracted-licensing-info
  // entry is added: a recognized id needs no LicenseRef- wrapper.
  {
    Component component = make_component("foo", "1.0", "pkg:generic/foo");
    component.license = "mit";
    const std::string text =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    const nlohmann::json document = nlohmann::json::parse(text);
    BOMWERK_TEST_CHECK(document["packages"][0]["licenseDeclared"] == "MIT");
    BOMWERK_TEST_CHECK(!document.contains("hasExtractedLicensingInfos"));
  }

  // Given a component whose license is free text, not a recognized SPDX id
  // ("BSD-style"), when written as 2.3, then licenseDeclared is wrapped as a
  // LicenseRef- id (never the raw text: Annex D license expression syntax,
  // not arbitrary text, is what the field holds) and the document records the
  // original text in hasExtractedLicensingInfos under that same id.
  {
    Component component = make_component("foo", "1.0", "pkg:generic/foo");
    component.license = "BSD-style";
    const std::string text =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    const nlohmann::json document = nlohmann::json::parse(text);
    const std::string ref_id = document["packages"][0]["licenseDeclared"];
    BOMWERK_TEST_CHECK(ref_id.rfind("LicenseRef-", 0) == 0);
    BOMWERK_TEST_CHECK(document["hasExtractedLicensingInfos"].size() == 1);
    const nlohmann::json& extracted = document["hasExtractedLicensingInfos"][0];
    BOMWERK_TEST_CHECK(extracted["licenseId"] == ref_id);
    BOMWERK_TEST_CHECK(extracted["extractedText"] == "BSD-style");
  }

  // Given two components sharing the same unrecognized license text, when
  // written as 2.3, then they share ONE hasExtractedLicensingInfos entry (not
  // two) and both packages reference the same LicenseRef- id.
  {
    Component first = make_component("foo", "1.0", "pkg:generic/foo");
    first.license = "Custom License";
    Component second = make_component("bar", "1.0", "pkg:generic/bar");
    second.license = "Custom License";
    const std::string text =
        write_spdx({first, second}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    const nlohmann::json document = nlohmann::json::parse(text);
    BOMWERK_TEST_CHECK(document["hasExtractedLicensingInfos"].size() == 1);
    BOMWERK_TEST_CHECK(document["packages"][0]["licenseDeclared"] ==
                       document["packages"][1]["licenseDeclared"]);
  }

  // Given components with two distinct unrecognized license texts, when
  // written as 2.3 in either order, then LicenseRef- ids are assigned by
  // sorted license text (not component order): so the mapping, and therefore
  // the whole document, is independent of caller-supplied ordering (rule 3).
  {
    Component alpha = make_component("alpha", "1.0", "pkg:generic/alpha");
    alpha.license = "Zeta Custom";
    Component beta = make_component("beta", "1.0", "pkg:generic/beta");
    beta.license = "Alpha Custom";
    const std::string forward =
        write_spdx({alpha, beta}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    const std::string reversed =
        write_spdx({beta, alpha}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3);
    BOMWERK_TEST_CHECK(forward == reversed);
    const nlohmann::json document = nlohmann::json::parse(forward);
    // "Alpha Custom" sorts before "Zeta Custom" lexicographically, so it gets
    // LicenseRef-declared-1 regardless of which component carried it first.
    BOMWERK_TEST_CHECK(document["hasExtractedLicensingInfos"][0]["extractedText"] ==
                       "Alpha Custom");
    BOMWERK_TEST_CHECK(document["hasExtractedLicensingInfos"][0]["licenseId"] ==
                       "LicenseRef-declared-1");
  }

  // ---- Shared behavior across both serializations ----

  // Given a product identity (ReleaseMeta), when written, then it becomes the
  // document name in both serializations.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    const std::string spdx3 =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V3_0, release_meta);
    const std::string spdx2 =
        write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3, release_meta);
    BOMWERK_TEST_CHECK(find_element(nlohmann::json::parse(spdx3), "SpdxDocument")["name"] ==
                       "widget-firmware");
    BOMWERK_TEST_CHECK(nlohmann::json::parse(spdx2)["name"] == "widget-firmware");
  }

  // Given the same components in a different vector order, when written, then
  // the full output is byte-identical either way, for both serializations :
  // rule 3, SOURCE_DATE_EPOCH pinned so the timestamp cannot differ.
  {
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    Component zlib_component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    Component fmt_component = make_component("fmt", "", "pkg:vcpkg/fmt");
    for (const SpdxVersion version : {SpdxVersion::V2_3, SpdxVersion::V3_0})
    {
      const std::string forward =
          write_spdx({zlib_component, fmt_component}, ToolInfo{"bomwerk", "0.1.0"}, version);
      const std::string reversed =
          write_spdx({fmt_component, zlib_component}, ToolInfo{"bomwerk", "0.1.0"}, version);
      BOMWERK_TEST_CHECK(forward == reversed);
    }
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given a component field with invalid UTF-8 (hostile evidence), when
  // written, then both serializations still parse as valid JSON rather than
  // throwing across the module boundary (rule 1).
  {
    Component component = make_component("weird", "1.0", "pkg:generic/weird");
    component.license = std::string("bad-\xff-utf8");
    for (const SpdxVersion version : {SpdxVersion::V2_3, SpdxVersion::V3_0})
    {
      const std::string text = write_spdx({component}, ToolInfo{"bomwerk", "0.1.0"}, version);
      const nlohmann::json document = nlohmann::json::parse(text);  // must not throw
      BOMWERK_TEST_CHECK(document.is_object());
    }
  }

  // Side effect for the two schema-validation ctests: a representative
  // multi-component document per version, written so validate_spdx_schema.py
  // has something to check against the vendored official schemas. Includes an
  // unrecognized license so the 2.3 fixture structurally exercises the
  // LicenseRef-/hasExtractedLicensingInfos path against the real schema, not
  // just the recognized-id path.
  {
    Component with_everything = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    with_everything.supplier = "zlib contributors";
    with_everything.license = "Zlib";
    with_everything.cpe = "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*";
    with_everything.sha256 = std::string(64, 'a');
    Component minimal = make_component("libfoo", "", "pkg:generic/libfoo");
    Component custom_licensed = make_component("customware", "1.0", "pkg:generic/customware");
    custom_licensed.license = "Acme Proprietary License";
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    release_meta.version = "2.4.1";
    const std::vector<Component> components{with_everything, minimal, custom_licensed};

    const auto write_fixture = [](const char* path, const std::string& document)
    {
      const fs::path fixture_path(path);
      fs::create_directories(fixture_path.parent_path());
      std::ofstream fixture_stream(fixture_path, std::ios::binary);
      fixture_stream << document;
      BOMWERK_TEST_CHECK(static_cast<bool>(fixture_stream));
    };
    write_fixture(
        BOMWERK_SPDX_2_3_FIXTURE_PATH,
        write_spdx(components, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V2_3, release_meta));
    write_fixture(
        BOMWERK_SPDX_3_0_FIXTURE_PATH,
        write_spdx(components, ToolInfo{"bomwerk", "0.1.0"}, SpdxVersion::V3_0, release_meta));
  }

  std::puts("test_spdx: OK");
  return 0;
}
