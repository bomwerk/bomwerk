#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

#include "core/model.hpp"
#include "output/cyclonedx.hpp"
#include "support/check.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::CpeProvenance;
using bomwerk::core::CraMetadata;
using bomwerk::core::ReleaseMeta;
using bomwerk::core::Scope;
using bomwerk::output::ToolInfo;
using bomwerk::output::write_cyclonedx;

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
  // Given a component with every optional field populated, when written,
  // then all BSI TR-03183-required fields appear with the expected shapes,
  // and bom-ref/dependencies match the known-answer UUIDv5 from test_uuid.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    component.supplier = "zlib contributors";
    component.license = "Zlib";
    component.cpe = "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*";
    component.sha256 = std::string(64, 'a');

    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);

    BOMWERK_TEST_CHECK(bom["bomFormat"] == "CycloneDX");
    BOMWERK_TEST_CHECK(bom["specVersion"] == "1.6");
    BOMWERK_TEST_CHECK(bom["components"].size() == 1);
    const nlohmann::json& emitted = bom["components"][0];
    BOMWERK_TEST_CHECK(emitted["type"] == "library");
    BOMWERK_TEST_CHECK(emitted["name"] == "zlib");
    BOMWERK_TEST_CHECK(emitted["version"] == "1.3.1");
    BOMWERK_TEST_CHECK(emitted["purl"] == "pkg:vcpkg/zlib@1.3.1");
    BOMWERK_TEST_CHECK(emitted["cpe"] == "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(emitted["supplier"]["name"] == "zlib contributors");
    BOMWERK_TEST_CHECK(emitted["licenses"][0]["license"]["name"] == "Zlib");
    BOMWERK_TEST_CHECK(emitted["hashes"][0]["alg"] == "SHA-256");
    BOMWERK_TEST_CHECK(emitted["hashes"][0]["content"] == std::string(64, 'a'));
    BOMWERK_TEST_CHECK(emitted["bom-ref"] == "4a33ce74-17ee-58ce-b2e0-4524c65bf3bf");
    BOMWERK_TEST_CHECK(bom["dependencies"][0]["ref"] == "4a33ce74-17ee-58ce-b2e0-4524c65bf3bf");
  }

  // Given a component with only name and purl set, when written, then every
  // optional field (version/supplier/hashes/licenses) is omitted rather than
  // emitted empty.
  {
    Component component = make_component("libfoo", "", "pkg:generic/libfoo");
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    const nlohmann::json& emitted = bom["components"][0];
    BOMWERK_TEST_CHECK(!emitted.contains("version"));
    BOMWERK_TEST_CHECK(!emitted.contains("supplier"));
    BOMWERK_TEST_CHECK(!emitted.contains("hashes"));
    BOMWERK_TEST_CHECK(!emitted.contains("licenses"));
    BOMWERK_TEST_CHECK(!emitted.contains("cpe"));
  }

  // Given a component with the default Required scope, when written, then no
  // `scope` field is emitted: absent means "required" per the CycloneDX
  // schema default, and omission keeps pre-scope snapshots byte-identical
  // (rule 3).
  {
    Component component = make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["components"][0].contains("scope"));
  }

  // Given a dev-only component (Scope::Excluded) beside an Optional one, when
  // written, then each emits its exact CycloneDX scope token.
  {
    Component dev_component = make_component("typescript", "5.4.5", "pkg:npm/typescript@5.4.5");
    dev_component.scope = Scope::Excluded;
    Component optional_component = make_component("fsevents", "2.3.3", "pkg:npm/fsevents@2.3.3");
    optional_component.scope = Scope::Optional;
    const std::string document =
        write_cyclonedx({dev_component, optional_component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    // Components are identity-sorted: pkg:npm/fsevents… precedes pkg:npm/typescript….
    BOMWERK_TEST_CHECK(bom["components"][0]["scope"] == "optional");
    BOMWERK_TEST_CHECK(bom["components"][1]["scope"] == "excluded");
  }

  // Given a component whose sha256 is present but not a well-formed 64-hex
  // digest (hostile/partial evidence), when written, then it is left out of
  // `hashes` rather than emitted invalid (would fail the schema's
  // hash-content pattern).
  {
    Component component = make_component("bar", "1.0", "pkg:generic/bar");
    component.sha256 = "not-a-hash";
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["components"][0].contains("hashes"));
  }

  // Given two components with no purl (heuristic evidence, not yet
  // identified), when written, then bom-ref falls back to name@version and
  // the two distinct components do not collide on the same identifier.
  {
    Component first = make_component("vendored-thing", "2.0", "");
    Component second = make_component("other-thing", "3.0", "");
    const std::string document = write_cyclonedx({first, second}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["components"][0]["bom-ref"].get<std::string>().empty());
    BOMWERK_TEST_CHECK(!bom["components"][0].contains("purl"));
    BOMWERK_TEST_CHECK(bom["components"][0]["bom-ref"] != bom["components"][1]["bom-ref"]);
  }

  // Given an empty component list, when written, then the document is still
  // schema-shaped: empty (not absent) components/dependencies arrays.
  {
    const std::string document = write_cyclonedx({}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["components"].empty());
    BOMWERK_TEST_CHECK(bom["dependencies"].empty());
  }

  // Given two runs over the identical component list, when compared, then
  // serialNumber, every bom-ref, and the full byte content are identical :
  // rule 3's two-runs-byte-identical guarantee (SOURCE_DATE_EPOCH pinned so
  // the timestamp field cannot differ between the two calls).
  {
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    const std::string first = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const std::string second = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    BOMWERK_TEST_CHECK(first == second);
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given the same components in a different vector order, when written,
  // then the full output is byte-identical either way: the document's
  // identity (including components/dependencies array order) does not
  // depend on caller-supplied ordering.
  {
    setenv("SOURCE_DATE_EPOCH", "1700000000", 1);
    Component zlib_component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    Component fmt_component = make_component("fmt", "", "pkg:vcpkg/fmt");
    const std::string forward =
        write_cyclonedx({zlib_component, fmt_component}, ToolInfo{"bomwerk", "0.1.0"});
    const std::string reversed =
        write_cyclonedx({fmt_component, zlib_component}, ToolInfo{"bomwerk", "0.1.0"});
    BOMWERK_TEST_CHECK(forward == reversed);
    unsetenv("SOURCE_DATE_EPOCH");
  }

  // Given a component whose license text contains invalid UTF-8 (hostile
  // evidence: e.g. a LICENSE file read with the wrong encoding), when
  // written, then the document still parses as valid JSON rather than
  // throwing across the module boundary (rule 1).
  {
    Component component = make_component("weird", "1.0", "pkg:generic/weird");
    component.license = std::string("bad-\xff-utf8");
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);  // must not throw
    BOMWERK_TEST_CHECK(bom.is_object());
  }

  // Given no ReleaseMeta (the default), when written, then metadata.component
  // is omitted entirely: no product identity was supplied to record.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["metadata"].contains("component"));
  }

  // Given a ReleaseMeta with product_id and version set, when written, then
  // metadata.component records the product this BOM describes, distinct from
  // metadata.tools (which records bomwerk itself).
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    release_meta.version = "2.4.1";
    const std::string document =
        write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"}, release_meta);
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["metadata"]["component"]["type"] == "application");
    BOMWERK_TEST_CHECK(bom["metadata"]["component"]["name"] == "widget-firmware");
    BOMWERK_TEST_CHECK(bom["metadata"]["component"]["version"] == "2.4.1");
  }

  // Given a ReleaseMeta with product_id set but version empty, when written,
  // then metadata.component omits version rather than emitting it empty.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    const std::string document =
        write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"}, release_meta);
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["metadata"]["component"]["name"] == "widget-firmware");
    BOMWERK_TEST_CHECK(!bom["metadata"]["component"].contains("version"));
  }

  // Given a product, when written, then metadata.component carries its
  // own bom-ref and a synthetic pkg:generic purl -- sbom-tools checks the
  // primary component against the same identifier rule as every dependency,
  // so it can no longer be left bare -- and a root dependencies[] entry lists
  // every component as the product's dependsOn, on top of (not instead of)
  // each component's own childless entry.
  {
    Component first = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    Component second = make_component("fmt", "10.2.1", "pkg:github/fmtlib/fmt@10.2.1");
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    release_meta.version = "2.4.1";
    const std::string document =
        write_cyclonedx({first, second}, ToolInfo{"bomwerk", "0.1.0"}, release_meta);
    const nlohmann::json bom = nlohmann::json::parse(document);
    const std::string product_bom_ref = bom["metadata"]["component"]["bom-ref"];
    BOMWERK_TEST_CHECK(!product_bom_ref.empty());
    BOMWERK_TEST_CHECK(bom["metadata"]["component"]["purl"] == "pkg:generic/widget-firmware@2.4.1");
    // No [cra] manufacturer configured: no supplier invented for the product.
    BOMWERK_TEST_CHECK(!bom["metadata"]["component"].contains("supplier"));
    BOMWERK_TEST_CHECK(bom["dependencies"].size() == 3);  // root + 2 components
    const nlohmann::json& root_entry = bom["dependencies"][0];
    BOMWERK_TEST_CHECK(root_entry["ref"] == product_bom_ref);
    BOMWERK_TEST_CHECK(root_entry["dependsOn"].size() == 2);
    // Purl-sorted identity order (fmt before zlib), same order components[]
    // and every other bomwerk-out document already uses.
    BOMWERK_TEST_CHECK(root_entry["dependsOn"][0] == bom["components"][0]["bom-ref"]);
    BOMWERK_TEST_CHECK(root_entry["dependsOn"][1] == bom["components"][1]["bom-ref"]);
    // The two per-component entries are unchanged: still childless.
    BOMWERK_TEST_CHECK(bom["dependencies"][1].contains("ref"));
    BOMWERK_TEST_CHECK(!bom["dependencies"][1].contains("dependsOn"));
  }

  // Given no product at all, when written, then there is no root to
  // anchor a dependency edge at, and every component's own entry stays
  // exactly as before -- a plain scan's bytes are unaffected by this feature.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["dependencies"].size() == 1);
    BOMWERK_TEST_CHECK(!bom["dependencies"][0].contains("dependsOn"));
  }

  // Given a [cra] manufacturer configured alongside a product, when
  // written, then metadata.manufacturer carries the name and contact email,
  // and metadata.component.supplier matches it -- sbom-tools checks the
  // primary component's OWN supplier field, not just the document-level
  // manufacturer, so both must carry it.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    release_meta.version = "2.4.1";
    CraMetadata cra_metadata;
    cra_metadata.manufacturer_name = "Acme Corp";
    cra_metadata.manufacturer_email = "legal@acme.example";
    const std::string document =
        write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"}, release_meta, cra_metadata);
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["metadata"]["manufacturer"]["name"] == "Acme Corp");
    BOMWERK_TEST_CHECK(bom["metadata"]["manufacturer"]["contact"][0]["email"] ==
                       "legal@acme.example");
    BOMWERK_TEST_CHECK(bom["metadata"]["component"]["supplier"]["name"] == "Acme Corp");
  }

  // Given a [cra] manufacturer name but no email, when written, then
  // metadata.manufacturer omits contact entirely rather than emitting an
  // empty one.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    CraMetadata cra_metadata;
    cra_metadata.manufacturer_name = "Acme Corp";
    const std::string document =
        write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"}, ReleaseMeta{}, cra_metadata);
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["metadata"]["manufacturer"]["name"] == "Acme Corp");
    BOMWERK_TEST_CHECK(!bom["metadata"]["manufacturer"].contains("contact"));
  }

  // Given no [cra] table at all, when written, then metadata.manufacturer
  // is absent entirely -- a plain scan's bytes are unaffected.
  {
    Component component = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["metadata"].contains("manufacturer"));
  }

  // Given a matched and an unmapped-purl-type component together, when
  // written, then only the unmapped one carries a `bomwerk:match-coverage`
  // property: a matched component's bytes are untouched, same
  // precedent as `scope` above: and metadata.properties carries the
  // BOM-level summary, name-sorted, always present regardless of what was
  // found.
  {
    Component matched_component = make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");
    Component unmapped_component = make_component("openssl", "3.2.0", "pkg:conan/openssl@3.2.0");
    const std::string document =
        write_cyclonedx({matched_component, unmapped_component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    // Identity-sorted: pkg:conan/openssl… precedes pkg:npm/left-pad….
    const nlohmann::json& conan_entry = bom["components"][0];
    const nlohmann::json& npm_entry = bom["components"][1];
    BOMWERK_TEST_CHECK(!npm_entry.contains("properties"));
    BOMWERK_TEST_CHECK(conan_entry["properties"].size() == 1);
    BOMWERK_TEST_CHECK(conan_entry["properties"][0]["name"] == "bomwerk:match-coverage");
    BOMWERK_TEST_CHECK(conan_entry["properties"][0]["value"] == "unmapped-purl-type");

    const nlohmann::json& metadata_properties = bom["metadata"]["properties"];
    BOMWERK_TEST_CHECK(metadata_properties.size() == 6);
    BOMWERK_TEST_CHECK(metadata_properties[0]["name"] == "bomwerk:coverage:components");
    BOMWERK_TEST_CHECK(metadata_properties[0]["value"] == "2");
    BOMWERK_TEST_CHECK(metadata_properties[1]["name"] == "bomwerk:coverage:matchable");
    BOMWERK_TEST_CHECK(metadata_properties[1]["value"] == "1");
    BOMWERK_TEST_CHECK(metadata_properties[2]["name"] == "bomwerk:coverage:no-identifier");
    BOMWERK_TEST_CHECK(metadata_properties[2]["value"] == "0");
    BOMWERK_TEST_CHECK(metadata_properties[3]["name"] == "bomwerk:coverage:unmapped-purl-type");
    BOMWERK_TEST_CHECK(metadata_properties[3]["value"] == "1");
    BOMWERK_TEST_CHECK(metadata_properties[4]["name"] == "bomwerk:coverage:unmatched");
    BOMWERK_TEST_CHECK(metadata_properties[4]["value"] == "1");
    BOMWERK_TEST_CHECK(metadata_properties[5]["name"] == "bomwerk:coverage:unversioned-purl");
    BOMWERK_TEST_CHECK(metadata_properties[5]["value"] == "0");
  }

  // --all-cpes: given a component whose cpe carries SynthesizedWildcardVendor
  // provenance and is ALSO unmapped-purl-type, when written, then properties
  // carries both entries in the fixed order (coverage first, provenance
  // second, per output/cyclonedx.hpp): insertion order is the emitted order,
  // since nlohmann sorts object keys, not array elements.
  {
    Component component = make_component("openssl", "3.2.0", "pkg:conan/openssl@3.2.0");
    component.cpe = "cpe:2.3:a:*:openssl:3.2.0:*:*:*:*:*:*:*";
    component.cpe_provenance = CpeProvenance::SynthesizedWildcardVendor;

    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    const nlohmann::json& properties = bom["components"][0]["properties"];
    BOMWERK_TEST_CHECK(properties.size() == 2);
    BOMWERK_TEST_CHECK(properties[0]["name"] == "bomwerk:match-coverage");
    BOMWERK_TEST_CHECK(properties[0]["value"] == "unmapped-purl-type");
    BOMWERK_TEST_CHECK(properties[1]["name"] == "bomwerk:cpe-provenance");
    BOMWERK_TEST_CHECK(properties[1]["value"] == "wildcard-vendor-guess");
  }

  // --all-cpes: given a MATCHED component (so no coverage property) whose cpe
  // still carries SynthesizedWildcardVendor provenance (the npm/Go case
  // --all-cpes newly covers), when written, then properties carries only the
  // provenance entry: a matched component gains a properties array for the
  // first time only because of this new provenance marker.
  {
    Component component = make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");
    component.cpe = "cpe:2.3:a:*:left-pad:1.3.0:*:*:*:*:*:*:*";
    component.cpe_provenance = CpeProvenance::SynthesizedWildcardVendor;

    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    const nlohmann::json& properties = bom["components"][0]["properties"];
    BOMWERK_TEST_CHECK(properties.size() == 1);
    BOMWERK_TEST_CHECK(properties[0]["name"] == "bomwerk:cpe-provenance");
    BOMWERK_TEST_CHECK(properties[0]["value"] == "wildcard-vendor-guess");
  }

  // Given a MATCHED component (so no coverage property of its own) with a
  // non-empty cpe but Unspecified provenance (a plain scan's default-scope
  // synthesis, or an upstream-sourced identifier), when written, then
  // properties is absent entirely: a plain scan's bytes stay exactly what
  // they were before --all-cpes existed. (An unmapped-purl-type component
  // would already carry a match-coverage property regardless of provenance,
  // which would not isolate what this case is testing.)
  {
    Component component = make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0");
    component.cpe = "cpe:2.3:a:*:left-pad:1.3.0:*:*:*:*:*:*:*";
    BOMWERK_TEST_CHECK(component.cpe_provenance == CpeProvenance::Unspecified);

    const std::string document = write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["components"][0].contains("properties"));
  }

  // Given an empty component list, when written, then metadata.properties
  // still carries the summary: all-zero counts, never omitted.
  {
    const std::string document = write_cyclonedx({}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(bom["metadata"]["properties"][0]["name"] == "bomwerk:coverage:components");
    BOMWERK_TEST_CHECK(bom["metadata"]["properties"][0]["value"] == "0");
  }

  // Given a component that records where it lives in the scanned tree,
  // when written, then that location is carried in CycloneDX's own
  // evidence.occurrences field. This is what lets `bomwerk trim` map a build
  // trace onto an SBOM it did not itself produce: without it a component read
  // back off disk has no root, and every one of them reports as unused.
  {
    Component vendored = make_component("zlib", "1.2.11", "pkg:generic/zlib@1.2.11");
    vendored.root = "third_party/zlib";
    const std::string document = write_cyclonedx({vendored}, ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    const nlohmann::json& occurrences = bom["components"][0]["evidence"]["occurrences"];
    BOMWERK_TEST_CHECK(occurrences.is_array());
    BOMWERK_TEST_CHECK(occurrences.size() == 1);
    BOMWERK_TEST_CHECK(occurrences[0]["location"] == "third_party/zlib");
  }

  // Given a component with no location: every lockfile component, which
  // is most of them: when written, then no `evidence` key appears at all, so
  // a plain scan's bytes are unchanged for it. Same precedent as `scope` and
  // the coverage property: a field is emitted only when it carries something.
  {
    const std::string document =
        write_cyclonedx({make_component("left-pad", "1.3.0", "pkg:npm/left-pad@1.3.0")},
                        ToolInfo{"bomwerk", "0.1.0"});
    const nlohmann::json bom = nlohmann::json::parse(document);
    BOMWERK_TEST_CHECK(!bom["components"][0].contains("evidence"));
  }

  // Side effect for the schema-validation ctest (BOMWERK_SCHEMA_FIXTURE_PATH,
  // set by CMakeLists.txt in Task 4): a representative multi-component
  // document, written once so `scripts/validate_cyclonedx_schema.py` has
  // something to validate against the vendored official schema.
  {
    Component with_everything = make_component("zlib", "1.3.1", "pkg:vcpkg/zlib@1.3.1");
    with_everything.supplier = "zlib contributors";
    with_everything.license = "Zlib";
    with_everything.cpe = "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*";
    with_everything.sha256 = std::string(64, 'a');
    Component minimal = make_component("libfoo", "", "pkg:generic/libfoo");
    // A rooted component, so `validate_cyclonedx_schema.py` checks our
    // evidence.occurrences emission against the OFFICIAL schema rather than
    // only against the assertions above: a shape can be self-consistent and
    // still not be CycloneDX.
    Component vendored = make_component("miniz", "3.0.2", "pkg:generic/miniz@3.0.2");
    vendored.root = "third_party/miniz";
    // A dev-only component so the official schema validates our `scope`
    // emission (enum required/optional/excluded): not just our own asserts.
    Component dev_only = make_component("typescript", "5.4.5", "pkg:npm/typescript@5.4.5");
    dev_only.scope = Scope::Excluded;
    ReleaseMeta release_meta;
    release_meta.product_id = "widget-firmware";
    release_meta.version = "2.4.1";
    const std::string document = write_cyclonedx({with_everything, minimal, dev_only, vendored},
                                                 ToolInfo{"bomwerk", "0.1.0"}, release_meta);

    const fs::path fixture_path(BOMWERK_SCHEMA_FIXTURE_PATH);
    fs::create_directories(fixture_path.parent_path());
    std::ofstream fixture_stream(fixture_path, std::ios::binary);
    fixture_stream << document;
    BOMWERK_TEST_CHECK(static_cast<bool>(fixture_stream));
  }

  std::puts("test_cyclonedx: OK");
  return 0;
}
