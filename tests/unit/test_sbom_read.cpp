// ctest unit test for the SBOM reader (sbom/read.hpp): the inverse of
// output::write_cyclonedx, so a consumer can load a product's
// already-generated SBOM back into core::Component form.
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "output/cyclonedx.hpp"
#include "output/tool_info.hpp"
#include "sbom/format.hpp"
#include "sbom/read.hpp"
#include "support/check.hpp"
#include "support/temp_tree.hpp"

namespace fs = std::filesystem;

using bomwerk::core::Component;
using bomwerk::core::CpeProvenance;
using bomwerk::core::Result;
using bomwerk::core::Scope;
using bomwerk::output::ToolInfo;
using bomwerk::output::write_cyclonedx;
using bomwerk::sbom::detect_sbom_format;
using bomwerk::sbom::load_sbom_file;
using bomwerk::sbom::read_cyclonedx;
using bomwerk::sbom::SbomDocument;
using bomwerk::sbom::SbomInputFormat;
using bomwerk::test::TempTree;
namespace core = bomwerk::core;

namespace
{

/// True when any warning mentions `needle`: warning wording may evolve, the
/// subject named in it must not (same convention as test_scan_config.cpp).
bool warnings_mention(const std::vector<core::Warning>& warnings, const std::string& needle)
{
  for (const core::Warning& warning : warnings)
  {
    if (warning.message.find(needle) != std::string::npos)
    {
      return true;
    }
  }
  return false;
}

const Component* find_by_purl(const std::vector<Component>& components, const std::string& purl)
{
  for (const Component& component : components)
  {
    if (component.purl == purl)
    {
      return &component;
    }
  }
  return nullptr;
}

}  // namespace

int main()
{
  // Given a component with every optional field populated, when written by
  // output::write_cyclonedx and read back, then every field round-trips.
  {
    Component original;
    original.name = "zlib";
    original.version = "1.3.1";
    original.purl = "pkg:vcpkg/zlib@1.3.1";
    original.cpe = "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*";
    original.supplier = "zlib contributors";
    original.license = "Zlib";
    original.sha256 = std::string(64, 'a');
    original.scope = Scope::Optional;

    const std::string document = write_cyclonedx({original}, ToolInfo{"bomwerk", "0.1.0"});
    const Result<SbomDocument> read = read_cyclonedx(document);

    BOMWERK_TEST_CHECK(read.complete);
    BOMWERK_TEST_CHECK(read.warnings.empty());
    BOMWERK_TEST_CHECK(read.value.components.size() == 1);
    const Component& round_tripped = read.value.components.front();
    BOMWERK_TEST_CHECK(round_tripped.name == "zlib");
    BOMWERK_TEST_CHECK(round_tripped.version == "1.3.1");
    BOMWERK_TEST_CHECK(round_tripped.purl == "pkg:vcpkg/zlib@1.3.1");
    BOMWERK_TEST_CHECK(round_tripped.cpe == "cpe:2.3:a:*:zlib:1.3.1:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(round_tripped.supplier == "zlib contributors");
    BOMWERK_TEST_CHECK(round_tripped.license == "Zlib");
    BOMWERK_TEST_CHECK(round_tripped.sha256 == std::string(64, 'a'));
    BOMWERK_TEST_CHECK(round_tripped.scope == Scope::Optional);
    BOMWERK_TEST_CHECK(!round_tripped.evidence.empty());  // "SBOM input" evidence recorded
  }

  // Given a component with only name and purl set, when written and read
  // back, then the omitted optional fields stay empty/default rather than
  // becoming, say, the literal string "null".
  {
    Component original;
    original.name = "libfoo";
    original.purl = "pkg:generic/libfoo";
    const std::string document = write_cyclonedx({original}, ToolInfo{"bomwerk", "0.1.0"});
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.size() == 1);
    const Component& round_tripped = read.value.components.front();
    BOMWERK_TEST_CHECK(round_tripped.version.empty());
    BOMWERK_TEST_CHECK(round_tripped.supplier.empty());
    BOMWERK_TEST_CHECK(round_tripped.sha256.empty());
    BOMWERK_TEST_CHECK(round_tripped.license.empty());
    BOMWERK_TEST_CHECK(round_tripped.cpe.empty());
    BOMWERK_TEST_CHECK(round_tripped.scope == Scope::Required);
  }

  // Given a document naming a product and manufacturer, when read, then the
  // document-level identity/contact fields land on SbomDocument, not on any
  // dependency component. A reader consumes the same metadata the writer emitted.
  {
    Component component;
    component.name = "left-pad";
    component.purl = "pkg:npm/left-pad@1.3.0";
    bomwerk::core::ReleaseMeta release_meta;
    release_meta.product_id = "acme-firmware";
    release_meta.version = "2.4.0";
    bomwerk::core::CraMetadata cra_metadata;
    cra_metadata.manufacturer_name = "Acme Devices S.L.";
    cra_metadata.manufacturer_email = "security@acme.example";
    const std::string document =
        write_cyclonedx({component}, ToolInfo{"bomwerk", "0.1.0"}, release_meta, cra_metadata);
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.product_id == "acme-firmware");
    BOMWERK_TEST_CHECK(read.value.product_version == "2.4.0");
    BOMWERK_TEST_CHECK(read.value.manufacturer_name == "Acme Devices S.L.");
    BOMWERK_TEST_CHECK(read.value.manufacturer_email == "security@acme.example");
    BOMWERK_TEST_CHECK(!read.value.generated_timestamp.empty());
    BOMWERK_TEST_CHECK(!read.value.serial_number.empty());
  }

  // Given hostile/wrong-typed manufacturer metadata, when read, then it stays
  // absent without crashing or becoming a literal JSON value.
  {
    const Result<SbomDocument> read = read_cyclonedx(
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","metadata":)"
        R"({"manufacturer":{"name":42,"contact":[false,{"email":7}]}},"components":[]})");
    BOMWERK_TEST_CHECK(read.value.manufacturer_name.empty());
    BOMWERK_TEST_CHECK(read.value.manufacturer_email.empty());
    BOMWERK_TEST_CHECK(read.warnings.empty());
  }

  // Given two components that share an identity (same purl), when read back,
  // then they merge into one: the reader's output obeys the same
  // core::merge_all identity rule every producer's does (rule 3).
  {
    const std::string document =
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
        R"({"type":"library","name":"a","purl":"pkg:npm/a@1.0.0"},)"
        R"({"type":"library","name":"a","purl":"pkg:npm/a@1.0.0","version":"1.0.0"}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.size() == 1);
    BOMWERK_TEST_CHECK(read.value.components.front().version == "1.0.0");
  }

  // Given a hash entry whose alg is not SHA-256, when read, then sha256
  // stays empty rather than picking up an unrelated digest.
  {
    const std::string document = R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
                                 R"({"type":"library","name":"a","purl":"pkg:npm/a@1.0.0",)"
                                 R"("hashes":[{"alg":"SHA-1","content":"deadbeef"}]}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.front().sha256.empty());
  }

  // Given a SHA-256-labeled hash whose content is not a well-formed 64-hex
  // digest (wrong length, non-hex characters: a hand-edited or hostile
  // document), when read, then sha256 stays empty rather than storing a
  // value output::write_cyclonedx itself would never have emitted.
  {
    const std::string document =
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
        R"({"type":"library","name":"a","purl":"pkg:npm/a@1.0.0",)"
        R"("hashes":[{"alg":"SHA-256","content":"not-hex-and-too-short"}]}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.front().sha256.empty());
  }

  // Given scope values "optional" and "excluded", when read, then each maps
  // to its enumerator; an absent scope stays Required.
  {
    const std::string document =
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
        R"({"type":"library","name":"a","purl":"pkg:npm/a@1","scope":"optional"},)"
        R"({"type":"library","name":"b","purl":"pkg:npm/b@1","scope":"excluded"}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.size() == 2);
    const Component* optional_component = find_by_purl(read.value.components, "pkg:npm/a@1");
    const Component* excluded_component = find_by_purl(read.value.components, "pkg:npm/b@1");
    BOMWERK_TEST_CHECK(optional_component != nullptr &&
                       optional_component->scope == Scope::Optional);
    BOMWERK_TEST_CHECK(excluded_component != nullptr &&
                       excluded_component->scope == Scope::Excluded);
  }

  // Given an unrecognized, non-empty scope value (a typo, or a future spec
  // value bomwerk does not know yet), when read, then the component stays
  // Required (the least restrictive value) but a warning names the value :
  // silently downgrading "excluded" to "required" on a typo must never be
  // quiet (rule 1's spirit).
  {
    const std::string document =
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
        R"({"type":"library","name":"a","purl":"pkg:npm/a@1","scope":"Optional"}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.front().scope == Scope::Required);
    BOMWERK_TEST_CHECK(warnings_mention(read.warnings, "unrecognized scope \"Optional\""));
  }

  // --all-cpes: given a component written with a SynthesizedWildcardVendor
  // cpe, when written then read back, then the exact provenance round-trips
  //: the writer's bomwerk:cpe-provenance property is what the reader
  // recognizes.
  {
    Component original;
    original.name = "left-pad";
    original.purl = "pkg:npm/left-pad@1.3.0";
    original.cpe = "cpe:2.3:a:*:left-pad:1.3.0:*:*:*:*:*:*:*";
    original.cpe_provenance = CpeProvenance::SynthesizedWildcardVendor;

    const std::string document = write_cyclonedx({original}, ToolInfo{"bomwerk", "0.1.0"});
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.size() == 1);
    const Component& round_tripped = read.value.components.front();
    BOMWERK_TEST_CHECK(round_tripped.cpe == "cpe:2.3:a:*:left-pad:1.3.0:*:*:*:*:*:*:*");
    BOMWERK_TEST_CHECK(round_tripped.cpe_provenance == CpeProvenance::SynthesizedWildcardVendor);
  }

  // Given a component whose cpe carries no provenance property at all (every
  // pre-existing SBOM, and a plain scan's default-scope synthesis), when read
  // back, then cpe_provenance stays Unspecified rather than defaulting to a
  // guess.
  {
    const std::string document = R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
                                 R"({"type":"library","name":"a","purl":"pkg:vcpkg/a@1",)"
                                 R"("cpe":"cpe:2.3:a:*:a:1:*:*:*:*:*:*:*"}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.front().cpe_provenance == CpeProvenance::Unspecified);
  }

  // Given a bomwerk:cpe-provenance property carrying an unrecognized value (a
  // typo, a hand edit, or a future spec value this bomwerk does not know
  // yet), when read, then it is ignored for forward compatibility: the
  // component stays Unspecified rather than the reader guessing at meaning.
  {
    const std::string document =
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
        R"({"type":"library","name":"a","purl":"pkg:vcpkg/a@1",)"
        R"("cpe":"cpe:2.3:a:*:a:1:*:*:*:*:*:*:*",)"
        R"("properties":[{"name":"bomwerk:cpe-provenance","value":"future-guess-kind"}]}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.front().cpe_provenance == CpeProvenance::Unspecified);
  }

  // Given truncated/hostile JSON, when read, then the document degrades to a
  // named warning and zero components rather than crashing (rule 1).
  {
    const Result<SbomDocument> read = read_cyclonedx(R"({"bomFormat":"CycloneDX")");
    BOMWERK_TEST_CHECK(read.value.components.empty());
    BOMWERK_TEST_CHECK(warnings_mention(read.warnings, "not valid JSON"));
  }

  // Given a document nested past the shared depth guard, when read, then it
  // is refused before nlohmann ever sees it (the same recursive-descent
  // stack-exhaustion defense every JSON-parsing producer uses).
  {
    std::string deeply_nested(300, '[');
    deeply_nested += std::string(300, ']');
    const Result<SbomDocument> read = read_cyclonedx(deeply_nested);
    BOMWERK_TEST_CHECK(read.value.components.empty());
    BOMWERK_TEST_CHECK(warnings_mention(read.warnings, "nested too deeply"));
  }

  // Given a document with no components array at all, when read, then it
  // warns by name rather than silently reporting zero components as if the
  // product genuinely shipped none.
  {
    const Result<SbomDocument> read =
        read_cyclonedx(R"({"bomFormat":"CycloneDX","specVersion":"1.6"})");
    BOMWERK_TEST_CHECK(read.value.components.empty());
    BOMWERK_TEST_CHECK(warnings_mention(read.warnings, "no components array"));
  }

  // Given a components array holding a non-object entry beside a valid one,
  // when read, then the valid entry still parses and the bad one is counted
  // in a warning rather than aborting the whole document.
  {
    const std::string document =
        R"({"bomFormat":"CycloneDX","specVersion":"1.6","components":[)"
        R"("not-an-object",{"type":"library","name":"a","purl":"pkg:npm/a@1.0.0"}]})";
    const Result<SbomDocument> read = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read.value.components.size() == 1);
    BOMWERK_TEST_CHECK(warnings_mention(read.warnings, "skipped (not a JSON object)"));
  }

  // Given a component that carried a location at scan time, when it makes
  // the full round trip through the writer and back, then the location comes
  // back intact. This is the pair that makes `bomwerk trim` possible at all:
  // the writer records where a component lives, this reader restores it, and a
  // build trace has somewhere to attribute its compiles.
  {
    Component vendored;
    vendored.name = "zlib";
    vendored.version = "1.2.11";
    vendored.purl = "pkg:generic/zlib@1.2.11";
    vendored.root = "third_party/zlib";
    Component from_lockfile;
    from_lockfile.name = "left-pad";
    from_lockfile.version = "1.3.0";
    from_lockfile.purl = "pkg:npm/left-pad@1.3.0";

    const std::string document =
        write_cyclonedx({vendored, from_lockfile}, ToolInfo{"bomwerk", "0.1.0"});
    const Result<SbomDocument> read_back = read_cyclonedx(document);
    BOMWERK_TEST_CHECK(read_back.warnings.empty());

    const Component* zlib = find_by_purl(read_back.value.components, "pkg:generic/zlib@1.2.11");
    BOMWERK_TEST_CHECK(zlib != nullptr);
    BOMWERK_TEST_CHECK(zlib->root == fs::path("third_party/zlib"));

    // A component that never had a location must not acquire one.
    const Component* left_pad = find_by_purl(read_back.value.components, "pkg:npm/left-pad@1.3.0");
    BOMWERK_TEST_CHECK(left_pad != nullptr);
    BOMWERK_TEST_CHECK(left_pad->root.empty());
  }

  // Given a hand-crafted SBOM whose occurrence location escapes the repo,
  // when it is read, then the location is dropped WITH a warning. An SBOM
  // handed to `bomwerk trim` is untrusted input and its root is later joined
  // against a scanned directory, so an absolute path or a `..` would walk the
  // mapping straight out of the tree; the warning matters because a component
  // whose root vanished will be reported unused and the operator has to know
  // why.
  {
    const auto with_location = [](const std::string& location)
    {
      return R"({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[)"
             R"({"type":"library","name":"evil","purl":"pkg:generic/evil@1.0",)"
             R"("evidence":{"occurrences":[{"location":")" +
             location + R"("}]}}]})";
    };

    const Result<SbomDocument> absolute = read_cyclonedx(with_location("/etc"));
    BOMWERK_TEST_CHECK(absolute.value.components.size() == 1);
    BOMWERK_TEST_CHECK(absolute.value.components[0].root.empty());
    BOMWERK_TEST_CHECK(warnings_mention(absolute.warnings, "not a relative path inside the repo"));

    const Result<SbomDocument> escaping = read_cyclonedx(with_location("../../../etc"));
    BOMWERK_TEST_CHECK(escaping.value.components[0].root.empty());
    BOMWERK_TEST_CHECK(warnings_mention(escaping.warnings, "not a relative path inside the repo"));
  }

  // Given occurrence shapes that are merely wrong rather than hostile,
  // when they are read, then each is simply absent: never an error, never a
  // warning. "The document does not say" and "the document lies" are different
  // situations and must not produce the same noise (rule 1).
  {
    const auto with_evidence = [](const std::string& evidence_json)
    {
      return R"({"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[)"
             R"({"type":"library","name":"x","purl":"pkg:generic/x@1.0","evidence":)" +
             evidence_json + R"(}]})";
    };

    for (const std::string& evidence_json :
         {std::string(R"("not-an-object")"), std::string(R"({"occurrences":"nope"})"),
          std::string(R"({"occurrences":[]})"), std::string(R"({"occurrences":[42]})"),
          std::string(R"({"occurrences":[{"line":3}]})"),
          std::string(R"({"occurrences":[{"location":7}]})")})
    {
      const Result<SbomDocument> read_back = read_cyclonedx(with_evidence(evidence_json));
      BOMWERK_TEST_CHECK(read_back.value.components.size() == 1);
      BOMWERK_TEST_CHECK(read_back.value.components[0].root.empty());
      BOMWERK_TEST_CHECK(read_back.warnings.empty());
    }
  }

  // Given format detection alone, when sniffing a CycloneDX document, an
  // SPDX document and neither, then each is named correctly.
  {
    BOMWERK_TEST_CHECK(detect_sbom_format(R"({"bomFormat":"CycloneDX"})") ==
                       SbomInputFormat::CycloneDx);
    BOMWERK_TEST_CHECK(detect_sbom_format(R"({"spdxVersion":"SPDX-2.3"})") ==
                       SbomInputFormat::Spdx);
    BOMWERK_TEST_CHECK(detect_sbom_format(R"({"hello":"world"})") == SbomInputFormat::Unknown);
  }

  // Given load_sbom_file over a real file, when the file holds a CycloneDX
  // document, an SPDX document, or does not exist at all, then each degrades
  // with the right named warning (SPDX and "unrecognized" must never be
  // confused with each other, and neither may silently parse as empty).
  {
    TempTree tree;
    const std::string cyclonedx_document =
        write_cyclonedx({}, ToolInfo{"bomwerk", "0.1.0"});  // valid, zero components
    tree.write("product.cdx.json", cyclonedx_document);
    const Result<SbomDocument> read_ok = load_sbom_file(tree.root() / "product.cdx.json");
    BOMWERK_TEST_CHECK(read_ok.value.components.empty());
    BOMWERK_TEST_CHECK(read_ok.warnings.empty());

    tree.write("product.spdx.json", R"({"spdxVersion":"SPDX-2.3","packages":[]})");
    const Result<SbomDocument> read_spdx = load_sbom_file(tree.root() / "product.spdx.json");
    BOMWERK_TEST_CHECK(read_spdx.value.components.empty());
    BOMWERK_TEST_CHECK(warnings_mention(read_spdx.warnings, "is an SPDX document"));

    tree.write("not-an-sbom.json", R"({"hello":"world"})");
    const Result<SbomDocument> read_unknown = load_sbom_file(tree.root() / "not-an-sbom.json");
    BOMWERK_TEST_CHECK(warnings_mention(read_unknown.warnings, "not a recognized SBOM format"));

    const Result<SbomDocument> read_missing = load_sbom_file(tree.root() / "does-not-exist.json");
    BOMWERK_TEST_CHECK(read_missing.value.components.empty());
    BOMWERK_TEST_CHECK(warnings_mention(read_missing.warnings, "cannot read SBOM file"));
  }

  return 0;
}
