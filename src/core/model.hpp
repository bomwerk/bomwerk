#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace bomwerk::core
{

/// Where a piece of evidence came from, roughly ordered by how it is obtained.
enum class Source
{
  Manifest,
  Heuristic,
  ObservedBuild,
  Fingerprint,
  Binary
};

enum class Confidence
{
  Low,
  Medium,
  High
};

/// Lower-case display label for a confidence level: the one user-facing
/// string table shared by the CLI listing and the HTML report (future
/// --lang hook). Same shape as `to_string(SbomFormat)`.
constexpr const char* to_string(Confidence confidence)
{
  switch (confidence)
  {
    case Confidence::High:
      return "high";
    case Confidence::Medium:
      return "medium";
    case Confidence::Low:
      return "low";
  }
  return "low";  // unreachable: all enumerators handled above
}

/// One observation that a component exists (a manifest entry, a license file,
/// a linker input, …). Components accumulate evidence from several producers.
struct Evidence
{
  Source source{};
  std::string detail;  ///< human-readable pointer, e.g. "vcpkg.json" or "third_party/zlib/LICENSE"
  Confidence confidence{Confidence::Low};
};

/// CycloneDX `component.scope`: whether a component is part of the
/// shipped deliverable. `Required` is the spec's default for an absent field
/// and is never serialized; `Excluded` marks packages a lockfile itself
/// declares dev-only (npm `dev: true`, poetry non-`main` groups): recorded,
/// never guessed.
enum class Scope
{
  Required,
  Optional,
  Excluded
};

/// CycloneDX spec token for a scope (`bom-1.6.schema.json` enum). These are
/// protocol strings, not user-facing text: they are never localized.
constexpr const char* to_string(Scope scope)
{
  switch (scope)
  {
    case Scope::Required:
      return "required";
    case Scope::Optional:
      return "optional";
    case Scope::Excluded:
      return "excluded";
  }
  return "required";  // unreachable: all enumerators handled above
}

/// How a `Component::cpe` value came to be, so a consumer can tell a
/// deliberately looser `--all-cpes` guess apart from an existing, precise
/// identifier. `Unspecified` is the default and covers everything that is not
/// a fresh `--all-cpes` synthesis: an empty `cpe`, one already present before
/// `vuln::populate_cpe_identifiers` ran (an upstream producer's own value, or
/// a plain scan's default-scope synthesis), and one read back from a
/// CycloneDX document that carried no recognized provenance property.
/// `SynthesizedWildcardVendor` marks a CPE `vuln::populate_cpe_identifiers`
/// synthesized while scoped to `vuln::CpePopulationScope::AllVersioned` (the
/// `--all-cpes` opt-in): the same wildcard-vendor construction the default
/// scope already uses, just applied to every safely convertible versioned
/// purl instead of only OSV-unmapped types.
enum class CpeProvenance
{
  Unspecified,
  SynthesizedWildcardVendor
};

/// The CycloneDX Property Taxonomy name a recognized `CpeProvenance` is
/// recorded under. Shared here (module dependency law: `output` and `sbom`
/// each include only `core`, not each other) so the writer and the reader
/// agree on the exact string without one depending on the other.
inline constexpr std::string_view kCpeProvenancePropertyName = "bomwerk:cpe-provenance";

/// CycloneDX property VALUE for a recognized provenance. `Unspecified` has no
/// value and is never serialized: a writer must gate on
/// `cpe_provenance != CpeProvenance::Unspecified` before emitting, the same
/// precedent `component.cpe.empty()` already sets for the `cpe` field itself.
/// A reader recognizes only this exact string (see `sbom::read_cyclonedx`);
/// any other value for `kCpeProvenancePropertyName` is ignored for forward
/// compatibility, leaving the component at `Unspecified`.
constexpr const char* to_string(CpeProvenance provenance)
{
  switch (provenance)
  {
    case CpeProvenance::SynthesizedWildcardVendor:
      return "wildcard-vendor-guess";
    case CpeProvenance::Unspecified:
      return "";
  }
  return "";  // unreachable: all enumerators handled above
}

/// The one data model every module shares.
struct Component
{
  std::string name;
  std::string version;
  std::string supplier;
  std::string license;
  std::string purl;  ///< identity key, e.g. "pkg:conan/openssl@3.2.0"
  std::string cpe;   ///< CPE 2.3 formatted identifier when safely derivable
  CpeProvenance cpe_provenance = CpeProvenance::Unspecified;  ///< how `cpe` was derived; see above
  std::string sha256;          ///< hash of source archive / main artifact when known
  std::filesystem::path root;  ///< where it lives in the repo (for "used?" matching)
  std::vector<Evidence> evidence;
  bool used_in_build = true;      ///< flipped by observe-diff (SBOM Trim)
  Scope scope = Scope::Required;  ///< CycloneDX component.scope; Required is never serialized
};

/// Identity of the product being scanned, supplied by the caller so a
/// generated SBOM can be tied back to the customer's own product registry
///. Distinct from `ToolInfo` (output/cyclonedx.hpp),
/// which identifies bomwerk itself, not the product it is scanning.
/// `product_id`/`version` come from CLI flags. `support_until` is stored by the
/// paid extension alongside a release. Nothing threads it back into a
/// `bomwerk scan` run, so
/// it is unset here today.
struct ReleaseMeta
{
  std::string product_id;
  std::string version;
  std::string support_until;  ///< ISO-8601 date; empty until the registry fills it
};

/// CRA compliance metadata a bomwerk.toml `[cra]` table supplies :
/// nothing here is derivable from the scanned repo itself, so unlike
/// `Component`/`ReleaseMeta` there is no producer for it, only config. Feeds
/// `output::write_cyclonedx`'s `metadata.manufacturer` and
/// `output::write_cra_sidecar`'s sidecar document, which together are what
/// lets `sbom-tools validate --standard cra` find manufacturer identification
/// (Art. 13(16)) and vulnerability-handling contact fields (Art. 13(17))
/// bomwerk cannot observe from source code alone. Every field is optional;
/// an empty string means "not configured" and is omitted from output, never
/// emitted as a placeholder.
struct CraMetadata
{
  std::string manufacturer_name;
  std::string manufacturer_email;
  std::string security_contact;
  std::string vulnerability_disclosure_url;
};

/// Merge/identity key for a component: the canonical purl when `component.purl` parses,
/// the raw purl when it doesn't, otherwise `name@version`. The identity `merge_all` groups
/// components by, and the identity every ID-deriving consumer (e.g. the CycloneDX writer's
/// bom-ref/serialNumber) must use so identity stays a single, shared definition.
std::string component_identity(const Component& component);

/// Merge `source` into `destination` (same identity): evidence is unioned,
/// duplicate evidence keeps the higher confidence, empty fields are filled from
/// `source`, `used_in_build` is any-true-wins, and `scope` keeps the least
/// restrictive of the two (`Required > Optional > Excluded`): a runtime use
/// anywhere trumps a dev-only marking, independent of merge order.
void merge_into(Component& destination, const Component& source);

/// Return the strongest confidence carried by a component's evidence.
Confidence highest_confidence(const Component& component);

/// Deduplicate by purl (fallback `name@version`); output is ordered by that
/// identity key so two runs are byte-identical (rule 3).
std::vector<Component> merge_all(std::vector<Component> components);

}  // namespace bomwerk::core
