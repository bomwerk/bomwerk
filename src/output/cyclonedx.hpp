#pragma once
#include <string>
#include <vector>

#include "core/model.hpp"
#include "output/tool_info.hpp"

namespace bomwerk::output
{

/// Render `components` as a CycloneDX 1.6 JSON document carrying the BSI
/// TR-03183 fields required for every component: name, version, supplier, purl,
/// sha256, license, dependencies.
///
/// When `release_meta.product_id` is non-empty, it is recorded as
/// `metadata.component` (type "application"), identifying the product this
/// BOM describes: separate from `tool`, which identifies bomwerk itself. An
/// empty `product_id` (the default) omits `metadata.component` entirely.
///
/// CRA platform interop: every claim below verified against the real
/// `sbom-tools` 0.2.0 binary, not just its schema): `sbom-tools validate
/// --standard ntia/cra` checks `metadata.component` against the exact same
/// per-component identifier/supplier/dependency rules as every real
/// dependency, so it is no longer left bare. It now carries its own
/// `bom-ref`; a synthetic `pkg:generic/<product_id>@<version>` purl (the same
/// fallback shape every producer already uses for an otherwise-unidentifiable
/// component); and, when `cra_metadata.manufacturer_name` is configured, a
/// `supplier` matching it. A root `dependencies[]` entry additionally lists
/// every component as a direct `dependsOn` of the product: the real graph
/// edge the dependency-relationship rule checks for, layered on top of (not
/// replacing) each component's own childless entry described below. A
/// non-empty `cra_metadata.manufacturer_name` also emits document-level
/// `metadata.manufacturer` (name + `contact[].email` when
/// `manufacturer_email` is set too): CycloneDX's own field for CRA Art.
/// 13(16) manufacturer identification, sourced from bomwerk.toml's `[cra]`
/// table since no producer can observe a manufacturer from source code.
///
/// This closes `--standard ntia` to a clean pass (0 violations) on a
/// `--product`-scanned SBOM. It does NOT close `--standard cra` to clean: once
/// `core::Component::supplier` is populated (a producer-level CRA interop change),
/// `SBOM-CRA-PRE-7-RQ-07-RE` (vendor-supplied components must carry a
/// cryptographic hash) surfaces for every supplied component with no hash: a
/// structural gap (the producers that know a supplier, e.g. a git remote
/// owner, do not compute a content hash, and vice versa), not a bug in this
/// writer; see the README's "CRA platform interop" section.
///
/// Deterministic (rule 3): object keys are canonically sorted (plain
/// `nlohmann::json`, not `ordered_json`); each component's `bom-ref` is
/// `uuidv5(purl_namespace(), purl-or-name@version)`; the document
/// `serialNumber` is derived the same way from the sorted set of component
/// identities, so caller ordering cannot change it; `metadata.timestamp`
/// honors `SOURCE_DATE_EPOCH` (see `core::current_timestamp_iso8601`'s doc
/// comment: self-reported generation-time metadata, not a tamper-evident
/// attestation: never the timestamp a CRA disclosure-clock decision should
/// rest on). Two calls with the same components (in any order) and the same
/// `SOURCE_DATE_EPOCH` produce byte-identical output.
///
/// `dependencies` still emits one childless `{"ref": ...}` entry per
/// component beyond the root edge above: `core::Component` has no
/// component-to-component dependency-graph data yet, so this records the
/// required field without inventing edges that were never observed.
///
/// A non-empty `core::Component::cpe` is emitted as the component's CPE field.
/// The CLI fills this independently of vulnerability matching for safely
/// derivable Conan, vcpkg and generic purls; the writer only serializes the
/// shared model and never reaches into the vulnerability module. When
/// `core::Component::cpe_provenance` carries a recognized value (today only
/// `SynthesizedWildcardVendor`, set for a CPE synthesized under `--all-cpes`
/// scope), the component additionally carries one `component.properties`
/// entry named `core::kCpeProvenancePropertyName`: omitted entirely for
/// `CpeProvenance::Unspecified`, same precedent as `component.scope`, so
/// every pre-`--all-cpes` snapshot stays byte-identical.
///
/// Match-coverage reporting: `metadata.properties` always carries the
/// BOM-level `bomwerk:coverage:*` totals (`core::summarize_match_coverage`),
/// name-sorted; a component whose `core::classify_match_coverage` is not
/// `Matched` additionally carries one `component.properties` entry named
/// `bomwerk:match-coverage` (CycloneDX Property Taxonomy shape): a matched
/// component gets no `properties` field at all, so a plain scan's bytes stay
/// unchanged, same precedent as `component.scope`.
///
/// Build-trace mapping: a component carrying a `root`: today only the
/// submodule and vendored-code producers set one: additionally emits
/// `component.evidence.occurrences[0].location` with that repo-relative path,
/// so `sbom::read_cyclonedx` can restore it and `bomwerk trim` can attribute
/// a build trace to an SBOM it did not produce itself. A rootless component
/// gets no `evidence` field at all, same precedent as `scope` above.
///
/// Never throws (rule 1): invalid UTF-8 in a component field (hostile
/// manifest/evidence content) is replaced during serialization, not
/// rejected.
[[nodiscard]] std::string write_cyclonedx(const std::vector<core::Component>& components,
                                          const ToolInfo& tool,
                                          const core::ReleaseMeta& release_meta = {},
                                          const core::CraMetadata& cra_metadata = {});

}  // namespace bomwerk::output
