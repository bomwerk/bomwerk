#pragma once
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/sbom_format.hpp"
#include "output/tool_info.hpp"

namespace bomwerk::output
{

/// Render `components` as an SPDX document: the second SBOM format bomwerk
/// emits, sharing the CycloneDX writer's model and determinism rules.
///
/// `spdx_version` selects the serialization:
///   * `SpdxVersion::V3_0` (the default): SPDX 3.0.1 JSON-LD: a single
///     `@graph` of typed elements (`CreationInfo`, the creating `Organization`
///     and `Tool`, one `SpdxDocument`, one `software_Package` per component,
///     one `describes` `Relationship`).
///   * `SpdxVersion::V2_3`: the classic flat SPDX 2.3 JSON document
///     (`packages` + `relationships`), for consumers whose tooling has not yet
///     moved to 3.0.
///
/// Per component the writer records the same identity/verification core the
/// CycloneDX writer does: name, version, the purl, CPE 2.3 identifier, and the
/// SHA-256 hash (when known and well-formed). CPE is an `ExternalIdentifier`
/// in SPDX 3.0.1 and a SECURITY `externalRef` in SPDX 2.3. SPDX 2.3
/// additionally records `licenseDeclared` and `supplier` when present.
/// `licenseDeclared` is validated against the
/// vendored SPDX License List (`canonical_spdx_license_id`, case-insensitive):
/// a recognized id (e.g. "MIT") is emitted as its canonical spelling; free
/// text or a compound expression the writer cannot itself parse (e.g.
/// "BSD-style") is instead wrapped as a stable `LicenseRef-declared-N` id
/// with a matching `hasExtractedLicensingInfos` entry carrying the original
/// text: both forms are schema-valid JSON, but only the wrapped form is a
/// real SPDX Annex D license expression. License and supplier are
/// deliberately left off the 3.0.1 packages for now: 3.0.1 models them
/// through the Licensing profile and `Agent` elements (the official SPDX
/// 2.3->3.0 conversion example omits licenses for the same reason), and
/// claiming them without that machinery would be dishonest: a follow-up task
/// enriches the 3.0.1 output.
///
/// When `release_meta.product_id` is non-empty it becomes the document name,
/// identifying the product this SBOM describes. As with the CycloneDX writer,
/// no dependency edges are invented: `core::Component` carries no graph, so
/// the only relationship emitted is the document/package `describes` edge.
///
/// Deterministic (rule 3), by the same primitives as the CycloneDX writer:
/// object keys are canonically sorted (plain `nlohmann::json`, not
/// `ordered_json`); packages are sorted by `core::component_identity` so caller
/// order cannot change the output; every SPDX id/IRI is `uuidv5` of the same
/// component identity that backs the CycloneDX `bom-ref`, and the document
/// identifier (`documentNamespace` / `SpdxDocument` spdxId) is derived from the
/// sorted set of identities; the creation timestamp honors `SOURCE_DATE_EPOCH`
/// (see `core::current_timestamp_iso8601`: self-reported generation metadata,
/// not a tamper-evident attestation, and never the CRA disclosure-clock
/// timestamp). Two calls with the same components (in any order) and the same
/// `SOURCE_DATE_EPOCH` produce byte-identical output.
///
/// Never throws (rule 1): invalid UTF-8 in a component field (hostile
/// manifest/evidence content) is replaced during serialization, not rejected.
[[nodiscard]] std::string write_spdx(const std::vector<core::Component>& components,
                                     const ToolInfo& tool, core::SpdxVersion spdx_version,
                                     const core::ReleaseMeta& release_meta = {});

}  // namespace bomwerk::output
