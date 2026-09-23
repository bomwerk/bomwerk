#pragma once
#include <filesystem>
#include <string>

#include "core/model.hpp"

namespace bomwerk::output
{

/// True when `release_meta`/`cra_metadata` carry at least one field worth
/// writing a sidecar for: the caller's signal to skip the file entirely
/// rather than emit a pointless `{}` document next to every plain scan.
[[nodiscard]] bool has_cra_sidecar_content(const core::ReleaseMeta& release_meta,
                                           const core::CraMetadata& cra_metadata);

/// Render the CRA compliance sidecar that `sbom-tools validate
/// --standard cra` auto-discovers next to a CycloneDX/SPDX document :
/// manufacturer identification (Art. 13(16)), vulnerability-handling contact
/// (Art. 13(17)) and support lifecycle (Art. 13(8)) fields no producer can
/// observe from source code, so they come from bomwerk.toml's `[cra]` table
/// (`core::CraMetadata`) and `release_meta` instead.
///
/// Field names are fixed by the consumer's schema (`CraSidecarMetadata`,
/// which deserializes with `deny_unknown_fields`): camelCase keys, written
/// only when the corresponding source field is non-empty: an absent key
/// deserializes as "not configured", the honest state, whereas a
/// placeholder value would assert something bomwerk never observed.
/// `release_meta.support_until` (an ISO-8601 date, e.g. "2028-01-01") is
/// widened to a full RFC-3339 datetime for `supportEndDate`: the
/// consumer's schema requires a datetime, and a bare date fails to
/// deserialize at all, hard-failing the whole sidecar (its loader treats a
/// malformed sidecar as an error, never a silent skip) rather than just
/// this one field. A value that already contains a 'T' is assumed to be a
/// full timestamp already and passed through unchanged.
///
/// `release_meta.version` is only emitted as `productVersion` alongside a
/// non-empty `product_id`: the same "version without a name is meaningless"
/// convention `write_cyclonedx`'s `metadata.component` already applies.
///
/// Deterministic (rule 3): a fixed key order, independent of `CraMetadata`'s
/// field declaration order or the caller's call site.
///
/// Never throws (rule 1): invalid UTF-8 in a configured field is replaced
/// during serialization, not rejected: same guard as the other writers.
[[nodiscard]] std::string write_cra_sidecar(const core::ReleaseMeta& release_meta,
                                            const core::CraMetadata& cra_metadata);

/// Where the sidecar for `sbom_output_path` belongs so `sbom-tools`'
/// auto-discovery (`<stem>.cra.json` next to the SBOM) finds it with no
/// extra flag. Strips exactly one trailing format suffix recognized by that
/// discovery (`.cdx`, `.cyclonedx`, `.spdx`, `.spdx3`) in addition to the
/// file extension itself, so `sbom.cdx.json` and `report.spdx.json` both
/// produce the short canonical form (`sbom.cra.json`, `report.cra.json`)
/// rather than `sbom.cdx.cra.json`: still discoverable either way (the
/// consumer tries both forms), but the short one is what a human expects
/// to see next to their SBOM.
[[nodiscard]] std::filesystem::path cra_sidecar_path_for(
    const std::filesystem::path& sbom_output_path);

}  // namespace bomwerk::output
