#pragma once
#include <optional>
#include <string_view>

namespace bomwerk::output
{

/// Case-insensitive lookup against the vendored SPDX License List (see the
/// provenance note in spdx_license_ids.cpp) of short license identifiers such
/// as "MIT" or "Apache-2.0". Returns the list's own canonical spelling when
/// `license_text` matches one (trimmed, case-insensitive), or `std::nullopt`
/// otherwise -- free text ("BSD-style") and compound expressions ("MIT OR
/// Apache-2.0") are not single recognized identifiers and return nullopt, so
/// the SPDX 2.3 writer can fall back to a LicenseRef-/
/// hasExtractedLicensingInfos entry instead of emitting a `licenseDeclared`
/// value that is JSON-Schema-valid but not a real SPDX license expression.
[[nodiscard]] std::optional<std::string_view> canonical_spdx_license_id(
    std::string_view license_text);

}  // namespace bomwerk::output
