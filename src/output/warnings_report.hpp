#pragma once
#include <set>
#include <string>
#include <vector>

#include "core/model.hpp"
#include "core/warning.hpp"
#include "output/tool_info.hpp"

namespace bomwerk::output
{

/// Render `warnings` as a standalone, machine-readable manifest
/// (`scan --warnings <file>.json`): one entry per distinct `(code, ecosystem)` pair, with
/// every occurrence collapsed into a count and a deduplicated, sorted list of affected
/// paths: the 604 repeated vcpkg lines a single corpus repo can produce become one entry
/// with `"count": 604`, not 604 JSON objects. Codes in `suppressed_codes` (bomwerk.toml
/// `[warnings] suppress`, including `CODE:ecosystem` entries) are marked `"suppressed": true`,
/// never omitted: suppression is
/// about the exit code and the operator's attention, never about hiding a coverage gap from
/// the evidence trail.
///
/// Deterministic (rule 3): plain `nlohmann::json` (not `ordered_json`), so object keys sort
/// canonically; entries are ordered by `(code id, ecosystem)`, so the order warnings were
/// recorded in cannot change the bytes; `generated_at` honors `SOURCE_DATE_EPOCH` (see
/// `core::current_timestamp_iso8601`).
///
/// When `release_meta.product_id` is non-empty, a `product` object records it, same
/// convention as the coverage and CycloneDX writers.
///
/// Never throws (rule 1): invalid UTF-8 in a warning's message or an affected path is
/// replaced during serialization, not rejected: same guard as the other writers.
[[nodiscard]] std::string write_warnings_report(const std::vector<core::Warning>& warnings,
                                                const std::set<std::string>& suppressed_codes,
                                                const ToolInfo& tool,
                                                const core::ReleaseMeta& release_meta = {});

}  // namespace bomwerk::output
