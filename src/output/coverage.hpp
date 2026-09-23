#pragma once
#include <string>
#include <vector>

#include "core/model.hpp"
#include "output/tool_info.hpp"

namespace bomwerk::output
{

/// Render `components` as a standalone, machine-readable match-coverage
/// document (match coverage; `scan --coverage <file>`): the per-component
/// classification the CycloneDX/HTML surfaces summarize, in full: EVERY
/// component (not only the unmatched ones the other two surfaces highlight)
/// with its `core::classify_match_coverage` class and the same confidence
/// label the CLI/HTML report already show (`core::highest_confidence`).
/// Intended for CI gating and audits that want the complete classification,
/// not just the anomalies.
///
/// Deterministic (rule 3): plain `nlohmann::json` (not `ordered_json`), so
/// object keys are canonically sorted; components are ordered by
/// `core::component_identity`: the same order every other writer uses, so
/// caller ordering cannot change the bytes; `generated_at` honors
/// `SOURCE_DATE_EPOCH` (see `core::current_timestamp_iso8601`).
///
/// When `release_meta.product_id` is non-empty, a `product` object records
/// it: same convention as the CycloneDX writer's `metadata.component`; an
/// empty `product_id` (the default) omits it entirely.
///
/// Never throws (rule 1): invalid UTF-8 in a component field is replaced
/// during serialization, not rejected: same guard as the other two writers.
[[nodiscard]] std::string write_coverage_report(const std::vector<core::Component>& components,
                                                const ToolInfo& tool,
                                                const core::ReleaseMeta& release_meta = {});

}  // namespace bomwerk::output
