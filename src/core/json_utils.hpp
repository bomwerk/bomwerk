#pragma once

#include <string_view>

namespace bomwerk::core::json_utils
{

/// Maximum safe JSON nesting depth to prevent stack exhaustion on pathological input.
inline constexpr int kMaxJsonNestingDepth = 100;

/// Per-manifest/file read cap to prevent memory exhaustion.
inline constexpr std::size_t kMaxFileBytes = 1024u * 1024u;  ///< 1 MiB

/// Strip a UTF-8 byte-order mark so a BOM'd manifest parses like any other.
std::string_view without_utf8_bom(std::string_view bytes);

/// nlohmann's parser is recursive-descent: pathologically nested input can
/// exhaust the stack before allow_exceptions=false can help. This linear,
/// string-aware pre-scan bounds the depth first (rule 1). Returns true when
/// `maximum_depth` is exceeded.
bool exceeds_json_nesting_depth(std::string_view bytes, int maximum_depth);

}  // namespace bomwerk::core::json_utils
