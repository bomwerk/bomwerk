#pragma once
#include <optional>
#include <string>
#include <string_view>

namespace bomwerk::core
{

/// Standard Base64 (RFC 4648 §4, `+`/`/` alphabet, `=` padding) of arbitrary
/// bytes. Used to embed a company logo as a `data:` URI so the HTML report
/// stays one self-contained file. Total-function and
/// allocation-bounded (output is 4/3 the input, rounded up): never throws,
/// so hostile/binary input is encoded, never rejected. Example:
/// `base64_encode("Man")` -> `"TWFu"`; `base64_encode("")` -> `""`.
[[nodiscard]] std::string base64_encode(std::string_view bytes);

/// Strict unpadded Base64url decoding (RFC 4648 section 5). Only the URL-safe
/// alphabet is accepted: standard Base64 symbols, padding, whitespace,
/// impossible lengths, and non-canonical trailing bits return `std::nullopt`.
/// Empty input is valid and decodes to an empty string. The returned value is
/// length-based, so decoded NUL bytes are preserved.
[[nodiscard]] std::optional<std::string> base64url_decode(std::string_view text);

}  // namespace bomwerk::core
