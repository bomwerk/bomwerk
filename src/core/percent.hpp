#pragma once
#include <string>
#include <string_view>

namespace bomwerk::core
{

/// Percent-encode `text` per RFC 3986: unreserved characters
/// (`A-Z a-z 0-9 - . _ ~`) pass through, every other byte becomes `%XX` with
/// upper-case hex. Used for purl name/version components and qualifier values.
/// Example: `percent_encode("git+https://x.y/a b")` ->
/// `"git%2Bhttps%3A%2F%2Fx.y%2Fa%20b"`.
[[nodiscard]] std::string percent_encode(std::string_view text);

/// Percent-encode a purl namespace (an owner or module path): each
/// `/`-separated segment is `percent_encode`d while the `/` separators stay
/// literal, since they are structural in a purl. So a GitLab subgroup namespace
/// `group/sub` or a Go module path `github.com/gorilla` keeps its slashes, but
/// a segment with a stray structural byte: e.g. the `broken)` a malformed
/// manifest can leak: becomes `broken%29`, keeping the emitted purl
/// well-formed for downstream consumers.
[[nodiscard]] std::string percent_encode_purl_namespace(std::string_view namespace_path);

/// Inverse of `percent_encode`: every `%XX` with two hex digits becomes the byte
/// it names, and every other character passes through. A truncated or malformed
/// escape (`%`, `%A`, `%ZZ`) is kept verbatim rather than dropped, so a hostile
/// manifest can never make text disappear (Hard Rule 1): decoding is total and
/// never fails. Used to recover the locator inside a Yarn `patch:` resolution,
/// where `:` arrives as `%3A`.
/// Example: `percent_decode("@material-ui%2Fpickers@npm%3A3.3.11")` ->
/// `"@material-ui/pickers@npm:3.3.11"`; `percent_decode("100%")` -> `"100%"`.
[[nodiscard]] std::string percent_decode(std::string_view text);

}  // namespace bomwerk::core
