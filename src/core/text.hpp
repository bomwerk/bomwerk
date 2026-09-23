#pragma once
#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>

namespace bomwerk::core
{

/// Whether `value` appears in `table`, compared by `==`. `table` is any
/// range of values comparable to `std::string_view` (a `std::array` of
/// option spellings, most often): a linear scan is the right cost for the
/// small, fixed option tables this is called against.
/// Example: `contains(std::array{"-c"sv, "-S"sv}, "-c"sv)` -> `true`.
template <typename Table>
[[nodiscard]] bool contains(const Table& table, std::string_view value)
{
  return std::find(table.begin(), table.end(), value) != table.end();
}

/// Locale-independent ASCII lower-casing of one byte; anything outside 'A'..'Z'
/// passes through unchanged (machine output must never depend on the C locale).
/// Example: `to_lower_ascii('G')` -> `'g'`; `to_lower_ascii('_')` -> `'_'`.
[[nodiscard]] char to_lower_ascii(char character);

/// Locale-independent ASCII lower-casing of a whole string.
/// Example: `to_lower_ascii("GIT_TAG")` -> `"git_tag"`.
[[nodiscard]] std::string to_lower_ascii(std::string_view text);

/// Locale-independent ASCII upper-casing of one byte; anything outside 'a'..'z'
/// passes through unchanged (machine output must never depend on the C locale).
/// Example: `to_upper_ascii('g')` -> `'G'`; `to_upper_ascii('_')` -> `'_'`.
[[nodiscard]] char to_upper_ascii(char character);

/// Locale-independent ASCII upper-casing of a whole string.
/// Example: `to_upper_ascii("cve-2026-1234")` -> `"CVE-2026-1234"`.
[[nodiscard]] std::string to_upper_ascii(std::string_view text);

/// Case-insensitive ASCII equality without allocating.
/// Example: `equals_ascii_ignore_case("URL_HASH", "url_hash")` -> `true`;
/// `equals_ascii_ignore_case("URL", "URL_HASH")` -> `false`.
[[nodiscard]] bool equals_ascii_ignore_case(std::string_view left, std::string_view right);

/// View of `text` without leading/trailing spaces, tabs, carriage returns and
/// newlines. Allocation-free: the view points into `text` and must not outlive
/// it. Example: `trimmed_view("  v1.2 \r\n")` -> `"v1.2"`.
[[nodiscard]] std::string_view trimmed_view(std::string_view text);

/// Owning copy of `trimmed_view(text)`, safe to keep after `text` is gone.
/// Example: `trimmed("\tmain\n")` -> `"main"`.
[[nodiscard]] std::string trimmed(std::string_view text);

/// Escape untrusted text for deterministic inclusion inside a double-quoted
/// diagnostic field. Printable bytes, including UTF-8, remain byte-exact;
/// backslash, quote, C0 controls and DEL use visible escapes so one hostile
/// identifier cannot forge extra log lines or terminal controls.
[[nodiscard]] std::string escaped_for_diagnostic(std::string_view text);

/// Number of leading space characters in `line`. Indentation-structured formats
/// (`Gemfile.lock`, `yarn.lock`, `pnpm-lock.yaml`) are written with literal
/// spaces, never tabs, so a tab counts as zero indentation and the caller sees
/// the line as unindented rather than silently mis-nested.
/// Example: `leading_space_count("    version: 1")` -> `4`;
/// `leading_space_count("\tversion: 1")` -> `0`.
[[nodiscard]] std::size_t leading_space_count(std::string_view line);

/// True when `text` is non-empty and every character is a hex digit
/// (`0-9 a-f A-F`). Validates untrusted hash values (e.g. a `URL_HASH`) before
/// they reach a purl qualifier or `Component::sha256`.
/// Example: `is_hex_digits("deadBEEF")` -> `true`; `is_hex_digits("")` -> `false`.
[[nodiscard]] bool is_hex_digits(std::string_view text);

/// True when `text` is exactly a 40-hex (SHA-1) or 64-hex (SHA-256) object id :
/// the two lengths git uses. Example: `is_hex_object_id(std::string(40, 'a'))`
/// -> `true`; `is_hex_object_id("v1.14.0")` -> `false`.
[[nodiscard]] bool is_hex_object_id(std::string_view text);

/// Lower-case `text` when it is a git object id, otherwise return it unchanged.
/// Object ids are canonically lower-case, so a manifest spelling one in capitals
/// must not fork the artifact into a second identity (rule 3). Anything that is
/// not an object id is operator text: a tag, a branch: and stays byte-exact.
/// Example: `normalized_object_id("ABC…")` (40 hex) -> `"abc…"`;
/// `normalized_object_id("v2.0-RC1")` -> `"v2.0-RC1"`.
[[nodiscard]] std::string normalized_object_id(std::string_view text);

}  // namespace bomwerk::core
